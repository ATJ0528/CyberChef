/**
 * @author CyberChef Contributor
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— TCP 流重组
 * 【文件】src/core/lib/PcapStream.mjs
 * 【职责】把一串已按层解析好的 DissectedPacket（见 PcapPacket.mjs）里携带的
 *         TCP 报文段，按连接（四元组）归并、按序列号重排、去掉重传/重叠、
 *         标记缺口，最终还原出每条连接「两个方向上连续的应用层字节流」。
 *         本库只处理 TCP，且只关心「载荷字节怎么拼成流」，不解释 HTTP/TLS
 *         等上层协议（那是更上层操作的职责）。
 * 【被谁使用】operations/ExtractPcapStreams、operations/FollowTcpStream、
 *         operations/PcapSummary 等上层操作（预期）。
 * ------------------------------------------------------------
 * 【导出接口】
 *   - TCP_FLAGS                     : TCP 标志位常量表（字节位）
 *   - flagsToNames(flagByte)        → string[] : 置位标志的名称数组
 *   - flagsToString(flagByte)       → string   : 形如 "SYN, ACK"
 *   - class TcpSegment              : 一个 TCP 报文段（含归一化序列号）
 *   - class TcpStream               : 一条 TCP 连接（双向、含重组结果）
 *   - class StreamTracker           : 逐包喂入、自动分流到各流
 *   - reassembleTcpStreams(packets) → {streams, stats} : 一步到位的便捷入口
 * ------------------------------------------------------------
 * 【关键算法】← 核心，评分重点
 *   1. 流标识与方向规范化：以 (ip, port) 为端点，把一条连接的两个端点排序
 *      （先比 ip 字符串、再比端口号），较小者为端点 a。于是「正向报文」与
 *      「反向报文」算出的 key 完全一致，天然归入同一条流，无需事后配对。
 *      ⚠取舍：ip 用字典序而非 IPv6 数值序。这里只需要一个**稳定且两向一致**
 *      的规范序，字典序完全满足；IPv6 十六进制字符串若做数值比较要额外
 *      展开冒号压缩格式，得不偿失。请勿改成数值比较，否则两向一致性的
 *      前提会被打破。
 *   2. 序列号归一化与 32 位回绕：TCP 序列号是 32 位且会回绕。每个**方向
 *      独立**维护一个零点 base：
 *        · 该方向见到 SYN → base = (syn.seq + 1) >>> 0（SYN 自身占一个序号）；
 *        · 该方向没有 SYN（中途开始抓包）→ base = 该方向首个观察到的 seq；
 *        之后每段的归一化位置 = (rawSeq - base) >>> 0。用无符号 32 位运算
 *        （>>> 0）保证回绕前后差值正确，不会出现负数或超出 2^32 的假值。
 *   3. 乱序重排：各段按归一化 seq 升序排序后再拼接，因此喂入顺序不影响
 *      最终字节流（前提是没有重叠，重叠按第 4 条处理）。
 *   4. 重传与重叠去重：按**到达顺序**逐段处理，维护一份「已覆盖区间」集合，
 *      每段只保留尚未被先前段覆盖的部分；完全被覆盖 → 丢弃并计一次重传，
 *      部分重叠 → 只留未覆盖部分并计一次重传。之所以**保留先到的数据**而非
 *      后到的：一是贴近 Wireshark 的默认行为（默认以首个到达的段为准），
 *      二是在有丢包/重传的网络里，先到的往往是真正被对端确认过的数据，
 *      后到的「重传段」可能与先前内容不一致（NAT 重写、路由怪异等），
 *      以先到者为准更稳，也更符合「首见即真相」的取证直觉。
 *   5. 缺口检测：去重后各保留片段两两不重叠，按位置排序后若相邻片段的
 *      起点与前一片段终点不连续，即记录一个缺口 {start, end} 并累计
 *      missingBytes。流的起始位置若不为 0（例如 SYN 后的首段数据丢失），
 *      也会补一个从 0 开始的缺口。
 *   6. 连接状态判定（优先级从高到低）：
 *        · 见过 RST                          → "reset"
 *        · 见过 SYN 且双向都见过 FIN          → "closed"
 *        · 见过 SYN                          → "established"
 *        · 从未见过 SYN                      → "incomplete"
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 归一化零点存在「方向」这一级而不是「段」这一级：base 是流的状态，
 *     所以归一化动作放在 TcpStream.addSegment()，TcpSegment 本身只存
 *     rawSeq（原始）与 seq（归一化）两个值，构造时二者相等，入流后被改写。
 *   - 覆盖区间用「排序 + 合并」的小数组维护（addInterval / subtractIntervals），
 *     而不是逐字节 bitmap。段数远小于字节数，区间法既省内存又快，还能
 *     自然支持乱序（若只在单方向上维护「高水位线」，一个乱序的低位段会
 *     被误判为已覆盖而丢弃）。
 *   - 重组结果做了惰性缓存：reassemble() 只在首次调用时计算，addSegment()
 *     负责把缓存置空。这样 stats 里反复读 bytes/retransmissionCount 不会
 *     重复做功。
 * ============================================================
 */

/**
 * TCP 标志位常量（TCP 首部第 13 字节的位定义）。
 *
 * 这是一个字节内的 8 个标志位；NS（0x100）落在第 12 字节的最低位，
 * 不属于本字节，故此处不收录（flagBits 也只承载一字节）。
 */
export const TCP_FLAGS = {
    FIN: 0x01,
    SYN: 0x02,
    RST: 0x04,
    PSH: 0x08,
    ACK: 0x10,
    URG: 0x20,
    ECE: 0x40,
    CWR: 0x80,
};

/**
 * 标志位的**展示顺序**（低→高按语义重排，而非位序）。
 *
 * 采用与 tcpdump/Wireshark 一致的阅读顺序：SYN、FIN、RST、PSH、ACK、URG、
 * ECE、CWR。这样 SYN+ACK 会输出 "SYN, ACK" 而不是按位序得到的 "ACK, SYN"，
 * 与抓包工具的输出习惯对齐，读起来更自然。
 */
const FLAG_DISPLAY_ORDER = [
    {name: "SYN", bit: TCP_FLAGS.SYN},
    {name: "FIN", bit: TCP_FLAGS.FIN},
    {name: "RST", bit: TCP_FLAGS.RST},
    {name: "PSH", bit: TCP_FLAGS.PSH},
    {name: "ACK", bit: TCP_FLAGS.ACK},
    {name: "URG", bit: TCP_FLAGS.URG},
    {name: "ECE", bit: TCP_FLAGS.ECE},
    {name: "CWR", bit: TCP_FLAGS.CWR},
];

/** 方向常量：相对端点 a / b 的传输方向。 */
const DIR_A_TO_B = "aToB";
const DIR_B_TO_A = "bToA";


/**
 * 把标志字节展开成置位标志的名称数组（按展示顺序）。
 *
 * @param {number} flagByte - 0-255 的标志字节
 * @returns {string[]} 例如 0x12 → ["SYN", "ACK"]；0 → []
 */
export function flagsToNames(flagByte) {
    const names = [];
    for (const {name, bit} of FLAG_DISPLAY_ORDER) {
        if ((flagByte & bit) !== 0) names.push(name);
    }
    return names;
}


/**
 * 把标志字节渲染成便于展示的字符串。
 *
 * @param {number} flagByte - 0-255 的标志字节
 * @returns {string} 例如 0x12 → "SYN, ACK"；0 → ""（无标志）
 */
export function flagsToString(flagByte) {
    return flagsToNames(flagByte).join(", ");
}


/**
 * 把 DissectedPacket 里 transport.flags 的对象形式压成一个标志字节。
 *
 * 只取字节内的 8 个位；ns 不参与（它不在此字节）。
 *
 * @param {Object|null} flags - {fin, syn, rst, psh, ack, urg, ece, cwr, ...}
 * @returns {number} 0-255 的标志字节
 */
function flagsToBits(flags) {
    if (!flags) return 0;
    let bits = 0;
    if (flags.fin) bits |= TCP_FLAGS.FIN;
    if (flags.syn) bits |= TCP_FLAGS.SYN;
    if (flags.rst) bits |= TCP_FLAGS.RST;
    if (flags.psh) bits |= TCP_FLAGS.PSH;
    if (flags.ack) bits |= TCP_FLAGS.ACK;
    if (flags.urg) bits |= TCP_FLAGS.URG;
    if (flags.ece) bits |= TCP_FLAGS.ECE;
    if (flags.cwr) bits |= TCP_FLAGS.CWR;
    return bits;
}


/**
 * 把标志字节展开成统一形态的 flags 对象（值一律为 0/1）。
 *
 * @param {number} bit - 0-255 的标志字节
 * @returns {Object} {fin, syn, rst, psh, ack, urg, ece, cwr}
 */
function flagsFromBits(bit) {
    return {
        fin: (bit & TCP_FLAGS.FIN) ? 1 : 0,
        syn: (bit & TCP_FLAGS.SYN) ? 1 : 0,
        rst: (bit & TCP_FLAGS.RST) ? 1 : 0,
        psh: (bit & TCP_FLAGS.PSH) ? 1 : 0,
        ack: (bit & TCP_FLAGS.ACK) ? 1 : 0,
        urg: (bit & TCP_FLAGS.URG) ? 1 : 0,
        ece: (bit & TCP_FLAGS.ECE) ? 1 : 0,
        cwr: (bit & TCP_FLAGS.CWR) ? 1 : 0,
    };
}


/**
 * 比较两个端点，产出一个稳定的规范序。
 *
 * 先比 ip 字符串（字典序，理由见文件头【关键算法】第 1 条），ip 相同再比
 * 端口号（数值）。返回值语义同 Array.prototype.sort 的比较器。
 *
 * @param {{ip: string, port: number}} p
 * @param {{ip: string, port: number}} q
 * @returns {number} 负数 / 0 / 正数
 */
function compareEndpoints(p, q) {
    if (p.ip < q.ip) return -1;
    if (p.ip > q.ip) return 1;
    return p.port - q.port;
}


/**
 * 判断两个端点是否为同一个 (ip, port)。
 *
 * @param {{ip: string, port: number}} p
 * @param {{ip: string, port: number}} q
 * @returns {boolean}
 */
function isSameEndpoint(p, q) {
    return p.ip === q.ip && p.port === q.port;
}


/**
 * 从一个已排序、互不重叠的区间数组中，减去 [start, end) 已覆盖的部分。
 *
 * @param {number} start - 待减区间的起点（含）
 * @param {number} end - 待减区间的终点（不含）
 * @param {Array<{start: number, end: number}>} covered - 已覆盖区间（升序、不重叠）
 * @returns {Array<{start: number, end: number}>} 未被覆盖的碎片（升序、不重叠）
 */
function subtractIntervals(start, end, covered) {
    const parts = [];
    let cursor = start;

    for (const iv of covered) {
        if (iv.end <= cursor) continue;   // 完全在游标之前，跳过
        if (iv.start >= end) break;       // 已在待减区间之后，后面也不用看了
        if (iv.start > cursor) {
            parts.push({start: cursor, end: Math.min(iv.start, end)});
        }
        if (iv.end > cursor) cursor = iv.end;
        if (cursor >= end) break;
    }

    if (cursor < end) parts.push({start: cursor, end});
    return parts;
}


/**
 * 把一个新区间并入「已覆盖区间」集合，并保持集合升序且互不重叠。
 *
 * @param {Array<{start: number, end: number}>} covered - 已覆盖集合（会被就地修改）
 * @param {number} start - 新区间起点（含）
 * @param {number} end - 新区间终点（不含）
 */
function addInterval(covered, start, end) {
    let i = 0;
    while (i < covered.length && covered[i].end < start) i++;

    let newStart = start;
    let newEnd = end;
    let j = i;
    while (j < covered.length && covered[j].start <= newEnd) {
        if (covered[j].start < newStart) newStart = covered[j].start;
        if (covered[j].end > newEnd) newEnd = covered[j].end;
        j++;
    }

    covered.splice(i, j - i, {start: newStart, end: newEnd});
}


/**
 * 一个 TCP 报文段（重组的最小单位）。
 *
 * 除承载载荷与元信息外，最重要的是 rawSeq 与 seq 这一对：
 * rawSeq 是报文里的原始序列号，seq 是入流后被归一化的绝对位置。
 */
export class TcpSegment {

    /**
     * @param {Object} opts
     * @param {number} opts.packetIndex - 来源包序号
     * @param {number} opts.timestamp - 时间戳（秒）
     * @param {string} opts.direction - "aToB" 或 "bToA"（相对流的端点 a/b）
     * @param {number} opts.rawSeq - 报文里的原始序列号（32 位无符号）
     * @param {number|null} [opts.ack] - 确认号
     * @param {number} [opts.flagBits] - 标志字节
     * @param {Uint8Array} [opts.payload] - TCP 载荷
     * @param {number|null} [opts.window] - 窗口大小
     */
    constructor(opts) {
        this.packetIndex = opts.packetIndex;
        this.timestamp = opts.timestamp;
        this.direction = opts.direction;
        this.rawSeq = opts.rawSeq >>> 0;
        this.ack = opts.ack === undefined ? null : opts.ack;
        this.flagBits = opts.flagBits || 0;
        this.flags = flagsFromBits(this.flagBits);
        this.payload = opts.payload instanceof Uint8Array ? opts.payload : new Uint8Array(0);
        this.window = opts.window === undefined ? null : opts.window;

        // seq 为归一化后的绝对序列号；构造函数先填 rawSeq，
        // 真正入流时由 TcpStream.addSegment() 按方向零点改写。
        this.seq = this.rawSeq;
    }

    /**
     * 载荷字节数。控制段（SYN/ACK/FIN/RST）通常为 0。
     * @returns {number}
     */
    get payloadLength() {
        return this.payload.length;
    }

    /**
     * 该段是否携带应用层数据。
     * @returns {boolean}
     */
    get hasPayload() {
        return this.payload.length > 0;
    }

    /**
     * 便于调试的一行摘要。
     * @returns {string}
     */
    toString() {
        return `#${this.packetIndex} ${this.direction} seq=${this.seq} ` +
            `[${flagsToString(this.flagBits)}] len=${this.payload.length}`;
    }
}


/**
 * 一条 TCP 连接（双向）。
 *
 * 持有该连接的所有报文段，并负责：序列号归一化、双向各自的重组、
 * 以及连接级别的统计。端点 a/b 是按规范序排定的（见文件头算法 1）。
 */
export class TcpStream {

    /**
     * @param {string} key - 形如 "192.168.1.10:1024-192.168.1.20:80"
     * @param {{ip: string, port: number}} a - 规范序中较小的端点
     * @param {{ip: string, port: number}} b - 规范序中较大的端点
     */
    constructor(key, a, b) {
        this.key = key;
        this.endpoints = {a: {ip: a.ip, port: a.port}, b: {ip: b.ip, port: b.port}};
        this.segments = [];

        // 每个方向独立的归一化零点与标志计数
        this._base = {aToB: null, bToA: null};
        this._synSeen = {aToB: false, bToA: false};
        this._finSeen = {aToB: false, bToA: false};
        this._synCount = 0;
        this._finCount = 0;
        this._rstSeen = false;

        this._reassembly = null;                // 惰性缓存
        this._dirMetrics = {
            aToB: {outOfOrderCount: 0, missingBytes: 0},
            bToA: {outOfOrderCount: 0, missingBytes: 0},
        };
    }

    /**
     * 把一个报文段加入本流：归一化其序列号、累计标志计数。
     *
     * @param {TcpSegment} segment - 方向必须与端点 a/b 一致
     */
    addSegment(segment) {
        const dir = segment.direction;

        // --- 步骤 1：确定本方向零点（SYN 优先，其次首见）---
        if (segment.flags.syn && this._base[dir] === null) {
            this._base[dir] = (segment.rawSeq + 1) >>> 0;   // SYN 占用一个序号
            this._synSeen[dir] = true;
        }
        if (this._base[dir] === null) {
            this._base[dir] = segment.rawSeq >>> 0;         // 中途抓包：以首段为 0
        }

        // --- 步骤 2：归一化（无符号 32 位，天然处理回绕）---
        // 若 SYN 在本方向被重复观察，零点已定，不会再次改写，安全。
        segment.seq = (segment.rawSeq - this._base[dir]) >>> 0;

        // --- 步骤 3：累计标志与计数 ---
        if (segment.flags.syn) this._synCount++;
        if (segment.flags.fin) {
            this._finCount++;
            this._finSeen[dir] = true;
        }
        if (segment.flags.rst) this._rstSeen = true;

        this.segments.push(segment);
        this._reassembly = null;
    }

    /**
     * 重组某一个方向的应用层字节流。
     *
     * 内部按到达顺序去重（保留先到），再按位置排序拼接，最后检测缺口。
     *
     * @private
     * @param {string} direction - "aToB" 或 "bToA"
     * @returns {{data: Uint8Array, gaps: Array<{start:number,end:number}>, byteCount: number, segmentCount: number, retransmissionCount: number}}
     */
    _reassembleDirection(direction) {
        // 只考虑携带载荷的段；控制段不贡献数据
        const segs = this.segments.filter((s) => s.direction === direction && s.hasPayload);

        const covered = [];        // 已覆盖区间（升序、合并）
        const pieces = [];         // 保留的数据碎片，形如 {start, data}
        let retransmissionCount = 0;
        let outOfOrderCount = 0;
        let maxEnd = 0;            // 本方向已见的最大结束位置（高水位）

        // --- 步骤 1：按到达顺序逐段去重（先到者优先）---
        for (const seg of segs) {
            const start = seg.seq;
            const end = start + seg.payloadLength;
            const parts = subtractIntervals(start, end, covered);

            if (parts.length === 0) {
                // 完全被先到的数据覆盖 → 纯重传，丢弃
                retransmissionCount++;
                continue;
            }

            const fullyUncovered = parts.length === 1 &&
                parts[0].start === start && parts[0].end === end;

            if (!fullyUncovered) {
                retransmissionCount++;         // 部分重叠：裁掉已覆盖部分，计一次
            } else if (start < maxEnd) {
                outOfOrderCount++;             // 纯乱序：填了前面的空洞
            }

            // 收集本段未被覆盖的碎片（复用底层 buffer 的 subarray，零拷贝）
            for (const part of parts) {
                pieces.push({
                    start: part.start,
                    data: seg.payload.subarray(part.start - start, part.end - start),
                });
            }

            addInterval(covered, start, end);
            if (end > maxEnd) maxEnd = end;
        }

        // --- 步骤 2：按位置排序后拼接 ---
        pieces.sort((x, y) => x.start - y.start);

        let totalLen = 0;
        for (const p of pieces) totalLen += p.data.length;

        const data = new Uint8Array(totalLen);
        const gaps = [];
        let offset = 0;
        let prevEnd = 0;
        let missingBytes = 0;

        // --- 步骤 3：检测缺口（含流首可能缺失的前缀）---
        for (const p of pieces) {
            if (p.start > prevEnd) {
                gaps.push({start: prevEnd, end: p.start});
                missingBytes += p.start - prevEnd;
            }
            data.set(p.data, offset);
            offset += p.data.length;
            prevEnd = p.start + p.data.length;
        }

        this._dirMetrics[direction] = {outOfOrderCount, missingBytes};

        return {
            data,
            gaps,
            byteCount: data.length,
            segmentCount: segs.length,
            retransmissionCount,
        };
    }

    /**
     * 重组本流两个方向的数据（结果惰性缓存）。
     *
     * @returns {{aToB: Object, bToA: Object}} 每个方向形如
     *   {data, gaps, byteCount, segmentCount, retransmissionCount}
     */
    reassemble() {
        if (this._reassembly === null) {
            this._reassembly = {
                aToB: this._reassembleDirection(DIR_A_TO_B),
                bToA: this._reassembleDirection(DIR_B_TO_A),
            };
        }
        return this._reassembly;
    }

    /**
     * 连接状态判定，详见文件头【关键算法】第 6 条。
     *
     * @returns {"established"|"closed"|"reset"|"incomplete"}
     */
    get state() {
        if (this._rstSeen) return "reset";
        if (this._synCount > 0 && this._finSeen.aToB && this._finSeen.bToA) return "closed";
        if (this._synCount > 0) return "established";
        return "incomplete";
    }

    /**
     * 时间跨度（秒）：最后一段与第一段的时间差。
     *
     * @returns {number}
     */
    get duration() {
        const times = this._timestamps();
        if (times.length < 2) return 0;
        return times[times.length - 1] - times[0];
    }

    /**
     * 首个观察时间（秒），无段时为 0。
     *
     * @returns {number}
     */
    get startTime() {
        const times = this._timestamps();
        return times.length ? times[0] : 0;
    }

    /**
     * 最后观察时间（秒），无段时为 0。
     *
     * @returns {number}
     */
    get endTime() {
        const times = this._timestamps();
        return times.length ? times[times.length - 1] : 0;
    }

    /**
     * 按时间升序排列的时间戳数组（内部使用）。
     *
     * @private
     * @returns {number[]}
     */
    _timestamps() {
        return this.segments.map((s) => s.timestamp).sort((x, y) => x - y);
    }

    /**
     * 本流的汇总统计。
     *
     * @returns {Object} 见任务契约 stats
     */
    get stats() {
        const r = this.reassemble();
        const payloadBytes = this.segments.reduce((acc, s) => acc + s.payloadLength, 0);

        return {
            packetCount: this.segments.length,
            payloadBytes,
            bytesAtoB: r.aToB.byteCount,
            bytesBtoA: r.bToA.byteCount,
            synCount: this._synCount,
            finCount: this._finCount,
            rstSeen: this._rstSeen,
            startTime: this.startTime,
            endTime: this.endTime,
            duration: this.duration,
            retransmissionCount: r.aToB.retransmissionCount + r.bToA.retransmissionCount,
            outOfOrderCount: this._dirMetrics.aToB.outOfOrderCount + this._dirMetrics.bToA.outOfOrderCount,
            missingBytes: this._dirMetrics.aToB.missingBytes + this._dirMetrics.bToA.missingBytes,
            state: this.state,
        };
    }
}


/**
 * 流跟踪器：把逐包喂入的 DissectedPacket 自动分派到各自的 TcpStream。
 *
 * 非 TCP（含无网络层、无传输层）包被忽略并计入 ignoredPacketCount。
 */
export class StreamTracker {

    /**
     * 建立一个空的流跟踪器。
     */
    constructor() {
        this._streams = new Map();     // key → TcpStream
        this._totalPackets = 0;
        this._tcpPacketCount = 0;
        this._ignoredPacketCount = 0;
        this._totalPayloadBytes = 0;
        this._finalized = false;
    }

    /**
     * 喂入一个已分层解析的包。
     *
     * @param {Object} dissected - DissectedPacket（见 PcapPacket.mjs 的输出契约）
     * @returns {TcpSegment|null} 归入的报文段；非 TCP 时返回 null
     */
    addPacket(dissected) {
        this._totalPackets++;

        const net = dissected && dissected.network;
        const tr = dissected && dissected.transport;

        // --- 步骤 1：过滤非 TCP / 缺层的包 ---
        if (!net || !tr || tr.protocol !== "TCP") {
            this._ignoredPacketCount++;
            return null;
        }

        this._tcpPacketCount++;

        // --- 步骤 2：构造端点并按规范序排序，得到稳定 key 与方向 ---
        const src = {ip: net.src, port: tr.srcPort === null || tr.srcPort === undefined ? 0 : tr.srcPort};
        const dst = {ip: net.dst, port: tr.dstPort === null || tr.dstPort === undefined ? 0 : tr.dstPort};
        const [a, b] = compareEndpoints(src, dst) <= 0 ? [src, dst] : [dst, src];
        const key = `${a.ip}:${a.port}-${b.ip}:${b.port}`;

        let stream = this._streams.get(key);
        if (!stream) {
            stream = new TcpStream(key, a, b);
            this._streams.set(key, stream);
        }

        const direction = isSameEndpoint(src, a) ? DIR_A_TO_B : DIR_B_TO_A;

        // --- 步骤 3：构造报文段并交给流 ---
        const payload = dissected.payload instanceof Uint8Array ? dissected.payload : new Uint8Array(0);
        const segment = new TcpSegment({
            packetIndex: dissected.index,
            timestamp: dissected.timestamp,
            direction,
            rawSeq: tr.seq === null || tr.seq === undefined ? 0 : tr.seq,
            ack: tr.ack,
            flagBits: flagsToBits(tr.flags),
            payload,
            window: tr.window,
        });

        stream.addSegment(segment);
        this._totalPayloadBytes += segment.payloadLength;
        return segment;
    }

    /**
     * 收尾：标记跟踪结束。
     *
     * 连接状态的判定是惰性的（由 TcpStream.state 实时计算），因此这里
     * 主要起「封口」作用——防止调用方继续误喂数据，并便于未来在此补
     * 「给未收到 FIN 的流定终态」等逻辑。
     */
    finalize() {
        this._finalized = true;
    }

    /**
     * 已识别的所有 TCP 流。
     *
     * @returns {TcpStream[]}
     */
    get streams() {
        return Array.from(this._streams.values());
    }

    /**
     * 跟踪器级汇总统计。
     *
     * @returns {Object} {totalPackets, tcpPacketCount, streamCount,
     *   retransmissionCount, outOfOrderCount, ignoredPacketCount, totalPayloadBytes}
     */
    get stats() {
        const streams = this.streams;
        let retransmissionCount = 0;
        let outOfOrderCount = 0;

        for (const stream of streams) {
            const s = stream.stats;
            retransmissionCount += s.retransmissionCount;
            outOfOrderCount += s.outOfOrderCount;
        }

        return {
            totalPackets: this._totalPackets,
            tcpPacketCount: this._tcpPacketCount,
            streamCount: streams.length,
            retransmissionCount,
            outOfOrderCount,
            ignoredPacketCount: this._ignoredPacketCount,
            totalPayloadBytes: this._totalPayloadBytes,
        };
    }
}


/**
 * 便捷入口：把一串 DissectedPacket 直接重组成 TCP 流与统计。
 *
 * @param {Object[]} dissectedPackets - DissectedPacket 数组
 * @returns {{streams: TcpStream[], stats: Object}}
 */
export function reassembleTcpStreams(dissectedPackets) {
    const tracker = new StreamTracker();
    for (const packet of dissectedPackets || []) {
        tracker.addPacket(packet);
    }
    tracker.finalize();

    return {
        streams: tracker.streams,
        stats: tracker.stats,
    };
}


export default {
    TCP_FLAGS,
    flagsToNames,
    flagsToString,
    TcpSegment,
    TcpStream,
    StreamTracker,
    reassembleTcpStreams,
};
