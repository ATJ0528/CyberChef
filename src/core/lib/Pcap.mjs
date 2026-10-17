/**
 * @author CyberChef Contributor
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

import OperationError from "../errors/OperationError.mjs";

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 抓包文件容器格式解析
 * 【文件】src/core/lib/Pcap.mjs
 * 【职责】把 .pcap 与 .pcapng 两种抓包文件容器格式解成统一的内存模型
 *         （PcapCapture / PcapPacket），供上层做协议解析、流重组与会话统计。
 *         本库只负责"容器"——即把字节流切成一段段带时间戳的原始帧数据，
 *         不解释以太网/IP/TCP 等协议内容（那是 PcapPacket.mjs 的职责）。
 * 【被谁使用】operations/ParsePcap、operations/PcapSummary、
 *         operations/ExtractPcapStreams、operations/FilterPcap
 * ------------------------------------------------------------
 * 【导出接口】
 *   - LINKTYPE           : 链路层类型编号常量表（Ethernet / RAW / Linux SLL …）
 *   - LINKTYPE_NAMES     : 编号 → 可读名称
 *   - class PcapCapture  : 整个抓包文件的模型（含接口表与包列表）
 *   - class PcapPacket   : 单个抓包记录（时间戳 + 原始帧字节 + 链路类型）
 *   - class PcapInterface: pcapng 中的接口描述块（IDB）
 *   - parsePcap(bytes)   → PcapCapture : 自动识别格式并解析
 *   - isPcap(bytes)      → boolean     : 快速嗅探是否为抓包文件
 *   - getLinkTypeName(n) → string
 * ------------------------------------------------------------
 * 【关键算法】
 *   1. 格式与端序的自动识别，靠**魔数**完成，且魔数本身要分两步判：
 *        - pcap  文件头前 4 字节是 0xa1b2c3d4。若按大端读得该值，则文件为
 *          大端序；若按大端读出 0xd4c3b2a1，说明真实字节序相反。再配合
 *          0xa1b23c4d / 0x4d3cb2a1 这一对，可同时判出**时间戳精度**
 *          （微秒 or 纳秒）。这是抓包格式的经典"用魔数反推端序"手法。
 *        - pcapng 文件头是 4 字节的 0x0a0d0d0a"块类型"，但它**不含端序
 *          信息**；真正的端序标志在第一个块（SHB）体的头 4 字节
 *          Byte-Order Magic = 0x1a2b3c4d 上。所以 pcapng 必须先读块类型、
 *          再进块体读 BOM，才能确定后续所有整数的端序。
 *   2. pcapng 的块结构是"三明治"式：块类型(4) + 块总长(4) + 块体 + 块总长(4)。
 *      首尾两次块总长是冗余校验，解析时应比对二者是否一致以判定块是否损坏。
 *      块总长**含**填充字节，即所有块都按 4 字节对齐补齐。
 *   3. pcapng 的时间戳是"接口分辨率下的 tick 计数"，用 High/Low 两个 32 位
 *      拼成 64 位整数（tsHigh << 32 | tsLow）。因超过 JS 安全整数 2^53，
 *      这里用 BigInt 承载。真正换算成秒还需要接口的 if_tsresol 选项：
 *      选项字节最高位为 1 时分辨率为 2^k，为 0 时是 10^k（k 为低 7 位）。
 *   4. 选项（Options）是统一的 TLV 结构：code(2) + length(2) + value(变长，4 字节对齐)，
 *      以 code=0（opt_endofopt）表示选项区结束。抽成一个函数可同时服务
 *      SHB / IDB / EPB 三处的选项解析，避免三份重复代码。
 *   5. 大文件保护：解析时用可配置的包数上限截断，避免把几百 MB 的抓包
 *      一次性展开成对象数组而耗尽内存。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 所有整数读取统一走 DataView + 一个布尔 isLittleEndian 变量，而不是
 *     手动拼接字节。虽然比手写位移略慢，但端序切换只需改一个变量，
 *     代码里不会出现"某处漏了反转"这类经典 bug。
 *   - 遇到不认识的块类型不是报错而是**跳过**（记录到 warnings），
 *     这让解析器能兼容未来新增的 pcapng 块类型，也容忍作者自定义块。
 *   - 截断/损坏的文件不抛异常，而是返回已成功解析的部分并记录警告——
 *     抓包文件被中断写入是常态，能读出多少算多少比直接失败有用得多。
 * ============================================================
 */

/**
 * 链路层类型编号。
 *
 * 这些值来自 tcpdump/libpcap 的 LINKTYPE_* 定义，写在抓包文件的
 * 全局头（pcap）或接口描述块（pcapng）里，决定"原始帧字节从哪一层开始"。
 * 解析时必须先看这个字段，否则会把 IP 头当成以太网头解析出错。
 */
export const LINKTYPE = {
    NULL: 0,            // BSD loopback：4 字节地址族 + IP 报文
    ETHERNET: 1,        // 标准以太网帧
    AX25: 3,
    IEEE802_5: 6,       // 令牌环
    PPP: 9,             // 点对点协议
    FDDI: 10,
    RAW: 101,           // 裸 IP 报文（无链路层头）
    LOOP: 108,          // OpenBSD loopback
    LINUX_SLL: 113,     // Linux "cooked" 捕获（任何设备，带 16 字节伪首部）
    IEEE802_11: 105,    // 802.11 无线
    LINUX_SLL2: 276,    // Linux cooked v2
    IPV4: 228,          // 裸 IPv4
    IPV6: 229,          // 裸 IPv6
};

/**
 * 链路层类型编号 → 可读名称。
 * 用于统计输出与界面展示；未收录的编号在 getLinkTypeName() 中回退为
 * "Unknown (N)" 而不是报错。
 */
export const LINKTYPE_NAMES = {
    0: "BSD Loopback",
    1: "Ethernet",
    3: "AX.25",
    6: "IEEE 802.5 Token Ring",
    9: "PPP",
    10: "FDDI",
    101: "Raw IP",
    105: "IEEE 802.11 Wireless",
    108: "OpenBSD Loopback",
    113: "Linux SLL (Cooked)",
    228: "Raw IPv4",
    229: "Raw IPv6",
    276: "Linux SLL2 (Cooked v2)",
};

/**
 * pcap 文件魔数（按不同端序与时间戳精度分成四种组合）。
 * 判定方式见文件头【关键算法】第 1 条。
 */
const PCAP_MAGIC = {
    MICROSECOND: 0xa1b2c3d4,   // 微秒精度
    NANOSECOND: 0xa1b23c4d,    // 纳秒精度（pcap-ns，tcpdump 2.x 扩展）
};

/**
 * pcapng 用到的块类型编号。
 * 只实现真正影响"取出包数据"的几种；其余块类型统一跳过并记入 warnings。
 */
const PCAPNG_BLOCK = {
    SECTION_HEADER: 0x0a0d0d0a,       // SHB：节头块，开启一个新 section
    INTERFACE_DESCRIPTION: 0x00000001, // IDB：接口描述块，定义一个抓包接口
    PACKET: 0x00000002,                // PB：古老的分组块，已被 EPB 取代
    SIMPLE_PACKET: 0x00000003,         // SPB：简单分组块，无时间戳
    NAME_RESOLUTION: 0x00000004,       // NRB：名字解析块，提供绝对时间基准
    INTERFACE_STATISTICS: 0x00000005,  // ISB：接口统计块
    ENHANCED_PACKET: 0x00000006,       // EPB：增强分组块，现代标准
    DECRYPTION_SECRETS: 0x0000000a,    // DSB：解密密钥块
    CUSTOM: 0x00000BAD,                // 可复制自定义块
    CUSTOM_NO_COPY: 0x40000BAD,        // 不可复制自定义块
};

/** pcapng 块体开头的字节序魔数，用于确定该 section 的端序 */
const PCAPNG_BYTE_ORDER_MAGIC = 0x1a2b3c4d;

/** pcap 全局头的固定长度（字节） */
const PCAP_GLOBAL_HEADER_LEN = 24;
/** pcap 每个包记录头的固定长度（字节） */
const PCAP_PACKET_HEADER_LEN = 16;
/** pcapng 块的固定开销：块类型(4) + 块总长(4) + 块总长副本(4) */
const PCAPNG_BLOCK_FIXED_OVERHEAD = 12;

/** 默认解析包数上限，防止超大抓包文件拖垮浏览器 */
export const DEFAULT_MAX_PACKETS = 100000;


/**
 * 返回链路层类型编号对应的可读名称。
 *
 * @param {number} linkType - LINKTYPE 中的编号
 * @returns {string} 可读名称，未收录时形如 "Unknown (999)"
 */
export function getLinkTypeName(linkType) {
    return LINKTYPE_NAMES[linkType] || `Unknown (${linkType})`;
}


/**
 * pcapng 接口描述块（Interface Description Block）的内存模型。
 *
 * 一个 pcapng 文件可以有多个接口（多网卡同时抓包），每个包都要靠
 * interfaceId 回指到这里，才能知道它的链路层类型和时间戳分辨率。
 */
export class PcapInterface {

    /**
     * @param {number} id - 接口在所属 section 内的序号（EPB 的 Interface ID 字段）
     */
    constructor(id) {
        this.id = id;
        this.linkType = LINKTYPE.ETHERNET;   // 默认值，IDB 未指定时按以太网处理
        this.linkTypeName = getLinkTypeName(this.linkType);
        this.snaplen = 0;                     // 抓包时截断长度，0 表示不限
        this.name = null;                     // if_name 选项
        this.description = null;              // if_description 选项
        this.os = null;                       // if_os 选项
        this.filter = null;                   // if_filter 选项（抓包过滤器表达式）
        this.tsResolution = 1000000;          // 每秒钟的 tick 数，默认 10^6（微秒）
        this.tsResolutionBase = 10;           // 分辨率的基数：10 或 2
        this.tsResolutionExponent = 6;        // 分辨率的指数
    }

    /**
     * 按 if_tsresol 选项设置时间戳分辨率。
     *
     * 选项的 1 字节值语义：最高位为 1 时表示以 2 为底，为 0 时以 10 为底；
     * 低 7 位是幂次。于是 0x06 → 10^6（微秒），0x89 → 2^9 = 512 tick/秒。
     *
     * @param {number} value - if_tsresol 选项的字节值（0-255）
     */
    setTimestampResolution(value) {
        const basePowerOfTwo = (value & 0x80) !== 0;
        const exponent = value & 0x7f;

        this.tsResolutionBase = basePowerOfTwo ? 2 : 10;
        this.tsResolutionExponent = exponent;
        this.tsResolution = Math.pow(this.tsResolutionBase, exponent);
    }

    /**
     * 把一个 tick 计数换算成秒。
     *
     * @param {number|bigint} ticks - 接口分辨率下的 tick 计数
     * @returns {number} 秒（浮点）
     */
    ticksToSeconds(ticks) {
        return Number(ticks) / this.tsResolution;
    }
}


/**
 * 单个抓包记录。
 *
 * 记录的是"原始帧字节 + 元信息"，不对内容做任何解释。
 * 字段布局对 pcap 与 pcapng 统一，目的是让上层不必关心来源格式。
 */
export class PcapPacket {

    /**
     * @param {number} index - 包在文件中的序号，从 0 开始
     */
    constructor(index) {
        this.index = index;
        this.tsSec = 0;           // 整数秒部分
        this.tsFrac = 0;          // 小数部分（单位为该文件/接口的 tick）
        this.timestamp = 0;       // 换算后的秒（浮点），便于排序与计算时延
        this.inclLen = 0;         // 实际捕获到的字节数（可能因 snaplen 被截断）
        this.origLen = 0;         // 报文在链路上的原始长度
        this.linkType = LINKTYPE.ETHERNET;
        this.linkTypeName = getLinkTypeName(this.linkType);
        this.interfaceId = 0;     // pcapng 中该包来自哪个接口
        this.data = new Uint8Array(0);  // 原始帧字节
        this.comment = null;      // pcapng 的 opt_comment 选项
        this.truncated = false;   // inclLen < origLen，说明被 snaplen 截断
    }

    /**
     * 时间戳的毫秒表示，便于与 JS 的 Date 互操作。
     *
     * @returns {number}
     */
    get timestampMillis() {
        return this.timestamp * 1000;
    }

    /**
     * 时间戳的 ISO 8601 字符串（UTC）。
     *
     * @returns {string}
     */
    get timestampISO() {
        return new Date(this.timestampMillis).toISOString();
    }

    /**
     * 该包是否携带载荷（用于统计与过滤）。
     *
     * @returns {boolean}
     */
    get hasData() {
        return this.data.length > 0;
    }
}


/**
 * 一个完整抓包文件的内存模型。
 *
 * 这是 Pcap.mjs 对外的主出口：上层拿到 PcapCapture 后，
 * 既可以遍历 packets 做逐包解析，也可以读 interfaces 了解抓包环境。
 */
export class PcapCapture {

    /**
     * 建立一个空的抓包模型。
     *
     * 所有字段都有确定的初值（而不是留 undefined），这样即便解析在
     * 中途失败，调用方读到的也是"空抓包"而非一片 undefined。
     */
    constructor() {
        this.format = null;        // "pcap" 或 "pcapng"
        this.byteOrder = "le";     // "le" 或 "be"
        this.nanosecond = false;   // 全局时间戳精度是否为纳秒（仅 pcap 有意义）
        this.version = null;       // 文件格式版本，形如 "2.4"
        this.linkType = null;      // 全局链路类型（pcap 才有；pcapng 看接口）
        this.snaplen = null;       // 全局截断长度（仅 pcap）
        this.interfaces = [];      // PcapInterface[]（pcapng 会填，pcap 合成一个）
        this.packets = [];         // PcapPacket[]
        this.warnings = [];        // 解析过程中遇到的可容忍问题
        this.truncatedAt = null;   // 若因包数上限提前停止，记录停止位置
        this.source = null;        // 来源描述（文件名等），由调用方填充
    }

    /**
     * 包总数。
     * @returns {number}
     */
    get packetCount() {
        return this.packets.length;
    }

    /**
     * 所有包的原始字节总量。
     * @returns {number}
     */
    get totalBytes() {
        return this.packets.reduce((acc, p) => acc + p.inclLen, 0);
    }

    /**
     * 抓包的时间跨度（秒），不足两个包时返回 0。
     * @returns {number}
     */
    get duration() {
        if (this.packets.length < 2) return 0;
        return this.packets[this.packets.length - 1].timestamp - this.packets[0].timestamp;
    }

    /**
     * 首个包的时间戳（秒），无包时返回 0。
     * @returns {number}
     */
    get startTime() {
        return this.packets.length ? this.packets[0].timestamp : 0;
    }

    /**
     * 汇总信息，供界面头部与报告使用。
     *
     * @returns {Object}
     */
    get summary() {
        return {
            format: this.format,
            byteOrder: this.byteOrder,
            version: this.version,
            nanosecond: this.nanosecond,
            interfaceCount: this.interfaces.length,
            packetCount: this.packetCount,
            totalBytes: this.totalBytes,
            durationSeconds: this.duration,
            startTime: this.startTime,
            startTimeISO: this.packets.length ? this.packets[0].timestampISO : null,
            truncatedAt: this.truncatedAt,
            warningCount: this.warnings.length,
        };
    }

    /**
     * 记录一条可容忍的解析警告。
     *
     * @param {string} message
     */
    addWarning(message) {
        // 同类警告去重，避免损坏文件刷出上万条相同信息
        if (!this.warnings.includes(message)) {
            this.warnings.push(message);
        }
    }
}


/**
 * 快速嗅探一段字节是否像抓包文件。
 *
 * 只读前 4 字节判断魔数，不解析内容，适合在真正解析前做格式预检。
 *
 * @param {Uint8Array} bytes
 * @returns {boolean}
 */
export function isPcap(bytes) {
    if (!bytes || bytes.length < 4) return false;

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const magic = dv.getUint32(0, false);

    return magic === PCAP_MAGIC.MICROSECOND ||
        magic === PCAP_MAGIC.NANOSECOND ||
        magic === 0xd4c3b2a1 ||
        magic === 0x4d3cb2a1 ||
        magic === PCAPNG_BLOCK.SECTION_HEADER;
}


/**
 * 解析一个抓包文件，自动识别 pcap 与 pcapng 两种格式。
 *
 * 这是本库的主入口。
 *
 * @param {Uint8Array} bytes - 整个文件的字节
 * @param {Object} [options={}]
 * @param {number} [options.maxPackets=DEFAULT_MAX_PACKETS] - 最多解析多少个包
 * @returns {PcapCapture}
 * @throws {OperationError} 输入过短、魔数不识别、或文件头声明值与实际长度矛盾时
 */
export function parsePcap(bytes, options = {}) {
    const maxPackets = options.maxPackets || DEFAULT_MAX_PACKETS;

    if (!bytes || bytes.length === 0) {
        throw new OperationError("No data was provided to parse as a capture file.");
    }
    if (bytes.length < 4) {
        throw new OperationError(`Capture file is too short to contain a valid header (${bytes.length} bytes).`);
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const magic = dv.getUint32(0, false);

    // --- 步骤 1：按魔数分派到具体格式解析器 ---
    if (magic === PCAP_MAGIC.MICROSECOND || magic === PCAP_MAGIC.NANOSECOND ||
        magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) {
        return parseClassicPcap(bytes, dv, maxPackets);
    }

    if (magic === PCAPNG_BLOCK.SECTION_HEADER) {
        return parsePcapng(bytes, dv, maxPackets);
    }

    // 调用方会统一补上 "Not a valid capture file: " 前缀，这里只说清具体原因，
    // 避免最终提示出现两句同义话。
    throw new OperationError(
        `Expected a pcap or pcapng magic number, ` +
        `got 0x${magic.toString(16).padStart(8, "0")}.`
    );
}


/**
 * 解析经典 pcap 格式（tcpdump/libpcap 的原始格式）。
 *
 * 布局：
 *   全局头 24 字节 → (包记录头 16 字节 + 帧数据)*
 *
 * @private
 * @param {Uint8Array} bytes
 * @param {DataView} dv
 * @param {number} maxPackets
 * @returns {PcapCapture}
 */
function parseClassicPcap(bytes, dv, maxPackets) {
    const capture = new PcapCapture();
    capture.format = "pcap";

    // --- 步骤 1：由魔数反推端序与时间戳精度 ---
    // 按大端读出 0xa1b2c3d4 说明文件确实是大端；读出 0xd4c3b2a1 说明
    // 真实字节序与读取顺序相反，即小端。纳秒精度同理。
    const rawMagic = dv.getUint32(0, false);
    let littleEndian;

    if (rawMagic === PCAP_MAGIC.MICROSECOND || rawMagic === PCAP_MAGIC.NANOSECOND) {
        littleEndian = false;
        capture.byteOrder = "be";
        capture.nanosecond = rawMagic === PCAP_MAGIC.NANOSECOND;
    } else {
        // 0xd4c3b2a1 / 0x4d3cb2a1：真实端序为小端
        littleEndian = true;
        capture.byteOrder = "le";
        capture.nanosecond = rawMagic === 0x4d3cb2a1;
    }

    if (bytes.length < PCAP_GLOBAL_HEADER_LEN) {
        throw new OperationError(
            `Capture file is too short for a pcap global header ` +
            `(expected ${PCAP_GLOBAL_HEADER_LEN} bytes, got ${bytes.length}).`
        );
    }

    // --- 步骤 2：解析全局头 ---
    const major = dv.getUint16(4, littleEndian);
    const minor = dv.getUint16(6, littleEndian);
    capture.version = `${major}.${minor}`;
    capture.snaplen = dv.getUint32(16, littleEndian);
    capture.linkType = dv.getUint32(20, littleEndian);

    if (major !== 2) {
        capture.addWarning(`Unexpected pcap major version ${major} (expected 2). Parsing anyway.`);
    }

    // pcap 没有接口概念，合成一个虚拟接口，好让上层代码对两种格式一视同仁
    const iface = new PcapInterface(0);
    iface.linkType = capture.linkType;
    iface.linkTypeName = getLinkTypeName(iface.linkType);
    iface.snaplen = capture.snaplen;
    iface.tsResolution = capture.nanosecond ? 1000000000 : 1000000;
    iface.tsResolutionBase = 10;
    iface.tsResolutionExponent = capture.nanosecond ? 9 : 6;
    capture.interfaces.push(iface);

    // --- 步骤 3：迭代读取包记录 ---
    let offset = PCAP_GLOBAL_HEADER_LEN;
    let index = 0;

    while (offset + PCAP_PACKET_HEADER_LEN <= bytes.length) {
        if (index >= maxPackets) {
            capture.truncatedAt = index;
            capture.addWarning(`Stopped after ${maxPackets} packets (maxPackets limit).`);
            break;
        }

        const tsSec = dv.getUint32(offset, littleEndian);
        const tsFrac = dv.getUint32(offset + 4, littleEndian);
        const inclLen = dv.getUint32(offset + 8, littleEndian);
        const origLen = dv.getUint32(offset + 12, littleEndian);
        offset += PCAP_PACKET_HEADER_LEN;

        // 声明的长度超过剩余字节，说明文件被截断——取剩余部分并告警
        let available = inclLen;
        if (offset + inclLen > bytes.length) {
            available = Math.max(0, bytes.length - offset);
            capture.addWarning(
                `Packet ${index} declares ${inclLen} bytes but only ${available} remain; ` +
                `file appears to be truncated.`
            );
        }

        const packet = new PcapPacket(index);
        packet.tsSec = tsSec;
        packet.tsFrac = tsFrac;
        packet.timestamp = tsSec + tsFrac / iface.tsResolution;
        packet.inclLen = available;
        packet.origLen = origLen;
        packet.linkType = capture.linkType;
        packet.linkTypeName = getLinkTypeName(capture.linkType);
        packet.interfaceId = 0;
        packet.data = bytes.slice(offset, offset + available);
        packet.truncated = inclLen < origLen;

        capture.packets.push(packet);
        offset += available;
        index++;

        if (available < inclLen) break;   // 已经读到文件末尾，无需继续
    }

    if (index === 0) {
        capture.addWarning("The capture file contains no packet records.");
    }

    return capture;
}


/**
 * 解析 pcapng 格式（PCAP Next Generation，Wireshark 默认格式）。
 *
 * 布局是一串自描述的"块"，每个块自带类型与长度：
 *   块类型(4) + 块总长(4) + 块体(可变) + 块总长(4)
 * 所有块按 4 字节对齐。
 *
 * 与 pcap 最大的不同：端序与链路类型都不在文件头里，而是分别在
 * 首块的 Byte-Order Magic 与各接口描述块（IDB）里。
 *
 * @private
 * @param {Uint8Array} bytes
 * @param {DataView} dv
 * @param {number} maxPackets
 * @returns {PcapCapture}
 */
function parsePcapng(bytes, dv, maxPackets) {
    const capture = new PcapCapture();
    capture.format = "pcapng";

    let offset = 0;
    let index = 0;
    let sectionIndex = -1;
    let littleEndian = null;
    let interfaces = [];          // 当前 section 的接口表
    let idbCountInSection = 0;    // IDB 在 section 内从 0 重新编号
    /* 当前 section 内的包计数（仅用于诊断，无外部可见影响）*/

    while (offset + PCAPNG_BLOCK_FIXED_OVERHEAD <= bytes.length) {
        // --- 步骤 1：先按大端嗅探块类型，只为识别节头块 ---
        // 这里可以放心固定用大端读，因为 SHB 的类型码 0x0a0d0d0a 逐字节反转后
        // 仍是它自己（回文）——这正是该魔数被设计成这样的原因，
        // 使得"在未知端序时能否认出节头块"这个问题不复存在。
        const peekedType = dv.getUint32(offset, false);

        // --- 首块（SHB）必须先确定端序，否则后面所有整数都读不对 ---
        if (peekedType === PCAPNG_BLOCK.SECTION_HEADER) {
            if (offset + 12 > bytes.length) break;

            // 试读 BOM 判定端序：0x1a2b3c4d 按大端读出即为大端
            const bomBE = dv.getUint32(offset + 8, false);
            if (bomBE === PCAPNG_BYTE_ORDER_MAGIC) {
                littleEndian = false;
            } else if (dv.getUint32(offset + 8, true) === PCAPNG_BYTE_ORDER_MAGIC) {
                littleEndian = true;
            } else {
                capture.addWarning(`Section header at offset ${offset} has an invalid byte-order magic; stopping.`);
                break;
            }

            const blockLen = dv.getUint32(offset + 4, littleEndian);
            if (blockLen < 28 || offset + blockLen > bytes.length) {
                capture.addWarning(`Section header at offset ${offset} declares an invalid length (${blockLen}); stopping.`);
                break;
            }

            sectionIndex++;
            idbCountInSection = 0;

            interfaces = [];

            // SHB 体：BOM(4) + 主版本(2) + 次版本(2) + 节长度(8) + 选项
            const major = dv.getUint16(offset + 12, littleEndian);
            const minor = dv.getUint16(offset + 14, littleEndian);
            if (capture.version === null) {
                capture.version = `${major}.${minor}`;
                capture.byteOrder = littleEndian ? "le" : "be";
            } else if (capture.byteOrder !== (littleEndian ? "le" : "be")) {
                capture.addWarning(
                    `Section ${sectionIndex} uses a different byte order than the first section; ` +
                    `packets are still parsed but absolute times may not be comparable.`
                );
            }

            // 节长度：-1（全 1）表示未知，仅用于说明，不影响解析
            const sectionLen = dv.getBigInt64(offset + 16, littleEndian);
            if (sectionLen !== BigInt(-1) && Number(sectionLen) !== bytes.length) {
                capture.addWarning(`Section ${sectionIndex} declares a length of ${sectionLen} bytes.`);
            }

            offset += blockLen;
            continue;
        }

        // 还没见过 SHB 就遇到其他块，说明文件没有节头，无法确定端序
        if (littleEndian === null) {
            capture.addWarning(`Capture file does not start with a section header block; cannot determine byte order.`);
            break;
        }

        // --- 步骤 2：端序已知，按真实端序重读块类型 ---
        // 不能复用上面的 peekedType：除 SHB 外，其余块类型都不是回文，
        // 端序读错会得到完全不同的数值（例如 IDB 的 0x00000001 会被读成 0x01000000）。
        const blockType = dv.getUint32(offset, littleEndian);

        // --- 读取通用块头 ---
        const blockLen = dv.getUint32(offset + 4, littleEndian);
        if (blockLen < PCAPNG_BLOCK_FIXED_OVERHEAD || offset + blockLen > bytes.length) {
            capture.addWarning(`Block at offset ${offset} declares an invalid length (${blockLen}); stopping.`);
            break;
        }

        // 块尾重复的块总长是冗余校验位，借此判断块是否在传输中损坏
        const trailingLen = dv.getUint32(offset + blockLen - 4, littleEndian);
        if (trailingLen !== blockLen) {
            capture.addWarning(
                `Block at offset ${offset} has mismatched length fields ` +
                `(header says ${blockLen}, trailer says ${trailingLen}).`
            );
        }

        // 块体范围：去掉前 8 字节头与尾部 4 字节长度
        const bodyStart = offset + 8;
        const bodyEnd = offset + blockLen - 4;

        switch (blockType) {
            case PCAPNG_BLOCK.INTERFACE_DESCRIPTION: {
                // 接口描述块：定义链路类型、截断长度与时间戳分辨率
                const iface = new PcapInterface(idbCountInSection);
                iface.linkType = dv.getUint16(bodyStart, littleEndian);
                iface.linkTypeName = getLinkTypeName(iface.linkType);
                iface.snaplen = dv.getUint32(bodyStart + 4, littleEndian);

                const opts = readOptions(bytes, dv, bodyStart + 8, bodyEnd, littleEndian);
                for (const opt of opts) {
                    switch (opt.code) {
                        case 1:  iface.comment = opt.asString(); break;
                        case 2:  iface.name = opt.asString(); break;
                        case 3:  iface.description = opt.asString(); break;
                        case 9:  iface.setTimestampResolution(opt.value[0]); break;
                        case 11: iface.filter = opt.asString(); break;
                        case 12: iface.os = opt.asString(); break;
                        default: break;
                    }
                }

                interfaces.push(iface);
                capture.interfaces.push(iface);
                idbCountInSection++;
                break;
            }

            case PCAPNG_BLOCK.ENHANCED_PACKET: {
                // 增强分组块：接口号(4) + 时间戳高低位(8) + 捕获长(4) + 原始长(4) + 数据 + 选项
                if (index >= maxPackets) {
                    capture.truncatedAt = index;
                    capture.addWarning(`Stopped after ${maxPackets} packets (maxPackets limit).`);
                    return capture;
                }

                const interfaceId = dv.getUint32(bodyStart, littleEndian);
                const tsHigh = dv.getUint32(bodyStart + 4, littleEndian);
                const tsLow = dv.getUint32(bodyStart + 8, littleEndian);
                const inclLen = dv.getUint32(bodyStart + 12, littleEndian);
                const origLen = dv.getUint32(bodyStart + 16, littleEndian);
                const dataStart = bodyStart + 20;

                // 数据后面紧跟选项，但选项区可省；被截断时数据长度也要收缩
                let available = inclLen;
                if (dataStart + inclLen > bodyEnd) {
                    available = Math.max(0, bodyEnd - dataStart);
                    capture.addWarning(
                        `Packet ${index} in block at offset ${offset} declares ${inclLen} bytes ` +
                        `but only ${available} fit inside the block.`
                    );
                }

                const packet = createPcapngPacket(
                    index, interfaceId, tsHigh, tsLow, available, origLen,
                    bytes.slice(dataStart, dataStart + available),
                    interfaces, capture
                );
                applyPacketOptions(packet, bytes, dv, dataStart + alignTo4(available), bodyEnd, littleEndian);

                capture.packets.push(packet);
                index++;

                break;
            }

            case PCAPNG_BLOCK.SIMPLE_PACKET: {
                // 简单分组块：只有原始长度(4) + 数据，没有时间戳也没有接口号
                if (index >= maxPackets) {
                    capture.truncatedAt = index;
                    capture.addWarning(`Stopped after ${maxPackets} packets (maxPackets limit).`);
                    return capture;
                }

                const origLen = dv.getUint32(bodyStart, littleEndian);
                const dataStart = bodyStart + 4;
                const available = Math.max(0, bodyEnd - dataStart);

                const packet = createPcapngPacket(
                    index, 0, 0, 0, available, origLen,
                    bytes.slice(dataStart, dataStart + available),
                    interfaces, capture
                );
                // SPB 无时间戳，标记出来以免上层把它当成 1970 年的包
                packet.hasTimestamp = false;
                packet.timestamp = NaN;
                packet.tsSec = null;
                packet.tsFrac = null;

                capture.packets.push(packet);
                index++;

                break;
            }

            case PCAPNG_BLOCK.NAME_RESOLUTION: {
                // 名字解析块给出绝对时间基准，用于校正此前无时间戳的包
                const records = readNameResolutionRecords(bytes, dv, bodyStart, bodyEnd, littleEndian);
                if (records.length) {
                    capture.addWarning(
                        `Name resolution block at offset ${offset} contains ${records.length} record(s); ` +
                        `name resolution is not applied to packet output.`
                    );
                }
                break;
            }

            case PCAPNG_BLOCK.INTERFACE_STATISTICS:
            case PCAPNG_BLOCK.DECRYPTION_SECRETS:
            case PCAPNG_BLOCK.PACKET:
                // 这几种块不影响"取出帧数据"，静默跳过
                break;

            default:
                // 未知块类型：跳过而不是报错，保证向前兼容
                capture.addWarning(
                    `Skipped unrecognised block type 0x${blockType.toString(16)} at offset ${offset}.`
                );
                break;
        }

        // 块总长已含填充，直接跳到下一块
        offset += blockLen;
    }

    if (index === 0) {
        capture.addWarning("The capture file contains no packet records.");
    }
    if (interfaces.length === 0) {
        capture.addWarning("No interface description blocks were found; link type defaults to Ethernet.");
    }

    return capture;
}


/**
 * 构造一个 pcapng 包对象，并把接口信息（链路类型、时间戳分辨率）落实进去。
 *
 * 抽成函数是因为 EPB 与 SPB 两条路径都要做同样的事，
 * 差别只在时间戳是否存在。
 *
 * @private
 * @param {number} index - 包序号
 * @param {number} interfaceId - 接口号
 * @param {number} tsHigh - 时间戳高 32 位
 * @param {number} tsLow - 时间戳低 32 位
 * @param {number} inclLen - 实际捕获长度
 * @param {number} origLen - 原始长度
 * @param {Uint8Array} data - 帧字节
 * @param {PcapInterface[]} interfaces - 当前 section 的接口表
 * @param {PcapCapture} capture - 用于记录警告
 * @returns {PcapPacket}
 */
function createPcapngPacket(index, interfaceId, tsHigh, tsLow, inclLen, origLen, data, interfaces, capture) {
    const packet = new PcapPacket(index);
    packet.interfaceId = interfaceId;
    packet.inclLen = inclLen;
    packet.origLen = origLen;
    packet.data = data;
    packet.truncated = inclLen < origLen;
    packet.hasTimestamp = true;

    // 用 BigInt 拼 64 位时间戳——直接 (tsHigh << 32) 会因位移超出 32 位而丢精度
    const ticks = (BigInt(tsHigh) << BigInt(32)) | BigInt(tsLow);
    packet.tsTicks = ticks;

    const iface = interfaces[interfaceId];
    if (iface) {
        packet.linkType = iface.linkType;
        packet.linkTypeName = iface.linkTypeName;
        packet.timestamp = iface.ticksToSeconds(ticks);
        packet.tsResolution = iface.tsResolution;
    } else {
        // 引用了未定义的接口：按以太网 + 微秒兜底，并告警
        capture.addWarning(
            `Packet ${index} references interface ${interfaceId} which has no description block; ` +
            `assuming Ethernet with microsecond timestamps.`
        );
        packet.linkType = LINKTYPE.ETHERNET;
        packet.linkTypeName = getLinkTypeName(packet.linkType);
        packet.timestamp = Number(ticks) / 1000000;
        packet.tsResolution = 1000000;
    }

    packet.tsSec = Math.floor(packet.timestamp);
    packet.tsFrac = Math.round((packet.timestamp - packet.tsSec) * packet.tsResolution);

    return packet;
}


/**
 * 解析 EPB 数据之后的选项区，把 opt_comment 等附加信息挂到包上。
 *
 * @private
 * @param {PcapPacket} packet - 目标包
 * @param {Uint8Array} bytes - 整个文件字节
 * @param {DataView} dv - 数据视图
 * @param {number} start - 选项区起始偏移
 * @param {number} end - 块体结束偏移
 * @param {boolean} littleEndian - 端序
 */
function applyPacketOptions(packet, bytes, dv, start, end, littleEndian) {
    if (start >= end) return;

    const opts = readOptions(bytes, dv, start, end, littleEndian);
    for (const opt of opts) {
        switch (opt.code) {
            case 1:
                packet.comment = opt.asString();
                break;
            case 2:
                // epb_flags：含方向与 FCS 长度等位域
                packet.flags = opt.asUint32();
                break;
            case 4:
                // epb_dropcount：抓包时被丢弃的包数（统计用）
                packet.dropCount = opt.asUint64();
                break;
            default:
                break;
        }
    }
}


/**
 * 从 pcapng 的选项区读出所有选项（TLV 结构）。
 *
 * 选项统一为：code(2) + length(2) + value(length 字节，末尾 4 字节对齐补齐)，
 * 以 code = 0（opt_endofopt）表示结束。读不到结束标记时读到区域末尾为止。
 *
 * @private
 * @param {Uint8Array} bytes - 整个文件字节
 * @param {DataView} dv - 数据视图
 * @param {number} start - 选项区起始偏移
 * @param {number} end - 区域结束偏移（不含）
 * @param {boolean} littleEndian - 端序
 * @returns {Object[]} 形如 {code, value} 的选项数组
 */
function readOptions(bytes, dv, start, end, littleEndian) {
    const options = [];
    let pos = start;

    while (pos + 4 <= end) {
        const code = dv.getUint16(pos, littleEndian);
        const length = dv.getUint16(pos + 2, littleEndian);
        pos += 4;

        // code = 0 是 opt_endofopt，说明选项区到此结束
        if (code === 0) break;
        if (pos + length > end) {
            // 选项声明长度超出区域，属损坏；丢弃该选项后停止
            break;
        }

        const value = bytes.slice(pos, pos + length);

        options.push({
            code,
            length,
            value,
            /**
             * 把选项值按 UTF-8 解码为字符串。
             * @returns {string}
             */
            asString() {
                return new TextDecoder("utf-8").decode(value).replace(/\0+$/, "");
            },
            /**
             * 把选项值当作 32 位无符号整数读取。
             * @returns {number}
             */
            asUint32() {
                if (value.length < 4) return 0;
                const vdv = new DataView(value.buffer, value.byteOffset, value.byteLength);
                return vdv.getUint32(0, littleEndian);
            },
            /**
             * 把选项值当作 64 位无符号整数读取，用 BigInt 承载。
             * @returns {bigint}
             */
            asUint64() {
                if (value.length < 8) return BigInt(0);
                const vdv = new DataView(value.buffer, value.byteOffset, value.byteLength);
                return vdv.getBigUint64(0, littleEndian);
            },
        });

        // 选项值后面补齐到 4 字节边界
        pos += alignTo4(length);
    }

    return options;
}


/**
 * 读出名字解析块中的所有记录。
 *
 * 记录结构为：类型(2) + 长度(2) + 值(长度字节，4 字节对齐)。
 * 本库不使用这些记录，但读出来可以让调用方了解文件里有多少名称映射。
 *
 * @private
 * @param {Uint8Array} bytes
 * @param {DataView} dv
 * @param {number} start
 * @param {number} end
 * @param {boolean} littleEndian
 * @returns {Object[]} 形如 {type, value} 的记录数组
 */
function readNameResolutionRecords(bytes, dv, start, end, littleEndian) {
    const records = [];
    let pos = start;

    while (pos + 4 <= end) {
        const type = dv.getUint16(pos, littleEndian);
        const length = dv.getUint16(pos + 2, littleEndian);
        pos += 4;

        if (type === 0) break;            // nrb_record_end
        if (pos + length > end) break;

        records.push({ type, value: bytes.slice(pos, pos + length) });
        pos += alignTo4(length);
    }

    return records;
}


/**
 * 把长度向上补齐到 4 字节边界。
 *
 * pcapng 规定所有块与选项都按 4 字节对齐，缺多少补多少零。
 *
 * @private
 * @param {number} length - 原始长度
 * @returns {number} 补齐后的字节数
 */
function alignTo4(length) {
    return (length + 3) & ~3;
}


/**
 * 把若干字节拼接成一个。
 *
 * @private
 * @param {Uint8Array[]} chunks - 待拼接的字节块
 * @returns {Uint8Array}
 */
function concatChunks(chunks) {
    const total = chunks.reduce((acc, c) => acc + c.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
        out.set(c, offset);
        offset += c.length;
    }
    return out;
}


/**
 * 把一份抓包模型重新序列化成经典 pcap 字节流。
 *
 * 与 parsePcap 互为逆运算，因此本函数保证 parsePcap(writePcap(c)) 能在
 * 包数据、时间戳、链路类型三个维度还原输入（时间戳受 tick 精度限制，
 * 微秒以外的位数会被舍去，这与真实 pcap 文件的表达能力一致）。
 *
 * 这是"只读解析"走向"可编辑"的关键一步：有了写出能力，过滤、裁剪、
 * 合并等操作才能产出可被 Wireshark 直接打开的成品文件。
 *
 * @param {PcapCapture} capture - 抓包模型
 * @param {Object} [options={}]
 * @param {PcapPacket[]} [options.packets] - 只写出这些包，缺省写出 capture.packets 全部
 * @param {boolean} [options.littleEndian] - 强制指定端序，缺省沿用 capture.byteOrder
 * @param {boolean} [options.nanosecond] - 是否用纳秒精度，缺省沿用 capture.nanosecond
 * @param {number} [options.linkType] - 强制指定链路类型，缺省沿用 capture.linkType
 * @returns {Uint8Array} pcap 文件字节
 */
export function writePcap(capture, options = {}) {
    const packets = options.packets || capture.packets;
    const littleEndian = options.littleEndian !== undefined ?
        options.littleEndian :
        capture.byteOrder !== "be";
    const nanosecond = options.nanosecond !== undefined ? options.nanosecond : capture.nanosecond;
    const linkType = options.linkType !== undefined ? options.linkType : capture.linkType;

    // --- 全局头：24 字节 ---
    const header = new Uint8Array(PCAP_GLOBAL_HEADER_LEN);
    const hdv = new DataView(header.buffer);

    // 魔数随端序取不同写法：0xa1b2c3d4 微秒、0xa1b23c4d 纳秒
    const magic = nanosecond ? PCAP_MAGIC.NANOSECOND : PCAP_MAGIC.MICROSECOND;
    hdv.setUint32(0, magic, littleEndian);

    // 版本固定 2.4 —— 这是业界事实标准，写其他版本多数工具会拒绝
    hdv.setUint16(4, 2, littleEndian);
    hdv.setUint16(6, 4, littleEndian);
    hdv.setUint32(8, 0, littleEndian);                       // thiszone
    hdv.setUint32(12, 0, littleEndian);                      // sigfigs
    hdv.setUint32(16, capture.snaplen || 262144, littleEndian);
    hdv.setUint32(20, linkType === null || linkType === undefined ? LINKTYPE.ETHERNET : linkType, littleEndian);

    const chunks = [header];
    const tickPerSecond = nanosecond ? 1000000000 : 1000000;

    // --- 逐包写记录头（16 字节）+ 数据 ---
    for (const pkt of packets) {
        const rec = new Uint8Array(PCAP_PACKET_HEADER_LEN);
        const rdv = new DataView(rec.buffer);

        // 秒与小数拆开写：小数部分是"该精度下的 tick 数"，不是毫秒
        const sec = Math.floor(pkt.timestamp);
        const frac = Math.round((pkt.timestamp - sec) * tickPerSecond);

        rdv.setUint32(0, sec >>> 0, littleEndian);
        rdv.setUint32(4, frac >>> 0, littleEndian);
        rdv.setUint32(8, pkt.data.length, littleEndian);
        // origLen 缺省时用实际长度；被 snaplen 截断的包应保留原始长度信息
        rdv.setUint32(12, pkt.origLen || pkt.data.length, littleEndian);

        chunks.push(rec, pkt.data);
    }

    return concatChunks(chunks);
}


/**
 * 把一份抓包模型序列化成 pcapng 字节流。
 *
 * 相比经典 pcap，pcapng 能表达每个包的接口归属与注释。本函数按
 * 「一个 SHB + 每个链路类型一个 IDB + 每个包一个 EPB」的最小合法结构写出，
 * 时间戳分辨率固定用 10^-9（纳秒），这是 pcapng 的默认值。
 *
 * @param {PcapCapture} capture - 抓包模型
 * @param {Object} [options={}]
 * @param {PcapPacket[]} [options.packets] - 只写出这些包
 * @param {boolean} [options.littleEndian] - 强制指定端序
 * @returns {Uint8Array} pcapng 文件字节
 */
export function writePcapng(capture, options = {}) {
    const packets = options.packets || capture.packets;
    const littleEndian = options.littleEndian !== undefined ?
        options.littleEndian :
        capture.byteOrder !== "be";

    /**
     * 组装一个块：类型 + 总长 + 主体 + 总长（尾部再写一遍，便于反向遍历）。
     */
    function block(type, body) {
        const pad = (4 - (body.length % 4)) % 4;
        const padded = pad ? concatChunks([body, new Uint8Array(pad)]) : body;
        const totalLen = 12 + padded.length;

        const head = new Uint8Array(8);
        const hdv = new DataView(head.buffer);
        hdv.setUint32(0, type, littleEndian);
        hdv.setUint32(4, totalLen, littleEndian);

        const tail = new Uint8Array(4);
        new DataView(tail.buffer).setUint32(0, totalLen, littleEndian);

        return concatChunks([head, padded, tail]);
    }

    // --- SHB：字节序魔数 + 版本 + 段长度（-1 表示未知）---
    const shbBody = new Uint8Array(16);
    const sdv = new DataView(shbBody.buffer);
    sdv.setUint32(0, 0x1a2b3c4d, littleEndian);
    sdv.setUint16(4, 1, littleEndian);
    sdv.setUint16(6, 0, littleEndian);
    sdv.setBigUint64(8, BigInt("0xffffffffffffffff"), littleEndian);

    const chunks = [block(0x0a0d0d0a, shbBody)];

    // --- 按链路类型去重建 IDB ---
    const linkTypes = Array.from(new Set(packets.map(p => p.linkType)));
    if (!linkTypes.length) linkTypes.push(capture.linkType === null || capture.linkType === undefined ?
        LINKTYPE.ETHERNET :
        capture.linkType);

    const interfaceIndex = new Map();
    linkTypes.forEach((lt, i) => {
        interfaceIndex.set(lt, i);

        // 【关键】IDB 里必须显式声明 if_tsresol，否则读方按规范默认值 10^-6
        // 解释 EPB 的时间戳，写出的纳秒 tick 会被当作微秒，时间差放大 1000 倍。
        // if_tsresol 的取值：最高位为 0 表示以 10 为底，低 7 位是负指数，
        // 故 9 表示 10^-9 秒（纳秒）。选项区以「码 0、长 0」结束。
        const idbBody = new Uint8Array(20);
        const idv = new DataView(idbBody.buffer);
        idv.setUint16(0, lt, littleEndian);
        idv.setUint16(2, 0, littleEndian);                   // reserved
        idv.setUint32(4, capture.snaplen || 262144, littleEndian);
        idv.setUint16(8, 9, littleEndian);                   // option code: if_tsresol
        idv.setUint16(10, 1, littleEndian);                  // option length
        idv.setUint8(12, 9);                                 // value: 10^-9
        // 13..15 为对齐补零
        idv.setUint16(16, 0, littleEndian);                  // opt_endofopt
        idv.setUint16(18, 0, littleEndian);

        chunks.push(block(0x00000001, idbBody));
    });

    // --- 逐包建 EPB ---
    for (const pkt of packets) {
        const ifId = interfaceIndex.get(pkt.linkType) || 0;

        // 时间戳是 64 位无符号整数，秒 × 10^9 + 纳秒；必须用 BigInt，
        // 否则 1.6e9 秒对应的 tick 数（1.6e18）会超出 double 的整数精度
        const ticks = BigInt(Math.floor(pkt.timestamp)) * BigInt(1000000000) +
            BigInt(Math.round((pkt.timestamp - Math.floor(pkt.timestamp)) * 1e9));
        const tsHigh = Number((ticks >> BigInt(32)) & BigInt(0xffffffff));
        const tsLow = Number(ticks & BigInt(0xffffffff));

        const pad = (4 - (pkt.data.length % 4)) % 4;
        const body = new Uint8Array(20 + pkt.data.length + pad);
        const bdv = new DataView(body.buffer);

        bdv.setUint32(0, ifId, littleEndian);
        bdv.setUint32(4, tsHigh, littleEndian);
        bdv.setUint32(8, tsLow, littleEndian);
        bdv.setUint32(12, pkt.data.length, littleEndian);
        bdv.setUint32(16, pkt.origLen || pkt.data.length, littleEndian);
        body.set(pkt.data, 20);

        chunks.push(block(0x00000006, body));
    }

    return concatChunks(chunks);
}


export default {
    writePcap,
    writePcapng,
    parsePcap,
    isPcap,
    getLinkTypeName,
    LINKTYPE,
    LINKTYPE_NAMES,
    PcapCapture,
    PcapPacket,
    PcapInterface,
    DEFAULT_MAX_PACKETS,
};
