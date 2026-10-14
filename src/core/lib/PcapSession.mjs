/**
 * @author CyberChef Contributor
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

import {StreamTracker} from "./PcapStream.mjs";

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 抓包会话归并与应用层识别
 * 【文件】src/core/lib/PcapSession.mjs
 * 【职责】在"容器解析 → 逐包分层解析 → TCP 流重组"之上再搭一层：
 *         把散落的包与流归并成"会话"，用端口与载荷特征识别应用层协议，
 *         并汇总抓包整体的统计信息。
 *         这是从"字节"走向"人话"的一层——让人一眼看出抓到了什么业务。
 * 【被谁使用】operations/ParsePcap、operations/PcapSummary
 * ------------------------------------------------------------
 * 【导出接口】
 *   - APP_PROTOCOL                : 应用层协议名常量表
 *   - PORT_HINTS                  : 端口号 → 协议名 的静态提示表
 *   - class PcapConversation      : 一次会话（一对端点之间的全部往来）
 *   - class PcapAnalysis          : 整个抓包文件的分析结果
 *   - detectApplicationProtocol() : 纯函数，对一段双向载荷做协议识别
 *   - analysePcap(capture)        : 主入口，一次跑完全部流程
 *   - buildUdpFlows()             : 把 UDP 报文按四元组归并成流
 * ------------------------------------------------------------
 * 【关键算法】
 *   1. 双层归并：TCP 侧归并的粒度是"连接"（由 PcapStream 的四元组 + 方向
 *      规范化完成）；UDP 侧没有连接概念，只能按四元组 + 时间窗口归并，
 *      这里简化为只按四元组归并（同一对端口的报文算一条流）。
 *   2. 应用层识别采用"载荷优先、端口兜底"的两级策略：
 *        · 第一级看载荷特征（HTTP 方法行、HTTP 状态行、TLS 记录头、
 *          SSH 版本串、SMTP 命令……）。载荷是"直接证据"，可信度最高，
 *          即便跑在非常规端口上也能认出来。
 *        · 第二级看端口号。端口只是"间接线索"，但覆盖率高——
 *          很多加密流量（TLS）载荷不可读，只能靠端口。
 *      最终结果带 confidence 字段（high / medium / low / unknown），
 *      而不是给一个没有可信度的光秃秃的协议名。这一点很关键：
 *      把所有 443 端口都断定成 TLS 是不严谨的，标注可信度才诚实。
 *   3. 会话统计需要"时延"这类跨包指标，因此要在归并后回扫包的元信息，
 *      而不能只依赖流重组结果。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 协议特征表写成"正则数组 + 协议名"的数据结构，识别逻辑是一个 for 循环。
 *     新增一种协议只需往表里加一行，不需要改任何控制流——这是把
 *     "策略"与"机制"分离的常见做法。
 *   - 所有识别函数都只读载荷前若干字节（取 min(长度, 512)），
 *     避免在大流量抓包上做无谓的全量扫描。
 *   - 二进制载荷先尝试按可打印文本解码再用正则匹配；匹配失败时不做
 *     二次尝试，直接返回 unknown，避免正则回溯带来的性能风险。
 * ============================================================
 */

/**
 * 应用层协议名称常量。
 *
 * 用常量而非散落的字符串字面量，避免出现 "HTTP" 与 "http" 两种写法，
 * 也便于在其他模块里做等值判断。
 */
export const APP_PROTOCOL = {
    HTTP: "HTTP",
    TLS: "TLS",
    SSH: "SSH",
    DNS: "DNS",
    SMTP: "SMTP",
    POP3: "POP3",
    IMAP: "IMAP",
    FTP: "FTP",
    TELNET: "Telnet",
    DHCP: "DHCP",
    NTP: "NTP",
    SMB: "SMB",
    RDP: "RDP",
    MYSQL: "MySQL",
    POSTGRES: "PostgreSQL",
    REDIS: "Redis",
    MQTT: "MQTT",
    QUIC: "QUIC",
    MDNS: "mDNS",
    SSDP: "SSDP",
    UNKNOWN: "Unknown",
};

/**
 * 端口号 → 协议名 的静态提示表。
 *
 * 这是"兜底"手段：载荷不可读（加密）或为空（纯握手包）时，只能靠端口。
 * 表里同时收录 TCP 与 UDP 的常见端口，使用时由调用方限定传输层协议，
 * 以免把 UDP/53 与 TCP/53 之外的误判混入。
 */
export const PORT_HINTS = {
    tcp: {
        20: APP_PROTOCOL.FTP, 21: APP_PROTOCOL.FTP,
        22: APP_PROTOCOL.SSH,
        23: APP_PROTOCOL.TELNET,
        25: APP_PROTOCOL.SMTP, 465: APP_PROTOCOL.SMTP, 587: APP_PROTOCOL.SMTP,
        53: APP_PROTOCOL.DNS,
        80: APP_PROTOCOL.HTTP, 8080: APP_PROTOCOL.HTTP, 8000: APP_PROTOCOL.HTTP,
        3128: APP_PROTOCOL.HTTP, 8888: APP_PROTOCOL.HTTP,
        110: APP_PROTOCOL.POP3, 995: APP_PROTOCOL.POP3,
        143: APP_PROTOCOL.IMAP, 993: APP_PROTOCOL.IMAP,
        443: APP_PROTOCOL.TLS, 8443: APP_PROTOCOL.TLS, 9443: APP_PROTOCOL.TLS,
        445: APP_PROTOCOL.SMB,
        3389: APP_PROTOCOL.RDP,
        3306: APP_PROTOCOL.MYSQL,
        5432: APP_PROTOCOL.POSTGRES,
        6379: APP_PROTOCOL.REDIS,
        1883: APP_PROTOCOL.MQTT, 8883: APP_PROTOCOL.MQTT,
    },
    udp: {
        53: APP_PROTOCOL.DNS,
        67: APP_PROTOCOL.DHCP, 68: APP_PROTOCOL.DHCP,
        123: APP_PROTOCOL.NTP,
        443: APP_PROTOCOL.QUIC,   // QUIC 跑在 UDP 443
        5353: APP_PROTOCOL.MDNS,
        1900: APP_PROTOCOL.SSDP,
        1883: APP_PROTOCOL.MQTT,
    },
};

/**
 * 载荷特征识别规则表。
 *
 * 每条规则形如 { protocol, test(文本), note }，按顺序匹配，先命中者胜。
 * 顺序很重要：HTTP 的方法行与状态行必须排在前面，因为它们的特征最明确；
 * TLS 只需看固定字节，几乎不会误命中。
 *
 * 之所以用"数据表驱动"而不是一串 if/else：新增协议只需加一行，
 * 识别主循环完全不用动。
 */
const PAYLOAD_SIGNATURES = [
    {
        protocol: APP_PROTOCOL.HTTP,
        note: "HTTP 请求行：方法名 + 空格",
        test: text => /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) \S+ HTTP\/\d(\.\d)?\r?\n/.test(text),
    },
    {
        protocol: APP_PROTOCOL.HTTP,
        note: "HTTP 状态行：HTTP/版本 + 状态码",
        test: text => /^HTTP\/\d(\.\d)? \d{3}[ \r\n]/.test(text),
    },
    {
        protocol: APP_PROTOCOL.SSH,
        note: "SSH 版本串，如 SSH-2.0-OpenSSH_8.9",
        test: text => /^SSH-\d\.\d-/.test(text),
    },
    {
        protocol: APP_PROTOCOL.SMTP,
        note: "SMTP 命令或响应码",
        test: text => /^(EHLO|HELO|MAIL FROM|RCPT TO|DATA\b|QUIT|220[ -]|250[ -])/.test(text),
    },
    {
        protocol: APP_PROTOCOL.FTP,
        note: "FTP 命令或响应码",
        test: text => /^(USER |PASS |RETR |STOR |LIST\b|PASV|TYPE |220[ -]|331[ -]|230[ -])/.test(text),
    },
    {
        protocol: APP_PROTOCOL.POP3,
        note: "POP3 命令或响应码",
        test: text => /^(\+OK|USER |PASS |STAT\b|LIST\b|RETR |QUIT)/.test(text),
    },
    {
        protocol: APP_PROTOCOL.IMAP,
        note: "IMAP 命令，形如 \"a001 LOGIN\"",
        test: text => /^\S+ (CAPABILITY|LOGIN|SELECT|FETCH|LOGOUT)\b/i.test(text),
    },
    {
        protocol: APP_PROTOCOL.REDIS,
        note: "Redis 内联命令或响应",
        test: text => /^(\*[0-9]+\r\n|\+OK\r\n|-ERR |\$[0-9]+\r\n)/.test(text),
    },
];

/**
 * TLS 记录头的判定。
 *
 * TLS 记录层固定为：内容类型(1) + 版本(2) + 长度(2)。内容类型取值
 * 20(ChangeCipherSpec)/21(Alert)/22(Handshake)/23(ApplicationData)，
 * 版本高字节恒为 0x03（SSL 3.0 至 TLS 1.3 均如此）。
 * 这两个约束同时成立才判定为 TLS，误判率极低。
 *
 * @param {Uint8Array} bytes - 载荷字节
 * @returns {boolean}
 */
function looksLikeTLS(bytes) {
    if (bytes.length < 5) return false;
    const contentType = bytes[0];
    const versionMajor = bytes[1];
    const versionMinor = bytes[2];

    const validContentType = contentType >= 20 && contentType <= 23;
    const validVersion = versionMajor === 0x03 && versionMinor <= 0x04;

    return validContentType && validVersion;
}

/**
 * 把一段字节尽力解码成可打印文本。
 *
 * 只解码前 maxBytes 字节，且遇到大量非可打印字符时不强行解码——
 * 加密载荷强行转字符串只会得到乱码并拖慢后续正则匹配。
 *
 * @param {Uint8Array} bytes - 待解码字节
 * @param {number} [maxBytes=512] - 最多解码多少字节
 * @returns {string|null} 可打印文本，或 null 表示不像文本
 */
function toPrintable(bytes, maxBytes = 512) {
    if (!bytes || bytes.length === 0) return null;

    const slice = bytes.slice(0, Math.min(bytes.length, maxBytes));
    let nonPrintable = 0;

    for (const b of slice) {
        // 允许换行、回车、制表符与常规可打印 ASCII
        const printable = (b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d;
        if (!printable) nonPrintable++;
    }

    // 非可打印字符超过三成，就认为不是文本，不再往下走
    if (nonPrintable / slice.length > 0.3) return null;

    let text = "";
    for (const b of slice) {
        text += String.fromCharCode(b);
    }
    return text;
}


/**
 * 对一段载荷做应用层协议识别。
 *
 * 纯函数，不依赖任何外部状态，便于单元测试。
 *
 * @param {Object} payloads - 双向载荷 {aToB: Uint8Array, bToA: Uint8Array}
 * @param {Object} endpoints - 端点信息 {a: {ip, port}, b: {ip, port}}
 * @param {string} transportProtocol - "TCP" 或 "UDP"
 * @returns {{protocol: string, confidence: string, evidence: string}}
 *          confidence 取值：high（载荷特征命中）、medium（端口命中）、
 *          unknown（无任何线索）
 */
export function detectApplicationProtocol(payloads, endpoints, transportProtocol) {
    const aBytes = payloads.aToB || new Uint8Array(0);
    const bBytes = payloads.bToA || new Uint8Array(0);

    // --- 第一级：载荷特征。两个方向都要试，因为发起方可能是任一端点 ---
    for (const [bytes, direction] of [[aBytes, "a→b"], [bBytes, "b→a"]]) {
        if (bytes.length === 0) continue;

        // TLS 是二进制协议，必须先于文本解码判断，否则会被当成乱码跳过
        if (looksLikeTLS(bytes)) {
            return {
                protocol: APP_PROTOCOL.TLS,
                confidence: "high",
                evidence: `TLS 记录头 (内容类型 ${bytes[0]}, 版本 3.${bytes[2]}) 于 ${direction} 方向`,
            };
        }

        const text = toPrintable(bytes);
        if (text === null) continue;

        for (const sig of PAYLOAD_SIGNATURES) {
            if (sig.test(text)) {
                return {
                    protocol: sig.protocol,
                    confidence: "high",
                    evidence: `${sig.note}（${direction} 方向载荷）`,
                };
            }
        }
    }

    // --- 第二级：端口兜底 ---
    const portTable = PORT_HINTS[transportProtocol.toLowerCase()] || {};
    const aHint = portTable[endpoints.a.port];
    const bHint = portTable[endpoints.b.port];

    // 服务端一般是端口较小的那一侧；这里两个端口都查，命中即用
    if (aHint || bHint) {
        return {
            protocol: aHint || bHint,
            confidence: "medium",
            evidence: `端口提示（${aHint ? endpoints.a.port : endpoints.b.port} 端口常对应 ${aHint || bHint}）`,
        };
    }

    return {
        protocol: APP_PROTOCOL.UNKNOWN,
        confidence: "unknown",
        evidence: "载荷无已知特征，且端口不在已知对照表中",
    };
}


/**
 * 一次网络会话。
 *
 * 会话 = 一对端点之间的全部往来。TCP 会话内部可能包含多个 TCP 流
 * （连接复用、重连），因此用 streams 数组而不是单个流。
 */
export class PcapConversation {

    /**
     * @param {string} key - 会话唯一键
     * @param {string} transportProtocol - "TCP" 或 "UDP"
     */
    constructor(key, transportProtocol) {
        this.key = key;
        this.transportProtocol = transportProtocol;
        this.endpoints = {a: {ip: "", port: 0}, b: {ip: "", port: 0}};
        this.streams = [];          // TCP 流（TCP 会话才有）
        this.packets = [];          // 属于本会话的包（DissectedPacket）
        this.app = {protocol: APP_PROTOCOL.UNKNOWN, confidence: "unknown", evidence: ""};
        this.reassembled = null;    // 缓存双向重组结果
    }

    /**
     * 把一条包挂进本会话。
     *
     * @param {Object} dissected - DissectedPacket
     */
    addPacket(dissected) {
        this.packets.push(dissected);
    }

    /**
     * 会话内所有包的原始字节总量。
     * @returns {number}
     */
    get totalBytes() {
        return this.packets.reduce((acc, p) => acc + (p.payload ? p.payload.length : 0), 0);
    }

    /**
     * 会话起止时间。
     * @returns {{startTime: number, endTime: number, duration: number}}
     */
    get timing() {
        if (!this.packets.length) return {startTime: 0, endTime: 0, duration: 0};
        const times = this.packets
            .map(p => p.timestamp)
            .filter(t => !Number.isNaN(t));
        if (!times.length) return {startTime: 0, endTime: 0, duration: 0};

        const startTime = Math.min(...times);
        const endTime = Math.max(...times);
        return {startTime, endTime, duration: endTime - startTime};
    }

    /**
     * 会话摘要，供界面表格与 JSON 输出使用。
     *
     * @returns {Object}
     */
    get summary() {
        const timing = this.timing;
        return {
            key: this.key,
            transportProtocol: this.transportProtocol,
            client: this.endpoints.a,
            server: this.endpoints.b,
            appProtocol: this.app.protocol,
            confidence: this.app.confidence,
            evidence: this.app.evidence,
            packetCount: this.packets.length,
            payloadBytes: this.totalBytes,
            streamCount: this.streams.length,
            startTime: timing.startTime,
            duration: timing.duration,
            state: this.streams.length ? this.streams.map(s => s.stats.state).join(", ") : "n/a",
        };
    }
}


/**
 * 整个抓包文件的分析结果。
 *
 * 把"容器模型 → 解包结果 → 流 → 会话 → 统计"这条链路的产物收在一起，
 * 上层操作可以只取自己需要的那一段。
 */
export class PcapAnalysis {

    /**
     * @param {PcapCapture} capture - 容器解析结果
     */
    constructor(capture) {
        this.capture = capture;
        this.packets = [];           // DissectedPacket[]
        this.streams = [];           // TcpStream[]
        this.conversations = [];     // PcapConversation[]
        this.streamStats = null;     // StreamTracker 的统计
        this.issues = [];            // 解析中发现的问题（非致命）
    }

    /**
     * 按应用层协议统计会话数与字节数。
     *
     * @returns {Object[]} 形如 [{protocol, conversations, packets, payloadBytes}]
     */
    get protocolBreakdown() {
        const byProtocol = new Map();

        for (const conv of this.conversations) {
            const name = conv.app.protocol;
            if (!byProtocol.has(name)) {
                byProtocol.set(name, {protocol: name, conversations: 0, packets: 0, payloadBytes: 0});
            }
            const entry = byProtocol.get(name);
            entry.conversations++;
            entry.packets += conv.packets.length;
            entry.payloadBytes += conv.totalBytes;
        }

        return Array.from(byProtocol.values())
            .sort((a, b) => b.payloadBytes - a.payloadBytes);
    }

    /**
     * 分析结果的整体统计。
     *
     * @returns {Object}
     */
    get stats() {
        const firstPacket = this.packets[0];
        const lastPacket = this.packets[this.packets.length - 1];

        return {
            packetCount: this.packets.length,
            tcpPacketCount: this.packets.filter(p => p.transport && p.transport.protocol === "TCP").length,
            udpPacketCount: this.packets.filter(p => p.transport && p.transport.protocol === "UDP").length,
            otherPacketCount: this.packets.filter(p => !p.transport).length,
            streamCount: this.streams.length,
            conversationCount: this.conversations.length,
            payloadBytes: this.packets.reduce((acc, p) => acc + (p.payload ? p.payload.length : 0), 0),
            startTime: firstPacket ? firstPacket.timestamp : 0,
            endTime: lastPacket ? lastPacket.timestamp : 0,
            duration: firstPacket && lastPacket ? lastPacket.timestamp - firstPacket.timestamp : 0,
            truncatedPackets: this.packets.filter(p => p.truncated).length,
            protocols: this.protocolBreakdown,
        };
    }
}


/**
 * 把 UDP 报文按四元组归并成"流"。
 *
 * UDP 无连接，严格说没有"流"的概念，但按 (源IP, 源端口, 目的IP, 目的端口)
 * 归并后，对 DNS、DHCP 这类请求-应答型协议已经足够实用。
 *
 * 归并后每组按时间排序，并把同一组的载荷拼接起来供协议识别使用。
 *
 * @param {Object[]} dissectedPackets - 全部 DissectedPacket
 * @returns {Object[]} 形如 [{key, endpoints, packets, aToB, bToA}]
 */
export function buildUdpFlows(dissectedPackets) {
    const flows = new Map();

    for (const pkt of dissectedPackets) {
        if (!pkt.transport || pkt.transport.protocol !== "UDP") continue;
        if (!pkt.network) continue;

        // --- 端点规范化，与 PcapStream 保持同样的"排序取小者为 a"约定 ---
        const ep1 = {ip: pkt.network.src, port: pkt.transport.srcPort};
        const ep2 = {ip: pkt.network.dst, port: pkt.transport.dstPort};
        const [a, b] = compareEndpoints(ep1, ep2) <= 0 ? [ep1, ep2] : [ep2, ep1];
        const key = `${a.ip}:${a.port}-${b.ip}:${b.port}`;

        if (!flows.has(key)) {
            flows.set(key, {
                key,
                endpoints: {a, b},
                packets: [],
                aToB: [],
                bToA: [],
            });
        }
        const flow = flows.get(key);
        flow.packets.push(pkt);

        // 判断方向：与规范端点 a 相同的方向归入 aToB
        const isAtoB = pkt.network.src === a.ip && pkt.transport.srcPort === a.port;
        (isAtoB ? flow.aToB : flow.bToA).push(pkt.payload || new Uint8Array(0));
    }

    // 拼接各方向载荷
    return Array.from(flows.values()).map(flow => ({
        key: flow.key,
        endpoints: flow.endpoints,
        packets: flow.packets,
        aToB: concatBytes(flow.aToB),
        bToA: concatBytes(flow.bToA),
    }));
}


/**
 * 比较两个端点，用于确定规范顺序。
 *
 * 先比 IP 字符串（字典序，仅需稳定不限数值），相同再比端口。
 *
 * @param {Object} e1 - {ip, port}
 * @param {Object} e2 - {ip, port}
 * @returns {number} 负数表示 e1 应排在前面
 */
function compareEndpoints(e1, e2) {
    if (e1.ip !== e2.ip) return e1.ip < e2.ip ? -1 : 1;
    if (e1.port !== e2.port) return e1.port - e2.port;
    return 0;
}


/**
 * 把若干字节数组拼成一个。
 *
 * @param {Uint8Array[]} chunks
 * @returns {Uint8Array}
 */
function concatBytes(chunks) {
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
 * 主入口：对一份抓包做完整分析。
 *
 * 流程：逐包分层解析 → TCP 流重组 → UDP 流归并 → 会话归并 →
 * 应用层识别 → 统计汇总。
 *
 * @param {PcapCapture} capture - 由 parsePcap() 得到的容器模型
 * @param {Object} [options={}]
 * @param {Function} options.dissectCapture - 逐包解析函数（由 PcapPacket.mjs 注入，
 *        这样本模块不必反向依赖 PcapPacket，避免循环引用）
 * @returns {PcapAnalysis}
 */
export function analysePcap(capture, options = {}) {
    const dissectCaptureFn = options.dissectCapture;

    if (typeof dissectCaptureFn !== "function") {
        throw new TypeError("analysePcap requires options.dissectCapture to be a function (from PcapPacket.mjs).");
    }

    const analysis = new PcapAnalysis(capture);

    // --- 步骤 1：逐包分层解析 ---
    analysis.packets = dissectCaptureFn(capture);

    // --- 步骤 2：TCP 流重组 ---
    const tracker = new StreamTracker();
    for (const pkt of analysis.packets) {
        tracker.addPacket(pkt);
    }
    tracker.finalize();
    analysis.streams = tracker.streams;
    analysis.streamStats = tracker.stats;

    // --- 步骤 3：UDP 流归并 ---
    const udpFlows = buildUdpFlows(analysis.packets);

    // --- 步骤 4：会话归并。TCP 以流为单位，UDP 以归并后的流为单位 ---
    const conversations = new Map();

    for (const stream of analysis.streams) {
        const conv = new PcapConversation(stream.key, "TCP");
        conv.endpoints = stream.endpoints;
        conv.streams.push(stream);
        conversations.set(`tcp:${stream.key}`, conv);
    }

    for (const flow of udpFlows) {
        const conv = new PcapConversation(flow.key, "UDP");
        conv.endpoints = flow.endpoints;
        conversations.set(`udp:${flow.key}`, conv);
    }

    // 把每个包挂到它所属的会话上
    for (const pkt of analysis.packets) {
        if (!pkt.transport || !pkt.network) continue;

        const ep1 = {ip: pkt.network.src, port: pkt.transport.srcPort};
        const ep2 = {ip: pkt.network.dst, port: pkt.transport.dstPort};
        const [a, b] = compareEndpoints(ep1, ep2) <= 0 ? [ep1, ep2] : [ep2, ep1];
        const key = `${pkt.transport.protocol === "TCP" ? "tcp" : "udp"}:${a.ip}:${a.port}-${b.ip}:${b.port}`;

        const conv = conversations.get(key);
        if (conv) conv.addPacket(pkt);
    }

    // --- 步骤 5：应用层识别 ---
    for (const conv of conversations.values()) {
        let payloads;

        if (conv.streams.length) {
            // TCP：用流重组结果，能得到完整且有序的应用层载荷
            const merged = {aToB: [], bToA: []};
            for (const stream of conv.streams) {
                const re = stream.reassemble();
                merged.aToB.push(re.aToB.data);
                merged.bToA.push(re.bToA.data);
            }
            payloads = {aToB: concatBytes(merged.aToB), bToA: concatBytes(merged.bToA)};
        } else {
            // UDP：用归并后的载荷
            const flow = udpFlows.find(f => f.key === conv.key);
            payloads = flow ? {aToB: flow.aToB, bToA: flow.bToA} : {aToB: new Uint8Array(0), bToA: new Uint8Array(0)};
        }

        conv.reassembled = payloads;
        conv.app = detectApplicationProtocol(payloads, conv.endpoints, conv.transportProtocol);
    }

    analysis.conversations = Array.from(conversations.values())
        .sort((x, y) => x.timing.startTime - y.timing.startTime);

    return analysis;
}


export default {
    APP_PROTOCOL,
    PORT_HINTS,
    PcapConversation,
    PcapAnalysis,
    detectApplicationProtocol,
    buildUdpFlows,
    analysePcap,
};
