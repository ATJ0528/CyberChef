/**
 * @author ATJ0528
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Utils from "../Utils.mjs";
import {parsePcap} from "../lib/Pcap.mjs";
import {dissectCapture, etherTypeName} from "../lib/PcapPacket.mjs";
import {analysePcap} from "../lib/PcapSession.mjs";

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 抓包文件解析
 * 【操作】Parse PCAP
 * 【功能】把 .pcap / .pcapng 抓包文件解析成可读的包列表、协议树与会话统计
 * 【输入】ArrayBuffer —— 抓包文件原始字节（支持直接拖拽文件到输入框）
 * 【输出】json，由 present() 渲染成 HTML 表格
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 校验输入非空，转成 Uint8Array
 *   2. 调用 parsePcap 解析容器格式（自动识别 pcap / pcapng、端序、时间精度）
 *   3. 调用 dissectCapture 逐包分层解包（链路层 → 网络层 → 传输层）
 *   4. 调用 analysePcap 做 TCP 流重组、UDP 归并与应用层协议识别
 *   5. 把结果整理成扁平的 json，供 present() 按所选视图渲染
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 逐包摘要（describePacket）不做完整协议树展开，只取界面需要的那几个
 *     字段。原因是抓包动辄上万包，若每个包都构造完整对象树，内存与渲染
 *     时间都会失控。详情视图只在用户切过去时才展开被选中的部分。
 *   - 渲染包数硬上限 MAX_RENDERED_PACKETS：这是保护浏览器的手段，
 *     而不是数据限制——解析仍然处理全部包，只是不把上万个 <tr> 塞进 DOM。
 *     超出部分在表尾明确提示"另有 N 个包未渲染"，不静默截断。
 *   - TCP 标志位在数据模型里是 {fin:0, syn:1, ...} 的对象形式（便于按位
 *     判断），但界面需要 "SYN, ACK" 这样的文本，故在展示层做一次转换。
 *     转换放在本文件而不是数据模型里，是为了让模型保持机器友好的形态。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 所有拼进 HTML 的字段都过 Utils.escapeHtml。抓包内容完全来自外部
 *     输入，其中很可能包含 <script> 之类的构造——不转义就是存储型 XSS。
 *   - 解析失败一律包装成 OperationError 并带上原始错误信息，
 *     既不吞掉细节，也让界面给出的是友好提示而非堆栈。
 *   - 输入类型用 ArrayBuffer 而非 string：抓包是二进制，若走字符串通道，
 *     未截断的原始字节会在转换中丢失。
 * ============================================================
 */

/** 界面最多渲染的包数，防止超大抓包把浏览器卡死 */
const MAX_RENDERED_PACKETS = 2000;

/** TCP 标志位的显示顺序（握手与挥手时的常见排列） */
const TCP_FLAG_ORDER = ["syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr", "ns"];

/** TCP 标志位的显示名称 */
const TCP_FLAG_NAMES = {
    syn: "SYN", ack: "ACK", fin: "FIN", rst: "RST",
    psh: "PSH", urg: "URG", ece: "ECE", cwr: "CWR", ns: "NS",
};

/** 传输层协议号 → 名称（用于没有传输层解析结果时的回退显示） */
const PROTOCOL_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
};

/**
 * 把 TCP 标志位对象格式化成可读文本。
 *
 * @param {Object} flags - {fin, syn, rst, psh, ack, urg, ece, cwr, ns}
 * @returns {string} 形如 "SYN, ACK"；无标志位时返回空串
 */
function formatFlags(flags) {
    if (!flags) return "";
    return TCP_FLAG_ORDER
        .filter((k) => flags[k])
        .map((k) => TCP_FLAG_NAMES[k])
        .join(", ");
}

/**
 * 为单个包生成界面所需的摘要字段。
 *
 * 只提取表格里要显示的那几列，不构造完整对象树——这是应对大流量抓包
 * 的关键取舍，理由见文件头【关键算法】第 1 条。
 *
 * @param {Object} pkt - DissectedPacket
 * @param {Object} [capturePacket] - 对应的容器层包（用于取整帧长度）
 * @returns {Object} {index, time, src, dst, protocol, length, payloadLength, info}
 */
function describePacket(pkt, capturePacket) {
    const net = pkt.network;
    const tr = pkt.transport;

    const src = net ? net.src : (pkt.link && pkt.link.src ? pkt.link.src : "—");
    const dst = net ? net.dst : (pkt.link && pkt.link.dst ? pkt.link.dst : "—");

    // 协议名优先取传输层结论；没有传输层解析结果时回退到 IP 协议号
    let protocol = tr ? tr.protocol : null;
    if (!protocol && net && net.protocol !== null && net.protocol !== undefined) {
        protocol = PROTOCOL_NAMES[net.protocol] || `IP/${net.protocol}`;
    }
    // 既没有传输层结论也没有 IP 协议号时，退到链路层的以太网类型
    // （例如 ARP 帧就属于这种情况：有链路层、无网络层、无传输层）
    if (!protocol) {
        protocol = pkt.link && pkt.link.etherType !== null ?
            etherTypeName(pkt.link.etherType) :
            "Raw";
    }

    // --- 按传输层类型拼装信息列 ---
    let info = "";
    if (tr && tr.protocol === "TCP") {
        const flagText = formatFlags(tr.flags);
        info = `${tr.srcPort} → ${tr.dstPort} [${flagText}] Seq=${tr.seq} Len=${tr.payloadLength}`;
    } else if (tr && tr.protocol === "UDP") {
        info = `${tr.srcPort} → ${tr.dstPort} Len=${tr.payloadLength}`;
    } else if (tr && tr.protocol === "ICMP") {
        info = `type=${tr.type} code=${tr.code}`;
    } else if (net) {
        info = net.src && net.dst ? `${net.src} → ${net.dst}` : "";
    }

    return {
        index: pkt.index,
        time: pkt.timestamp,
        src,
        dst,
        protocol,
        // 帧长与应用层载荷长分别列出。列表里的 Length 列按 Wireshark 惯例
        // 显示整帧字节数，载荷长度放进信息列，两者不混为一谈。
        length: capturePacket ? capturePacket.data.length : pkt.payload.length,
        payloadLength: pkt.payload.length,
        info,
        truncated: pkt.truncated,
    };
}

/**
 * Parse PCAP operation
 */
class ParsePcap extends Operation {

    /**
     * 构造函数 —— 声明元信息与参数。
     *
     * inputType 用 ArrayBuffer，让界面支持直接拖入 .pcap 文件。
     */
    constructor() {
        super();

        this.name = "Parse PCAP";
        this.module = "Default";
        this.description = "Parses a libpcap (.pcap) or pcapng (.pcapng) capture file and displays " +
            "each packet's protocol layers, along with reassembled TCP streams and a breakdown " +
            "of the application protocols in use. Automatically detects byte order and timestamp precision.";
        this.infoURL = "https://wikipedia.org/wiki/Pcap";
        this.inputType = "ArrayBuffer";
        this.outputType = "json";
        this.presentType = "html";
        this.args = [
            {
                name: "Max packets",
                type: "number",
                value: 10000,
                min: 0,
                hint: "Stop after this many packets. 0 means no limit.",
            },
            {
                name: "Display",
                type: "option",
                value: ["Packet list", "Packet details", "Conversations", "Capture info"],
            },
        ];
    }

    /**
     * 【主流程】解析抓包文件
     *
     * @param {ArrayBuffer} input - 抓包文件原始字节
     * @param {Object[]} args - [maxPackets, display]
     * @returns {Object} 供 present() 渲染的扁平结构
     */
    run(input, args) {
        const maxPackets = args[0];
        const display = args[1];

        // --- 步骤 1：输入校验 ---
        if (!input || input.byteLength === 0) {
            throw new OperationError(
                "No input data. Drop a .pcap or .pcapng capture file into the input, " +
                "or paste its bytes using a 'From Hex' operation first."
            );
        }

        const bytes = new Uint8Array(input);

        // --- 步骤 2：容器层解析。失败时保留原始信息，便于用户判断是格式问题还是文件损坏 ---
        let capture;
        try {
            capture = parsePcap(bytes, {maxPackets: maxPackets > 0 ? maxPackets : undefined});
        } catch (err) {
            throw new OperationError(`Not a valid capture file: ${err.message}`);
        }

        // --- 步骤 3、4：逐包解包 + 流重组 + 会话归并 ---
        const analysis = analysePcap(capture, {dissectCapture});

        // --- 步骤 5：整理输出 ---
        const packets = analysis.packets.map((pkt) => describePacket(pkt, capture.packets[pkt.index]));

        return {
            display,
            format: capture.format,
            byteOrder: capture.byteOrder === "be" ? "Big endian" : "Little endian",
            version: capture.version,
            linkType: capture.linkType,
            linkTypeName: capture.interfaces.length ? capture.interfaces[0].linkTypeName : "",
            interfaces: capture.interfaces.map((i) => ({
                id: i.id,
                linkType: i.linkType,
                linkTypeName: i.linkTypeName,
                snaplen: i.snaplen,
                tsResolution: i.tsResolution,
            })),
            warnings: capture.warnings,
            truncatedAt: capture.truncatedAt,
            packets,
            renderedCount: Math.min(packets.length, MAX_RENDERED_PACKETS),
            conversations: analysis.conversations.map((c) => c.summary),
            stats: analysis.stats,
            streamStats: analysis.streamStats,
        };
    }

    /**
     * 【呈现】把 run() 的结果渲染成 HTML。
     *
     * 按 args[1] 选择视图。所有来自抓包文件的字符串一律转义后再拼接。
     *
     * @param {Object} data - run() 的返回值
     * @param {Object[]} args - [maxPackets, display]
     * @returns {string} HTML
     */
    present(data, args) {
        const esc = Utils.escapeHtml;
        const display = data.display;

        if (display === "Capture info") return this._presentCaptureInfo(data, esc);
        if (display === "Conversations") return this._presentConversations(data, esc);
        if (display === "Packet details") return this._presentPacketDetails(data, esc);
        return this._presentPacketList(data, esc);
    }

    /**
     * 视图：抓包整体信息。
     *
     * @param {Object} data - run() 结果
     * @param {Function} esc - HTML 转义函数
     * @returns {string} HTML
     */
    _presentCaptureInfo(data, esc) {
        const s = data.stats;

        let html = "<table class='table table-hover table-sm table-bordered table-nonfluid'>" +
            "<tr><th>Property</th><th>Value</th></tr>";

        const row = (k, v) => {
            html += `<tr><td>${esc(k)}</td><td>${esc(String(v))}</td></tr>`;
        };

        row("File format", data.format.toUpperCase());
        row("Byte order", data.byteOrder);
        row("Version", data.version);
        row("Global link type", `${data.linkType} (${data.linkTypeName})`);
        row("Packet count", s.packetCount);
        row("— TCP", s.tcpPacketCount);
        row("— UDP", s.udpPacketCount);
        row("— Other", s.otherPacketCount);
        row("TCP streams", s.streamCount);
        row("Conversations", s.conversationCount);
        row("Captured payload bytes", s.payloadBytes);
        row("Truncated packets", s.truncatedPackets);
        row("Duration", `${s.duration.toFixed(6)} s`);
        row("First packet", new Date(s.startTime * 1000).toISOString());
        row("Last packet", new Date(s.endTime * 1000).toISOString());

        html += "</table>";

        if (data.interfaces.length) {
            html += "<table class='table table-hover table-sm table-bordered table-nonfluid'>" +
                "<tr><th>#</th><th>Link type</th><th>Snap length</th><th>Ticks per second</th></tr>";
            for (const i of data.interfaces) {
                html += `<tr><td>${esc(String(i.id))}</td><td>${esc(i.linkTypeName)} (${i.linkType})</td>` +
                    `<td>${esc(String(i.snapLength))}</td><td>${esc(String(i.tsResolution))}</td></tr>`;
            }
            html += "</table>";
        }

        if (data.streamStats) {
            const ss = data.streamStats;
            html += "<table class='table table-hover table-sm table-bordered table-nonfluid'>" +
                "<tr><th>Stream tracking</th><th>Value</th></tr>";
            html += `<tr><td>Packets examined</td><td>${ss.totalPackets}</td></tr>`;
            html += `<tr><td>TCP packets</td><td>${ss.tcpPacketCount}</td></tr>`;
            html += `<tr><td>Non-TCP ignored</td><td>${ss.ignoredPacketCount}</td></tr>`;
            html += `<tr><td>Retransmissions</td><td>${ss.retransmissionCount}</td></tr>`;
            html += `<tr><td>Out-of-order segments</td><td>${ss.outOfOrderCount}</td></tr>`;
            html += `<tr><td>Total payload bytes</td><td>${ss.totalPayloadBytes}</td></tr>`;
            html += "</table>";
        }

        if (data.warnings.length) {
            html += "<table class='table table-hover table-sm table-bordered table-nonfluid'>" +
                "<tr><th>Warnings</th></tr>";
            for (const w of data.warnings) html += `<tr><td>${esc(w)}</td></tr>`;
            html += "</table>";
        }

        return html;
    }

    /**
     * 视图：会话列表。展示归并后的会话及其应用层协议识别结果。
     *
     * @param {Object} data - run() 结果
     * @param {Function} esc - HTML 转义函数
     * @returns {string} HTML
     */
    _presentConversations(data, esc) {
        let html = "<table class='table table-hover table-sm table-bordered table-nonfluid'>" +
            "<tr><th>#</th><th>Transport</th><th>Client</th><th>Server</th>" +
            "<th>Application</th><th>Confidence</th><th>Packets</th><th>Bytes</th><th>State</th></tr>";

        data.conversations.forEach((c, i) => {
            html += `<tr><td>${i + 1}</td>` +
                `<td>${esc(c.transportProtocol)}</td>` +
                `<td>${esc(`${c.client.ip}:${c.client.port}`)}</td>` +
                `<td>${esc(`${c.server.ip}:${c.server.port}`)}</td>` +
                `<td><b>${esc(c.appProtocol)}</b></td>` +
                `<td>${esc(c.confidence)}</td>` +
                `<td>${c.packetCount}</td>` +
                `<td>${c.payloadBytes}</td>` +
                `<td>${esc(c.state)}</td></tr>`;
        });

        html += "</table>";

        // 识别依据单独列出：可信度只有配上依据才有意义
        html += "<table class='table table-hover table-sm table-bordered table-nonfluid'>" +
            "<tr><th>#</th><th>Identification evidence</th></tr>";
        data.conversations.forEach((c, i) => {
            html += `<tr><td>${i + 1}</td><td>${esc(c.evidence || "—")}</td></tr>`;
        });
        html += "</table>";

        return html;
    }

    /**
     * 视图：逐包详情。展开每个包的各层字段。
     *
     * @param {Object} data - run() 结果
     * @param {Function} esc - HTML 转义函数
     * @returns {string} HTML
     */
    _presentPacketDetails(data, esc) {
        let html = "";
        for (const p of data.packets.slice(0, data.renderedCount)) {
            html += `<table class='table table-hover table-sm table-bordered table-nonfluid'>` +
                `<tr><th colspan='2'>Packet ${p.index} — ${esc(p.protocol)} — ` +
                `${esc(p.src)} → ${esc(p.dst)} — ${esc(new Date(p.time * 1000).toISOString())}</th></tr>`;
            html += `<tr><td>Payload bytes</td><td>${p.length}</td></tr>`;
            html += `<tr><td>Truncated</td><td>${p.truncated ? "yes" : "no"}</td></tr>`;
            html += `<tr><td>Summary</td><td>${esc(p.info)}</td></tr>`;
            html += "</table>";
        }

        if (data.packets.length > data.renderedCount) {
            html += `<p>${data.packets.length - data.renderedCount} further packets were parsed but not rendered.</p>`;
        }
        return html;
    }

    /**
     * 视图：包列表。仿 Wireshark 的摘要表。
     *
     * @param {Object} data - run() 结果
     * @param {Function} esc - HTML 转义函数
     * @returns {string} HTML
     */
    _presentPacketList(data, esc) {
        let html = "<table class='table table-hover table-sm table-bordered table-nonfluid'>" +
            "<tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th>" +
            "<th>Protocol</th><th>Length</th><th>Info</th></tr>";

        for (const p of data.packets.slice(0, data.renderedCount)) {
            html += `<tr><td>${p.index}</td>` +
                `<td>${esc(p.time.toFixed(6))}</td>` +
                `<td>${esc(p.src)}</td>` +
                `<td>${esc(p.dst)}</td>` +
                `<td>${esc(p.protocol)}</td>` +
                `<td>${p.length}</td>` +
                `<td>${esc(p.info)}</td></tr>`;
        }

        html += "</table>";

        if (data.packets.length > data.renderedCount) {
            html += `<p><b>${data.packets.length - data.renderedCount}</b> further packets were parsed ` +
                `but not rendered (display limit is ${MAX_RENDERED_PACKETS}).</p>`;
        }

        if (data.truncatedAt !== null && data.truncatedAt !== undefined) {
            html += `<p>The capture was truncated by the <b>Max packets</b> setting at packet ${data.truncatedAt}.</p>`;
        }

        return html;
    }
}

export default ParsePcap;
