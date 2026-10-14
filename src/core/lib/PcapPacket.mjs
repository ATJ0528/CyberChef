/**
 * @author CyberChef Contributor
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

import Stream from "./Stream.mjs";
import {ipv4ToStr, ipv6ToStr} from "./IP.mjs";
import {bytesToLargeNumber} from "./Protocol.mjs";
import {LINKTYPE, getLinkTypeName} from "./Pcap.mjs";

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 抓包帧的分层协议解析
 * 【文件】src/core/lib/PcapPacket.mjs
 * 【职责】把一段**原始帧字节**按链路层 → 网络层 → 传输层逐层解析成分层结构
 *         （DissectedPacket）并给出应用层载荷。只做解析，不做流重组、不做
 *         校验和验证、不做分片重组。与 Pcap.mjs 分工：Pcap.mjs 负责"容器"
 *         （把文件切成带时间戳的帧），本库负责"内容"（把帧解释成协议字段）。
 * 【被谁使用】operations/ParsePcap、PcapSummary、ExtractPcapStreams、FilterPcap
 *         等逐包读取协议字段的上层操作（输出契约固定，见 DissectedPacket）。
 * ------------------------------------------------------------
 * 【导出接口】
 *   - ETHERTYPE / IP_PROTOCOL / TCP_OPTION_KIND : 常量表
 *   - etherTypeName(n) / ipProtocolName(n)      : 编号 → 名称（含 Unknown 回退）
 *   - parseEthernet/parseIpv4/parseIpv6/parseTcp/parseUdp/parseIcmp/
 *     parseLinuxSll/parseNullLoopback(parseLoopback) : 各层解析函数
 *   - class DissectedPacket                     : 单个已解析包（固定字段契约）
 *   - dissectBytes(bytes, linkType, index, timestamp) → DissectedPacket
 *   - dissectCapture(capture) → DissectedPacket[]
 * ------------------------------------------------------------
 * 【关键算法】
 *   1. 顺序读取：各层内部用 Stream（游标流）按字段顺序 readInt/getBytes，
 *      把"手工累加偏移"变成"顺序消费"；层与层靠上一层返回的 headerLength /
 *      payloadOffset 切片，层层递进。
 *   2. 32 位无符号数：TCP 序列号/确认号是 32 位无符号，而 JS 位运算按 32 位
 *      有符号处理，≥2^31 会溢出。故统一走 Protocol.mjs 的 bytesToLargeNumber
 *      （内部 BigNumber）再 Number() 收敛。
 *   3. VLAN/QinQ 标签栈：以太网类型为 0x8100/0x88A8 时，其后每 4 字节为一个
 *      标签（TCI(2)+类型(2)），**循环**剥栈可支持多级；TCI 拆 priority(3)/
 *      DEI(1)/VID(12)，末次类型才是真正的 L3 类型。
 *   4. 位域拆分：TCP 的 Data offset(4)/Reserved(3)/NS(1) 与 8 个标志位共处相邻
 *      两字节，用 readBits 按位连续读取自动跨字节，无需手工移位。
 *   5. 容错优先：数据不足**绝不抛异常**，能填的填、其余 null，并置 truncated
 *      =true；不认识的链路类型令 link.type="unknown" 且原样保留 payload。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 地址格式化复用 IP.mjs（ipv4ToStr / ipv6ToStr），不重复实现。
 *   - 偏移量语义统一为"相对本层缓冲区起点"（network 相对 IP 首部、transport
 *     相对传输层首部），二者所在缓冲区不同，切勿直接相加。
 *   - 标志位在输出契约里必须是 **0/1 数字**而非布尔，便于下游做位运算。
 *   - Stream.readInt/getBytes 越界是"软失败"（读到 undefined 会被当 0），
 *     读取前务必用 remaining() 自行判长，不能依赖 Stream 报错。
 * ============================================================
 */

/**
 * 以太网类型编号（EtherType），位于帧第 13-14 字节（或 VLAN 标签之后）。
 * 本库只对 IPv4/IPv6 继续做网络层解析，其余（如 ARP）如实记类型后令 network 为 null。
 */
export const ETHERTYPE = {
    IPv4: 0x0800,
    ARP: 0x0806,
    RARP: 0x8035,
    VLAN: 0x8100,           // 802.1Q 单层标签
    QinQ: 0x88A8,           // 802.1ad 标签栈外层
    IPv6: 0x86DD,
    MPLS: 0x8847,
    MPLS_MULTICAST: 0x8848,
    PPPOE_DISCOVERY: 0x8863,
    PPPOE_SESSION: 0x8864,
    LLDP: 0x88CC,
    IPX: 0x8137,
};

/** 以太网类型号 → 可读名称；未收录回退 "Unknown (0xNNNN)"。 */
const ETHERTYPE_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8035: "RARP",
    0x8100: "VLAN",
    0x88A8: "QinQ",
    0x86DD: "IPv6",
    0x8847: "MPLS",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery",
    0x8864: "PPPoE Session",
    0x88CC: "LLDP",
    0x8137: "IPX",
};

/**
 * IP 协议号（IPv4 首部的 Protocol 字段 / IPv6 首部的 Next Header 字段）。
 * 本库对 TCP/UDP/ICMP/ICMPv6 做进一步解析，其余仅记名。
 */
export const IP_PROTOCOL = {
    HOPOPT: 0,      // IPv6 逐跳选项
    ICMP: 1,
    IGMP: 2,
    IPv4: 4,
    TCP: 6,
    UDP: 17,
    IPv6: 41,
    ROUTING: 43,    // IPv6 路由首部
    FRAGMENT: 44,   // IPv6 分片首部
    GRE: 47,
    ESP: 50,
    AH: 51,
    ICMPV6: 58,
    NO_NEXT: 59,
    IPV6_OPTS: 60,  // IPv6 目的地选项
    EIGRP: 88,
    OSPFIGP: 89,
    PIM: 103,
    VRRP: 112,
    L2TP: 115,
    SCTP: 132,
    UDPLITE: 136,
};

/**
 * IP 协议号 → 可读名称；未收录回退 "Unknown (N)"。
 * 58 用 "ICMPv6"（而非 IANA 的 IPv6-ICMP），因其直接作为 transport.protocol 输出。
 */
const IP_PROTOCOL_NAMES = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 17: "UDP", 41: "IPv6",
    43: "IPv6-Route", 44: "IPv6-Frag", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
    59: "IPv6-NoNxt", 60: "IPv6-Opts", 88: "EIGRP", 89: "OSPF", 103: "PIM",
    112: "VRRP", 115: "L2TP", 132: "SCTP", 136: "UDPLite",
};

/**
 * TCP 选项 kind → 可读名称（IANA TCP Parameters）。
 * 0（End of Options）与 1（Nop）无长度字节、长度为 1；其余选项第 2 字节为合计长度。
 */
export const TCP_OPTION_KIND = {
    0: "End of Options",
    1: "Nop",
    2: "MSS",
    3: "Window Scale",
    4: "SACK Permitted",
    5: "SACK",
    6: "Echo",
    7: "Echo Reply",
    8: "Timestamps",
    9: "Partial Order Connection Permitted",
    10: "Partial Order Service Profile",
    11: "CC",
    12: "CC.NEW",
    13: "CC.ECHO",
    14: "TCP Alternate Checksum Request",
    15: "TCP Alternate Checksum Data",
    19: "MD5 Signature",
    28: "User Timeout",
    29: "TCP Authentication Option",
    30: "Multipath TCP",
    34: "Fast Open",
};

/**
 * 【函数】以太网类型号 → 可读名称
 * 参数：n 类型号（16 位，可为 null）。返回：名称字符串；未收录为 "Unknown (0xNNNN)"。
 */
export function etherTypeName(n) {
    if (n === null || n === undefined) return null;
    return ETHERTYPE_NAMES[n] || `Unknown (0x${(n & 0xFFFF).toString(16).toUpperCase().padStart(4, "0")})`;
}

/**
 * 【函数】IP 协议号 → 可读名称
 * 参数：n 协议号（8 位，可为 null）。返回：名称字符串；未收录为 "Unknown (N)"。
 */
export function ipProtocolName(n) {
    if (n === null || n === undefined) return null;
    return IP_PROTOCOL_NAMES[n] || `Unknown (${n})`;
}

/**
 * 【辅助】本层缓冲区剩余可读字节数（Stream 软失败的判长前置）。
 * 参数：s 游标流。返回：剩余字节数（≥0）。
 */
function remaining(s) {
    return Math.max(0, s.length - s.position);
}

/**
 * 【辅助】任意长度链路地址 → "aa:bb:cc:…" 小写冒号分隔串。
 * 参数：bytes 地址字节。返回：字符串。
 */
function formatMac(bytes) {
    const parts = [];
    for (let i = 0; i < bytes.length; i++) parts.push(bytes[i].toString(16).padStart(2, "0"));
    return parts.join(":");
}

/**
 * 【辅助】16 字节 IPv6 地址 → 字符串（复用 ipv6ToStr 做 :: 压缩）。
 * 参数：bytes 16 字节。返回：压缩形式的地址串。
 */
function formatIpv6(bytes) {
    const segs = new Array(8);
    for (let i = 0; i < 8; i++) segs[i] = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
    return ipv6ToStr(segs, true);
}

/**
 * 【辅助】4 字节大端无符号数（0..4294967295）。
 * 用 BigNumber 承担 32 位无符号语义（同 ParseTCP 的做法），再收敛为 Number；
 * 32 位最大值远在 Number 安全整数内，无精度损失。
 * 参数：bytes 4 字节。返回：number。
 */
function readUint32(bytes) {
    return Number(bytesToLargeNumber(bytes));
}

/**
 * 【函数】解析以太网（Ethernet II）帧首部
 * 参数：bytes 从以太网首部起的帧字节。返回：{headerLength, dst, src, etherType,
 *      vlan[], truncated}。
 * 算法：目的 MAC(6)+源 MAC(6)+类型(2)=14 字节；若类型为 VLAN/QinQ 则循环每 4 字节
 *      剥一个标签（TCI 拆 priority(3)/DEI(1)/VID(12)），支持标签栈。
 */
export function parseEthernet(bytes) {
    const result = {headerLength: 0, dst: null, src: null, etherType: null, vlan: [], truncated: false};

    // --- 步骤 1：不足 14 字节的短帧尽量读出已有部分 ---
    if (bytes.length < 14) {
        if (bytes.length >= 6) result.dst = formatMac(bytes.slice(0, 6));
        if (bytes.length >= 12) result.src = formatMac(bytes.slice(6, 12));
        result.headerLength = bytes.length;
        result.truncated = true;
        return result;
    }

    // --- 步骤 2：读固定 14 字节首部 ---
    const s = new Stream(bytes);
    result.dst = formatMac(s.getBytes(6));
    result.src = formatMac(s.getBytes(6));
    result.etherType = s.readInt(2);

    // --- 步骤 3：循环剥掉 VLAN / QinQ 标签 ---
    while (result.etherType === ETHERTYPE.VLAN || result.etherType === ETHERTYPE.QinQ) {
        if (remaining(s) < 4) {
            result.truncated = true;
            break;
        }
        const tci = s.readInt(2);
        result.etherType = s.readInt(2);
        result.vlan.push({priority: (tci >> 13) & 0x7, dei: (tci >> 12) & 0x1, id: tci & 0x0FFF});
    }

    result.headerLength = s.position;
    return result;
}

/**
 * 【函数】解析 IPv4 首部（RFC 791）
 * 参数：bytes 从 IPv4 首部起的字节。返回：含 version/ihl/dscp/ecn/totalLength/
 *      identification/flags/fragmentOffset/ttl/protocol/checksum/src/dst/
 *      headerLength/payloadOffset/payloadLength/truncated。
 * 算法：版本/IHL(1)+DSCP/ECN(1)+总长(2)+标识(2)+标志/分片偏移(2)+TTL(1)+协议(1)+
 *      校验和(2)+源/目的地址(4+4)+选项；首部长度由 IHL（32 位字数）定位载荷。
 */
export function parseIpv4(bytes) {
    const r = {
        version: 4, ihl: null, headerLength: 0, dscp: null, ecn: null, totalLength: null,
        identification: null, flags: null, fragmentOffset: null, ttl: null, protocol: null,
        checksum: null, src: null, dst: null, payloadOffset: 0, payloadLength: 0, truncated: false,
    };

    // --- 步骤 1：不足最小 20 字节首部，尽力读出 IHL 后返回 ---
    if (bytes.length < 20) {
        if (bytes.length >= 1) {
            r.ihl = bytes[0] & 0x0F;
            r.headerLength = r.ihl * 4;
        }
        r.truncated = true;
        return r;
    }

    // --- 步骤 2：顺序读取固定首部 ---
    const s = new Stream(bytes);
    r.ihl = s.readInt(1) & 0x0F;
    r.headerLength = r.ihl * 4;
    if (r.headerLength < 20) {   // IHL<5 属畸形，钳到最小首部
        r.headerLength = 20;
        r.truncated = true;
    }
    const b1 = s.readInt(1);
    r.dscp = b1 >> 2;            // 高 6 位
    r.ecn = b1 & 0x03;           // 低 2 位
    r.totalLength = s.readInt(2);
    r.identification = s.readInt(2);
    const frag = s.readInt(2);   // Reserved(1)|DF(1)|MF(1)|分片偏移(13)
    r.flags = {reserved: (frag >> 15) & 1, dontFragment: (frag >> 14) & 1, moreFragments: (frag >> 13) & 1};
    r.fragmentOffset = frag & 0x1FFF;
    r.ttl = s.readInt(1);
    r.protocol = s.readInt(1);
    r.checksum = s.readInt(2);
    r.src = ipv4ToStr(s.readInt(4));   // 有符号读入，ipv4ToStr 同样正确
    r.dst = ipv4ToStr(s.readInt(4));

    // --- 步骤 3：按 IHL 与总长计算载荷范围并判截断 ---
    r.payloadOffset = r.headerLength;
    const avail = bytes.length;
    let end = r.totalLength > 0 ? Math.min(r.totalLength, avail) : avail;
    if (end < r.headerLength) {
        end = r.headerLength;
        r.truncated = true;
    }
    r.payloadLength = Math.max(0, end - r.headerLength);
    if (avail < r.headerLength || (r.totalLength > 0 && avail < r.totalLength)) r.truncated = true;
    return r;
}

/**
 * 【函数】解析 IPv6 首部（RFC 8200）
 * 参数：bytes 从 IPv6 首部起的字节。返回：含 version/trafficClass/flowLabel/
 *      payloadLength/nextHeader/hopLimit/src/dst/headerLength/payloadOffset/
 *      totalLength/protocol/fragmentOffset/truncated。
 * 算法：40 字节固定首部（版本/流量类别/流标签(4)+载荷长度(2)+下一首部(1)+跳数限制(1)
 *      +源/目的地址(16+16)）；若下一首部指向扩展首部则顺序跳过，定位真正的传输层。
 */
export function parseIpv6(bytes) {
    const r = {
        version: 6, trafficClass: null, flowLabel: null, payloadLength: 0, nextHeader: null,
        hopLimit: null, src: null, dst: null, headerLength: 40, payloadOffset: 40,
        totalLength: null, protocol: null, fragmentOffset: null, truncated: false,
    };

    // --- 步骤 1：不足 40 字节固定首部，尽力读地址后返回 ---
    if (bytes.length < 40) {
        if (bytes.length >= 8) {
            r.payloadLength = (bytes[4] << 8) | bytes[5];
            r.nextHeader = bytes[6];
            r.hopLimit = bytes[7];
            r.protocol = bytes[6];
        }
        if (bytes.length >= 24) r.src = formatIpv6(bytes.slice(8, 24));
        if (bytes.length >= 40) r.dst = formatIpv6(bytes.slice(24, 40));
        r.truncated = true;
        return r;
    }

    // --- 步骤 2：顺序读固定首部 ---
    const s = new Stream(bytes);
    const b0 = s.readInt(1), b1 = s.readInt(1), b2 = s.readInt(1), b3 = s.readInt(1);
    r.version = b0 >> 4;
    r.trafficClass = ((b0 & 0x0F) << 4) | (b1 >> 4);
    r.flowLabel = ((b1 & 0x0F) << 16) | (b2 << 8) | b3;
    r.payloadLength = s.readInt(2);
    r.nextHeader = s.readInt(1);
    r.hopLimit = s.readInt(1);
    r.src = formatIpv6(s.getBytes(16));
    r.dst = formatIpv6(s.getBytes(16));
    r.totalLength = 40 + r.payloadLength;

    // --- 步骤 3：跳过扩展首部，定位传输层协议与载荷偏移 ---
    let nh = r.nextHeader, off = 40, guard = 0;
    while (guard++ < 8 && (nh === IP_PROTOCOL.HOPOPT || nh === IP_PROTOCOL.ROUTING ||
            nh === IP_PROTOCOL.FRAGMENT || nh === IP_PROTOCOL.IPV6_OPTS)) {
        if (off + 8 > bytes.length) {
            r.truncated = true;
            break;
        }
        if (nh === IP_PROTOCOL.FRAGMENT) {  // 分片首部固定 8 字节
            r.fragmentOffset = (((bytes[off + 2] << 8) | bytes[off + 3]) >>> 3) & 0x1FFF;
            nh = bytes[off];
            off += 8;
        } else {                            // 其余：(HdrExtLen+1)*8 字节
            const hlen = (bytes[off + 1] + 1) * 8;
            nh = bytes[off];
            if (hlen <= 0) {
                r.truncated = true;
                break;
            }
            off += hlen;
        }
    }
    r.protocol = nh;
    r.headerLength = off;
    r.payloadOffset = off;

    // --- 步骤 4：载荷长度 = 声明值扣扩展首部，并被实际可用字节夹紧 ---
    const declared = r.payloadLength > 0 ? r.payloadLength : 0;
    let avail = Math.max(0, bytes.length - 40);
    if (declared > 0) avail = Math.min(avail, declared);
    r.payloadLength = Math.max(0, avail - (off - 40));
    if (off > bytes.length) {
        r.payloadLength = 0;
        r.truncated = true;
    }
    return r;
}

/**
 * 【函数】解析 TCP 首部（RFC 793），含可变长选项区
 * 参数：bytes 从 TCP 首部起的字节（通常为 IP 载荷）。返回：含 protocol/srcPort/
 *      dstPort/seq/ack/dataOffset/flags/window/checksum/urgentPointer/options[]/
 *      segmentLength/payloadOffset/payloadLength/truncated。
 * 算法：源/目的端口(2+2)+序列号(4)+确认号(4)+数据偏移/保留/NS(2)+8 标志位(1)+
 *      窗口(2)+校验和(2)+紧急指针(2)+选项；序列号/确认号走 BigNumber。
 */
export function parseTcp(bytes) {
    const r = {
        protocol: "TCP", srcPort: null, dstPort: null, seq: null, ack: null, dataOffset: null,
        flags: null, window: null, checksum: null, urgentPointer: null, options: [],
        segmentLength: null, headerLength: 0, payloadOffset: 0, payloadLength: 0, truncated: false,
    };

    // --- 步骤 1：不足 20 字节固定首部则判截断 ---
    if (bytes.length < 20) {
        r.headerLength = Math.min(20, bytes.length);
        r.payloadOffset = r.headerLength;
        r.truncated = true;
        return r;
    }

    // --- 步骤 2：顺序读固定首部 ---
    const s = new Stream(bytes);
    r.srcPort = s.readInt(2);
    r.dstPort = s.readInt(2);
    r.seq = readUint32(s.getBytes(4));    // 32 位无符号，走 BigNumber
    r.ack = readUint32(s.getBytes(4));
    r.dataOffset = s.readBits(4);
    r.headerLength = Math.max(20, r.dataOffset * 4);

    // --- 步骤 3：按位读取保留位与 9 个标志位（相邻两字节内按位序拆）---
    const reserved = s.readBits(3);
    const ns = s.readBits(1), cwr = s.readBits(1), ece = s.readBits(1), urg = s.readBits(1);
    const ackFlag = s.readBits(1), psh = s.readBits(1), rst = s.readBits(1);
    const syn = s.readBits(1), fin = s.readBits(1);
    r.flags = {fin, syn, rst, psh, ack: ackFlag, urg, ece, cwr, ns, reserved};

    r.window = s.readInt(2);
    r.checksum = s.readInt(2);
    r.urgentPointer = s.readInt(2);

    // --- 步骤 4：解析选项区（[20, headerLength) 区间）---
    const optEnd = Math.min(r.headerLength, bytes.length);
    if (r.headerLength > bytes.length) r.truncated = true;
    let p = 20;
    while (p < optEnd) {
        const kind = bytes[p];
        const entry = {
            kind,
            kindName: Object.prototype.hasOwnProperty.call(TCP_OPTION_KIND, kind) ? TCP_OPTION_KIND[kind] : "Unknown",
            length: 1,
            data: new Uint8Array(0),
        };
        // kind 0/1 长度为 1 且无长度字节
        if (kind === 0) {
            r.options.push(entry);
            break;
        }
        if (kind === 1) {
            r.options.push(entry);
            p += 1;
            continue;
        }
        // 其余选项第 2 字节为总长度；越界或非法则记损坏并停止
        if (p + 1 >= optEnd) {
            r.options.push(entry);
            r.truncated = true;
            break;
        }
        const len = bytes[p + 1];
        entry.length = len;
        if (len < 2) {
            r.options.push(entry);
            r.truncated = true;
            break;
        }
        const dataLen = len - 2;
        if (p + 2 + dataLen > optEnd) {
            entry.data = bytes.slice(p + 2, optEnd);
            r.options.push(entry);
            r.truncated = true;
            break;
        }
        entry.data = bytes.slice(p + 2, p + 2 + dataLen);
        r.options.push(entry);
        p += len;
    }

    // --- 步骤 5：计算载荷范围 ---
    r.segmentLength = bytes.length;   // 传入的 IP 载荷即整个 TCP 段
    r.payloadOffset = r.headerLength;
    r.payloadLength = Math.max(0, bytes.length - r.headerLength);
    if (bytes.length < r.headerLength) {
        r.payloadLength = 0;
        r.truncated = true;
    }
    return r;
}

/**
 * 【函数】解析 UDP 首部（RFC 768）
 * 参数：bytes 从 UDP 首部起的字节。返回：{protocol, srcPort, dstPort, length,
 *      checksum, segmentLength, headerLength, payloadOffset, payloadLength, truncated}。
 * 算法：源/目的端口(2+2)+长度(2)+校验和(2)=8 字节，其后全是数据；length 字段被
 *      实际可用字节夹紧以判截断。
 */
export function parseUdp(bytes) {
    const r = {
        protocol: "UDP", srcPort: null, dstPort: null, length: null, checksum: null,
        segmentLength: null, headerLength: 8, payloadOffset: 8, payloadLength: 0, truncated: false,
    };

    // --- 步骤 1：不足 8 字节固定首部则判截断 ---
    if (bytes.length < 8) {
        r.headerLength = bytes.length;
        r.payloadOffset = bytes.length;
        r.truncated = true;
        return r;
    }

    // --- 步骤 2：顺序读 8 字节首部 ---
    const s = new Stream(bytes);
    r.srcPort = s.readInt(2);
    r.dstPort = s.readInt(2);
    r.length = s.readInt(2);       // 声明总长（含 8 字节首部）
    r.checksum = s.readInt(2);

    // --- 步骤 3：载荷范围，length 被实际可用字节夹紧 ---
    r.segmentLength = r.length > 0 ? r.length : bytes.length;
    let end = bytes.length;
    if (r.length > 0 && r.length < end) end = r.length;
    r.payloadOffset = 8;
    r.payloadLength = Math.max(0, end - 8);
    if (r.length > bytes.length) r.truncated = true;
    return r;
}

/**
 * 【函数】解析 ICMP / ICMPv6 首部（简单版）
 * 参数：bytes 从 ICMP 首部起的字节；isV6 是否为 ICMPv6（决定 protocol 名称）。
 * 返回：{protocol, type, code, checksum, srcPort, dstPort, flags, headerLength,
 *      payloadOffset, payloadLength, truncated}。
 * 算法：类型(1)+代码(1)+校验和(2)+首部其余部分(4)=8 字节，不按类型分支深度解析。
 */
export function parseIcmp(bytes, isV6 = false) {
    const r = {
        protocol: isV6 ? "ICMPv6" : "ICMP", type: null, code: null, checksum: null,
        srcPort: null, dstPort: null, flags: null, headerLength: 8, payloadOffset: 8,
        payloadLength: 0, truncated: false,
    };

    // --- 步骤 1：至少要有类型/代码/校验和 4 字节 ---
    if (bytes.length < 4) {
        r.headerLength = bytes.length;
        r.payloadOffset = bytes.length;
        r.truncated = true;
        return r;
    }

    // --- 步骤 2：读类型/代码/校验和，首部按 8 字节（含 4 字节其余部分）---
    r.type = bytes[0];
    r.code = bytes[1];
    r.checksum = (bytes[2] << 8) | bytes[3];
    r.headerLength = bytes.length >= 8 ? 8 : bytes.length;
    r.payloadOffset = r.headerLength;
    r.payloadLength = Math.max(0, bytes.length - r.headerLength);
    if (bytes.length < 8) r.truncated = true;
    return r;
}

/**
 * 【函数】解析 Linux SLL（"cooked"）16 字节伪首部
 * 参数：bytes 从伪首部起的字节。返回：{headerLength, packetType, arpHrdType,
 *      linkAddrLen, linkAddr, src, protocolType, truncated}。
 * 算法：包类型(2)+ARPHRD 类型(2)+链路地址长度(2)+链路地址(8)+协议类型(2)，
 *      其后即为 L3 报文；链路地址仅前 linkAddrLen 字节有效。
 */
export function parseLinuxSll(bytes) {
    const r = {
        headerLength: 16, packetType: null, arpHrdType: null, linkAddrLen: null,
        linkAddr: null, src: null, protocolType: null, truncated: false,
    };

    // --- 步骤 1：不足 16 字节则尽力填已有字段 ---
    if (bytes.length < 16) {
        if (bytes.length >= 2) r.packetType = (bytes[0] << 8) | bytes[1];
        if (bytes.length >= 4) r.arpHrdType = (bytes[2] << 8) | bytes[3];
        if (bytes.length >= 6) r.linkAddrLen = (bytes[4] << 8) | bytes[5];
        r.headerLength = bytes.length;
        r.truncated = true;
        return r;
    }

    // --- 步骤 2：顺序读伪首部各字段 ---
    const s = new Stream(bytes);
    r.packetType = s.readInt(2);
    r.arpHrdType = s.readInt(2);
    r.linkAddrLen = s.readInt(2);
    const addr = s.getBytes(8);
    r.linkAddr = addr;
    const used = Math.min(8, r.linkAddrLen);
    r.src = used > 0 ? formatMac(addr.slice(0, used)) : null;
    r.protocolType = s.readInt(2);
    return r;
}

/**
 * 【函数】解析 BSD/NULL 回环伪首部（4 字节地址族 + 其后直接是 IP 报文）
 * 参数：bytes 从伪首部起的字节。返回：{headerLength, addressFamily, ipVersion,
 *      etherType, truncated}。
 * 算法：地址族按主机字节序存放，这里按常见的小端读取：2=IPv4；10/23/24/28/30
 *      等为各系统上 IPv6 的不同编号，据此决定后续按 IPv4 还是 IPv6 继续。
 */
export function parseNullLoopback(bytes) {
    const r = {headerLength: 4, addressFamily: null, ipVersion: null, etherType: null, truncated: false};

    // --- 步骤 1：不足 4 字节无法读出地址族 ---
    if (bytes.length < 4) {
        r.headerLength = bytes.length;
        r.truncated = true;
        return r;
    }

    // --- 步骤 2：小端读地址族并映射到 IP 版本与以太网类型 ---
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const af = dv.getUint32(0, true);
    r.addressFamily = af;
    if (af === 2) {
        r.ipVersion = 4;
        r.etherType = ETHERTYPE.IPv4;
    } else if (af === 10 || af === 23 || af === 24 || af === 28 || af === 30) {
        r.ipVersion = 6;
        r.etherType = ETHERTYPE.IPv6;
    }
    return r;
}

/**
 * 【函数】parseNullLoopback 的同义别名（LOOP/OpenBSD 回环即此格式）
 * 参数：bytes。返回：同 parseNullLoopback。
 */
export function parseLoopback(bytes) {
    return parseNullLoopback(bytes);
}

/**
 * 【类】单个已解析的抓包（分层协议结构）
 * 构造即完成整包解析：链路层 → 网络层 → 传输层 → 应用层载荷。字段严格遵循固定
 * 契约：index/timestamp/linkType/linkTypeName/link/network/transport/payload/
 * truncated/headerBytesConsumed，并有 summary 一行摘要。
 */
export class DissectedPacket {

    /**
     * 【构造函数】创建并立即解析一个帧
     * 参数：bytes 原始帧字节；linkType 链路层类型编号；index 包序号；timestamp 秒。
     */
    constructor(bytes, linkType, index = 0, timestamp = NaN) {
        this.index = index;
        this.timestamp = timestamp;
        this.linkType = linkType;
        this.linkTypeName = getLinkTypeName(linkType);

        this.link = null;
        this.network = null;
        this.transport = null;
        this.payload = new Uint8Array(0);
        this.truncated = false;
        this.headerBytesConsumed = 0;

        this._dissect(bytes instanceof Uint8Array ? bytes : new Uint8Array(0));
    }

    /**
     * 【方法】执行整包分层解析
     * 算法：按链路类型解析链路层得"L3 缓冲区 + 以太网类型"；据类型解析 IPv4/IPv6
     *      得"L4 缓冲区 + 协议号"；据协议号解析传输层，并把其载荷切片存入 payload。
     *      任一层数据不足只置 truncated，不抛出。
     * 参数：bytes 原始帧字节。返回：无（写自身字段）。
     */
    _dissect(bytes) {
        let l3Bytes = null;
        let etherType = null;

        // --- 步骤 1：按链路类型解析链路层，定位 L3 起始 ---
        switch (this.linkType) {
            case LINKTYPE.ETHERNET: {
                const eth = parseEthernet(bytes);
                this.link = {
                    type: "ethernet", src: eth.src, dst: eth.dst, etherType: eth.etherType,
                    etherTypeName: etherTypeName(eth.etherType), vlan: eth.vlan,
                    headerLength: eth.headerLength,
                    summary: this._linkSummary(eth.src, eth.dst, eth.etherType, eth.vlan),
                };
                if (eth.truncated) this.truncated = true;
                l3Bytes = bytes.slice(eth.headerLength);
                etherType = eth.etherType;
                break;
            }
            case LINKTYPE.RAW:
            case LINKTYPE.IPV4:
            case LINKTYPE.IPV6: {
                // 裸 IP：无链路层首部，据首字节高 4 位判版本
                const v = bytes.length > 0 ? (bytes[0] >> 4) : null;
                if (this.linkType === LINKTYPE.IPV4 || v === 4) etherType = ETHERTYPE.IPv4;
                else if (this.linkType === LINKTYPE.IPV6 || v === 6) etherType = ETHERTYPE.IPv6;
                this.link = {
                    type: "raw-ip", src: null, dst: null, etherType, etherTypeName: etherTypeName(etherType),
                    vlan: [], headerLength: 0, summary: "raw IP",
                };
                l3Bytes = bytes;
                break;
            }
            case LINKTYPE.LINUX_SLL: {
                const sll = parseLinuxSll(bytes);
                this.link = {
                    type: "linux-sll", src: sll.src, dst: null, etherType: sll.protocolType,
                    etherTypeName: etherTypeName(sll.protocolType), vlan: [], headerLength: sll.headerLength,
                    summary: `Linux SLL pkttype ${sll.packetType}, protocol ${sll.protocolType !== null ? "0x" + sll.protocolType.toString(16).padStart(4, "0") : "?"}`,
                };
                if (sll.truncated) this.truncated = true;
                l3Bytes = bytes.slice(sll.headerLength);
                etherType = sll.protocolType;
                break;
            }
            case LINKTYPE.NULL:
            case LINKTYPE.LOOP: {
                const lb = parseNullLoopback(bytes);
                this.link = {
                    type: "null-loopback", src: null, dst: null, etherType: lb.etherType,
                    etherTypeName: etherTypeName(lb.etherType), vlan: [], headerLength: lb.headerLength,
                    summary: `BSD loopback, AF ${lb.addressFamily}`,
                };
                if (lb.truncated) this.truncated = true;
                l3Bytes = bytes.slice(lb.headerLength);
                etherType = lb.etherType;
                break;
            }
            default: {
                // 不认识的链路类型：标记 unknown 并原样保留 payload
                this.link = {
                    type: "unknown", src: null, dst: null, etherType: null, etherTypeName: null,
                    vlan: [], headerLength: 0, summary: `Unknown link type ${this.linkType}`,
                };
                this.payload = bytes;
                this.headerBytesConsumed = 0;
                return;
            }
        }

        // --- 步骤 2：解析网络层（仅 IPv4 / IPv6）---
        let ip = null;
        let isV6 = false;
        if (etherType === ETHERTYPE.IPv4) {
            ip = parseIpv4(l3Bytes);
        } else if (etherType === ETHERTYPE.IPv6) {
            ip = parseIpv6(l3Bytes);
            isV6 = true;
        } else {
            return;   // 非 IP（如 ARP）：network 保持 null
        }
        if (ip.truncated) this.truncated = true;
        this.network = this._buildNetwork(ip, isV6);

        // --- 步骤 3：解析传输层（非首分片不解析，避免把载荷当首部）---
        if (ip.fragmentOffset !== null && ip.fragmentOffset > 0) {
            this.headerBytesConsumed = this.link.headerLength + this.network.headerLength;
            return;
        }

        const l4Bytes = this._sliceL4(l3Bytes, ip);
        const proto = ip.protocol;
        let t = null;
        if (proto === IP_PROTOCOL.TCP) t = parseTcp(l4Bytes);
        else if (proto === IP_PROTOCOL.UDP) t = parseUdp(l4Bytes);
        else if (proto === IP_PROTOCOL.ICMP) t = parseIcmp(l4Bytes, false);
        else if (proto === IP_PROTOCOL.ICMPV6) t = parseIcmp(l4Bytes, true);

        if (t) {
            if (t.truncated) this.truncated = true;
            this.transport = this._buildTransport(t);

            // --- 步骤 4：切出应用层载荷（仅 TCP/UDP 有）---
            if (t.protocol === "TCP" || t.protocol === "UDP") {
                this.payload = l4Bytes.slice(t.payloadOffset, t.payloadOffset + t.payloadLength);
            }
        }

        // 传输层首部长度即其 payloadOffset（契约中 transport 不单独暴露 headerLength）
        this.headerBytesConsumed = this.link.headerLength +
            this.network.headerLength +
            (this.transport ? this.transport.payloadOffset : 0);
    }

    /**
     * 【方法】从 L3 缓冲区切出传输层字节
     * 参数：l3Bytes 网络层缓冲区；ip 网络层解析结果。
     * 返回：传输层字节 Uint8Array；载荷长度为 0（截断）时回退到剩余全部字节。
     */
    _sliceL4(l3Bytes, ip) {
        let plen = ip.payloadLength;
        if (!plen) plen = Math.max(0, l3Bytes.length - ip.payloadOffset);
        return l3Bytes.slice(ip.payloadOffset, ip.payloadOffset + plen);
    }

    /**
     * 【方法】整理网络层为固定契约的 network 对象
     * 参数：ip 解析结果；isV6 是否 IPv6。返回：契约规定的 network 结构（v6 填
     *      trafficClass/flowLabel/hopLimit，v4 填 dscp/ecn/identification/flags）。
     */
    _buildNetwork(ip, isV6) {
        if (isV6) {
            return {
                version: 6, src: ip.src, dst: ip.dst, protocol: ip.protocol,
                protocolName: ipProtocolName(ip.protocol), headerLength: ip.headerLength,
                totalLength: ip.totalLength, ttl: ip.hopLimit, payloadOffset: ip.payloadOffset,
                payloadLength: ip.payloadLength, dscp: null, ecn: null, identification: null,
                flags: null, fragmentOffset: ip.fragmentOffset, trafficClass: ip.trafficClass,
                flowLabel: ip.flowLabel, hopLimit: ip.hopLimit,
            };
        }
        return {
            version: 4, src: ip.src, dst: ip.dst, protocol: ip.protocol,
            protocolName: ipProtocolName(ip.protocol), headerLength: ip.headerLength,
            totalLength: ip.totalLength, ttl: ip.ttl, payloadOffset: ip.payloadOffset,
            payloadLength: ip.payloadLength, dscp: ip.dscp, ecn: ip.ecn,
            identification: ip.identification, flags: ip.flags, fragmentOffset: ip.fragmentOffset,
            trafficClass: null, flowLabel: null, hopLimit: null,
        };
    }

    /**
     * 【方法】整理传输层为固定契约的 transport 对象
     * 参数：t 解析结果（parseTcp/parseUdp/parseIcmp 之一）。返回：契约规定的
     *      transport 结构；缺失字段一律补 null。
     */
    _buildTransport(t) {
        return {
            protocol: t.protocol,
            srcPort: t.srcPort ?? null,
            dstPort: t.dstPort ?? null,
            seq: t.seq ?? null,
            ack: t.ack ?? null,
            dataOffset: t.dataOffset ?? null,
            flags: t.flags ?? null,
            window: t.window ?? null,
            checksum: t.checksum ?? null,
            urgentPointer: t.urgentPointer ?? null,
            options: t.options ?? [],
            segmentLength: t.segmentLength ?? null,
            length: t.length ?? null,
            payloadOffset: t.payloadOffset,
            payloadLength: t.payloadLength,
            type: t.type ?? null,
            code: t.code ?? null,
        };
    }

    /**
     * 【方法】生成链路层摘要片段（供 summary 使用）
     * 参数：src/dst 地址；etherType 类型号；vlan 标签栈。返回：摘要字符串。
     */
    _linkSummary(src, dst, etherType, vlan) {
        const parts = [`${src ?? "?"} > ${dst ?? "?"}`];
        if (vlan && vlan.length) parts.push(`VLAN ${vlan.map((v) => v.id).join("/")}`);
        if (etherType !== null) parts.push(`ethertype ${etherTypeName(etherType)}`);
        return parts.join(", ");
    }

    /**
     * 【取值器】一行摘要，形如 tcpdump 输出
     * 参数：无。返回：如 "aa:bb:.. > cc:dd:.., ethertype IPv4, 1.2.3.4 > 5.6.7.8,
     *      80 > 443: Flags [S], seq 1, ack 0, win 29200, length 0"。
     */
    get summary() {
        const segs = [];
        if (this.link) segs.push(this.link.summary);

        const n = this.network;
        if (n) {
            segs.push(`${n.src} > ${n.dst}`);
            const t = this.transport;
            if (t) {
                if (t.protocol === "TCP") {
                    const f = t.flags || {};
                    const fs = [f.fin ? "F" : "", f.syn ? "S" : "", f.rst ? "R" : "", f.psh ? "P" : "",
                                f.ack ? "." : "", f.urg ? "U" : "", f.ece ? "E" : "", f.cwr ? "C" : "", f.ns ? "N" : ""].join("");
                    segs.push(`${t.srcPort} > ${t.dstPort}: Flags [${fs}], seq ${t.seq}, ack ${t.ack}, win ${t.window}, length ${t.payloadLength}`);
                } else if (t.protocol === "UDP") {
                    segs.push(`${t.srcPort} > ${t.dstPort}: UDP, length ${t.payloadLength}`);
                } else {
                    const tc = (t.type !== null && t.code !== null) ? ` type ${t.type} code ${t.code}` : "";
                    segs.push(`${t.protocol}${tc}, length ${t.payloadLength}`);
                }
            } else {
                segs.push(`proto ${n.protocolName}`);
            }
        }
        return segs.join(", ");
    }
}

/**
 * 【函数】解析单段原始帧字节
 * 参数：bytes 帧字节；linkType 链路层类型；index 包序号；timestamp 秒。
 * 返回：DissectedPacket。
 */
export function dissectBytes(bytes, linkType, index = 0, timestamp = NaN) {
    return new DissectedPacket(bytes, linkType, index, timestamp);
}

/**
 * 【函数】遍历 PcapCapture 的所有包并逐包解析
 * 参数：capture Pcap.mjs 产出的抓包模型。返回：DissectedPacket[]，与
 *      capture.packets 一一对应；容器层已判定的截断会一并反映到结果上。
 */
export function dissectCapture(capture) {
    if (!capture || !Array.isArray(capture.packets)) return [];
    return capture.packets.map((p) => {
        const d = new DissectedPacket(p.data, p.linkType, p.index, p.timestamp);
        d.truncated = d.truncated || !!p.truncated;
        return d;
    });
}

export default {
    ETHERTYPE,
    IP_PROTOCOL,
    TCP_OPTION_KIND,
    etherTypeName,
    ipProtocolName,
    parseEthernet,
    parseIpv4,
    parseIpv6,
    parseTcp,
    parseUdp,
    parseIcmp,
    parseLinuxSll,
    parseNullLoopback,
    parseLoopback,
    DissectedPacket,
    dissectBytes,
    dissectCapture,
};
