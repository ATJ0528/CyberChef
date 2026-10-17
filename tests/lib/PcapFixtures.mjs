/**
 * @author CyberChef Contributor
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 抓包测试夹具构造器
 * 【文件】tests/lib/PcapFixtures.mjs
 * 【职责】用纯代码构造合法的以太网/IP/TCP/UDP 报文与 pcap、pcapng
 *         容器字节流，供单元测试与界面演示使用。
 *         好处是不依赖任何二进制样本文件，测试数据可复现、可审阅。
 * 【被谁使用】tests/operations/tests/Pcap*.mjs、
 *         tools/gen-sample-pcap.mjs（生成演示用样本文件）
 * ------------------------------------------------------------
 * 【导出接口】
 *   - checksum16(bytes)                 → number : 16 位反码校验和
 *   - ipv4Bytes(ip) / ipv6Bytes(ip)     → Uint8Array : 地址字符串转字节
 *   - macBytes(mac)                     → Uint8Array : MAC 字符串转 6 字节
 *   - ipv4Header(opts) / ipv6Header(opts) → Uint8Array : IP 首部
 *   - tcpHeader(opts)                   → Uint8Array : TCP 首部
 *   - tcpChecksum / tcpChecksum6 / udpChecksum → number : 传输层校验和
 *   - tcpFrame(opts)                    → Uint8Array : 以太网+IPv4+TCP 帧
 *   - tcpFrame6(opts)                   → Uint8Array : 以太网+IPv6+TCP 帧
 *   - udpFrame(opts)                    → Uint8Array : 以太网+IPv4+UDP 帧
 *   - buildPcap(packets, opts)          → Uint8Array : 经典 pcap 文件
 *   - pcapngBlock(type, body, le)       → Uint8Array : 单个 pcapng 块
 *   - buildPcapng(packets, opts)        → Uint8Array : pcapng 文件
 *   - toHex(bytes)                      → string
 *   - httpSessionFixture(opts)          → Object : 一个完整的 HTTP 会话抓包
 * ------------------------------------------------------------
 * 【关键算法】
 *   1. 校验和用 RFC 1071 的"16 位反码求和"：按 16 位分组累加，进位回卷到
 *      低位，最后取反。TCP/IP 校验和计算时要把校验和字段本身置 0。
 *   2. TCP 伪首部：TCP 校验和覆盖的不仅是 TCP 首部与数据，还包括一个
 *      12 字节"伪首部"（源 IP、目的 IP、0、协议号、TCP 长度）。这是
 *      TCP 校验和区别于其他校验和的关键，构造夹具时必须补上。
 *   3. pcapng 块按 4 字节对齐：块体长度不足 4 的倍数要补齐，
 *      而块总长字段记录的是**补齐之后**的长度。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 全部用 Uint8Array + DataView 构造，不拼字符串。字符串拼接在处理
 *     0x00 字节与高位字节时会引入编码陷阱（如 UTF-8 会把 >0x7F 的字节
 *     扩成两字节）。
 *   - 夹具函数只接受普通对象参数并给出合理默认值，测试用例里只需写
 *     关心的字段，读起来接近自然语言。
 * ============================================================
 */

/**
 * 计算 16 位反码校验和（RFC 1071）。
 *
 * 步骤：按 16 位大端分组求和 → 把高 16 位的进位回卷加到低 16 位 →
 * 取反。因为 JS 的 `+` 是 64 位浮点，累加不会溢出，回卷时要手工处理。
 * 输入长度为奇数时，末尾补一个 0 字节。
 *
 * @param {Uint8Array} bytes - 参与校验的数据（调用方需自行把校验和字段置 0）
 * @returns {number} 16 位校验和
 */
export function checksum16(bytes) {
    let sum = 0;

    // --- 步骤 1：按 16 位大端分组累加 ---
    for (let i = 0; i < bytes.length - 1; i += 2) {
        sum += (bytes[i] << 8) | bytes[i + 1];
    }

    // 奇数长度：末字节当作高 8 位，低 8 位补 0
    if (bytes.length % 2 === 1) {
        sum += bytes[bytes.length - 1] << 8;
    }

    // --- 步骤 2：把溢出到高 16 位的进位回卷到低位，直到不再溢出 ---
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // --- 步骤 3：取反得到校验和 ---
    return (~sum) & 0xffff;
}


/**
 * 把字节数组转成小写十六进制字符串。
 *
 * 用于把构造好的抓包字节喂给 CyberChef 的 "From Hex" 操作
 * （测试框架的 input 是字符串，二进制数据需以 hex 形式提供）。
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}


/**
 * 把若干字节数组拼接成一个。
 *
 * @param {...Uint8Array} arrays
 * @returns {Uint8Array}
 */
export function concat(...arrays) {
    const total = arrays.reduce((acc, a) => acc + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
        out.set(a, offset);
        offset += a.length;
    }
    return out;
}


/**
 * 构造一个 2 字节的大端无符号整数。
 *
 * @param {number} value
 * @returns {Uint8Array}
 */
function u16be(value) {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, value, false);
    return b;
}


/**
 * 把 "192.168.1.10" 形式的字符串转成 4 字节。
 *
 * @param {string} ip
 * @returns {Uint8Array}
 */
export function ipv4Bytes(ip) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) {
        throw new Error(`Invalid IPv4 address: ${ip}`);
    }
    return new Uint8Array(parts);
}


/**
 * 把 "66:77:88:99:aa:bb" 形式的字符串转成 6 字节。
 *
 * @param {string} mac
 * @returns {Uint8Array}
 */
export function macBytes(mac) {
    const parts = mac.split(":").map(h => parseInt(h, 16));
    if (parts.length !== 6 || parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) {
        throw new Error(`Invalid MAC address: ${mac}`);
    }
    return new Uint8Array(parts);
}


/**
 * 把 "2001:db8::1" 形式的字符串转成 16 字节。
 *
 * 支持 `::` 压缩，以及末尾内嵌 IPv4 的写法（如 `::ffff:192.168.1.1`）。
 *
 * @param {string} ip
 * @returns {Uint8Array} 16 字节
 */
export function ipv6Bytes(ip) {
    let text = ip;
    let embedded = null;

    // 末尾若是一个点分 IPv4，先取出 4 字节，再把它换成两个 16 位组占位
    const m = text.match(/(\d+\.\d+\.\d+\.\d+)$/);
    if (m) {
        embedded = ipv4Bytes(m[1]);
        text = text.slice(0, m.index) + "0:0";
    }

    const parseGroups = (s) => s ? s.split(":").map(g => {
        const v = parseInt(g, 16);
        if (!/^[0-9a-fA-F]{1,4}$/.test(g) || Number.isNaN(v)) {
            throw new Error(`Invalid IPv6 address: ${ip}`);
        }
        return v;
    }) : [];

    let groups;
    if (text.includes("::")) {
        const [head, tail] = text.split("::");
        if (text.indexOf("::") !== text.lastIndexOf("::")) {
            throw new Error(`Invalid IPv6 address: ${ip}`);
        }
        const a = parseGroups(head), b = parseGroups(tail);
        const missing = 8 - a.length - b.length;
        if (missing < 1) throw new Error(`Invalid IPv6 address: ${ip}`);
        groups = [...a, ...new Array(missing).fill(0), ...b];
    } else {
        groups = parseGroups(text);
    }

    if (groups.length !== 8) throw new Error(`Invalid IPv6 address: ${ip}`);

    const out = new Uint8Array(16);
    const dv = new DataView(out.buffer);
    groups.forEach((g, i) => dv.setUint16(i * 2, g, false));
    if (embedded) out.set(embedded, 12);

    return out;
}


/**
 * 构造 IPv6 首部（40 字节，无扩展首部）。
 *
 * @param {Object} opts
 * @param {string} opts.src - 源 IPv6 地址
 * @param {string} opts.dst - 目的 IPv6 地址
 * @param {number} opts.nextHeader - 下一个首部（6=TCP，17=UDP，58=ICMPv6）
 * @param {number} opts.payloadLength - 载荷长度（不含 IPv6 首部）
 * @param {number} [opts.hopLimit=64]
 * @param {number} [opts.trafficClass=0]
 * @param {number} [opts.flowLabel=0]
 * @returns {Uint8Array} 40 字节首部
 */
export function ipv6Header(opts) {
    const {
        src, dst,
        nextHeader, payloadLength,
        hopLimit = 64,
        trafficClass = 0,
        flowLabel = 0,
    } = opts;

    const header = new Uint8Array(40);
    const dv = new DataView(header.buffer);

    dv.setUint32(0, (6 << 28) | ((trafficClass & 0xff) << 20) | (flowLabel & 0xfffff), false);
    dv.setUint16(4, payloadLength, false);
    dv.setUint8(6, nextHeader);
    dv.setUint8(7, hopLimit);
    header.set(ipv6Bytes(src), 8);
    header.set(ipv6Bytes(dst), 24);

    return header;
}


/**
 * 构造 IPv4 首部（20 字节，无选项）。
 *
 * 校验和字段在最后一步按 RFC 1071 填入。
 *
 * @param {Object} opts
 * @param {string} opts.src - 源 IP
 * @param {string} opts.dst - 目的 IP
 * @param {number} opts.protocol - 协议号（6=TCP，17=UDP，1=ICMP）
 * @param {number} opts.payloadLength - 载荷长度（不含 IP 首部）
 * @param {number} [opts.ttl=64] - 生存时间
 * @param {number} [opts.identification=0x1234] - 标识字段
 * @param {number} [opts.flagsAndOffset=0x4000] - 标志位与分片偏移（默认为不分片）
 * @param {number} [opts.dscp=0] - 区分服务代码点
 * @returns {Uint8Array} 20 字节首部
 */
export function ipv4Header(opts) {
    const {
        src, dst, protocol, payloadLength,
        ttl = 64,
        identification = 0x1234,
        flagsAndOffset = 0x4000,
        dscp = 0,
    } = opts;

    const totalLength = 20 + payloadLength;
    const header = new Uint8Array(20);
    const dv = new DataView(header.buffer);

    dv.setUint8(0, 0x45);                        // 版本 4 + IHL 5（20 字节）
    dv.setUint8(1, (dscp << 2) & 0xfc);          // DSCP + ECN(0)
    dv.setUint16(2, totalLength, false);
    dv.setUint16(4, identification, false);
    dv.setUint16(6, flagsAndOffset, false);
    dv.setUint8(8, ttl);
    dv.setUint8(9, protocol);
    dv.setUint16(10, 0, false);                  // 校验和先置 0 再计算
    header.set(ipv4Bytes(src), 12);
    header.set(ipv4Bytes(dst), 16);
    dv.setUint16(10, checksum16(header), false);

    return header;
}


/**
 * 构造 TCP 首部（20 字节，无选项）。
 *
 * @param {Object} opts
 * @param {number} opts.srcPort
 * @param {number} opts.dstPort
 * @param {number} opts.seq - 序列号（32 位）
 * @param {number} opts.ack - 确认号（32 位）
 * @param {number} opts.flags - 标志位字节（SYN=0x02, ACK=0x10, FIN=0x01 …）
 * @param {number} [opts.window=65535]
 * @param {number} [opts.urgentPointer=0]
 * @returns {Uint8Array} 20 字节首部（校验和留待伪首部一起算）
 */
export function tcpHeader(opts) {
    const {
        srcPort, dstPort, seq, ack, flags,
        window = 65535,
        urgentPointer = 0,
    } = opts;

    const header = new Uint8Array(20);
    const dv = new DataView(header.buffer);

    dv.setUint16(0, srcPort, false);
    dv.setUint16(2, dstPort, false);
    dv.setUint32(4, seq >>> 0, false);
    dv.setUint32(8, ack >>> 0, false);
    dv.setUint8(12, 0x50);                       // 数据偏移 5（20 字节），保留位 0
    dv.setUint8(13, flags);
    dv.setUint16(14, window, false);
    dv.setUint16(16, 0, false);                  // 校验和稍后填
    dv.setUint16(18, urgentPointer, false);

    return header;
}


/**
 * 计算 TCP 校验和（需要 12 字节伪首部）。
 *
 * 伪首部 = 源IP(4) + 目的IP(4) + 全0(1) + 协议号(1=TCP) + TCP总长度(2)。
 * 它不真正出现在网络上，只参与校验和计算，目的是让 TCP 能检测出
 * 报文被错误投递到其他主机的情况。
 *
 * @param {Uint8Array} tcpSegment - TCP 首部 + 数据（校验和字段须为 0）
 * @param {string} srcIp
 * @param {string} dstIp
 * @returns {number} 16 位校验和
 */
export function tcpChecksum(tcpSegment, srcIp, dstIp) {
    const pseudo = concat(
        ipv4Bytes(srcIp),
        ipv4Bytes(dstIp),
        new Uint8Array([0, 6]),                  // 全 0 + 协议号 TCP
        u16be(tcpSegment.length)
    );
    return checksum16(concat(pseudo, tcpSegment));
}


/**
 * 计算 UDP 校验和（伪首部格式同 TCP，只有协议号不同）。
 *
 * @param {Uint8Array} udpDatagram - UDP 首部 + 数据（校验和字段须为 0）
 * @param {string} srcIp
 * @param {string} dstIp
 * @returns {number} 16 位校验和
 */
export function udpChecksum(udpDatagram, srcIp, dstIp) {
    const pseudo = concat(
        ipv4Bytes(srcIp),
        ipv4Bytes(dstIp),
        new Uint8Array([0, 17]),                 // 全 0 + 协议号 UDP
        u16be(udpDatagram.length)
    );
    return checksum16(concat(pseudo, udpDatagram));
}


/**
 * 计算 IPv6 下 TCP 的校验和（RFC 8200 伪首部）。
 *
 * 伪首部 = 源地址(16) + 目的地址(16) + 上层报文长度(4) + 全 0(3) + 下一首部(1)。
 *
 * @param {Uint8Array} tcpSegment - TCP 首部 + 数据（校验和字段须为 0）
 * @param {string} srcIp
 * @param {string} dstIp
 * @returns {number} 16 位校验和
 */
export function tcpChecksum6(tcpSegment, srcIp, dstIp) {
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, tcpSegment.length, false);

    const pseudo = concat(
        ipv6Bytes(srcIp),
        ipv6Bytes(dstIp),
        length,
        new Uint8Array([0, 0, 0, 6])            // 3 字节全 0 + 协议号 TCP
    );
    return checksum16(concat(pseudo, tcpSegment));
}


/**
 * 构造一个完整的以太网 + IPv6 + TCP 帧。
 *
 * @param {Object} opts
 * @param {string} [opts.srcMac="66:77:88:99:aa:bb"]
 * @param {string} [opts.dstMac="00:11:22:33:44:55"]
 * @param {string} opts.srcIp - IPv6 源地址
 * @param {string} opts.dstIp - IPv6 目的地址
 * @param {number} opts.srcPort
 * @param {number} opts.dstPort
 * @param {number} opts.seq
 * @param {number} [opts.ack=0]
 * @param {number} opts.flags
 * @param {Uint8Array|number[]} [opts.payload=[]]
 * @param {number|null} [opts.vlanId=null]
 * @returns {Uint8Array} 完整帧
 */
export function tcpFrame6(opts) {
    const {
        srcMac = "66:77:88:99:aa:bb",
        dstMac = "00:11:22:33:44:55",
        srcIp, dstIp, srcPort, dstPort, seq,
        ack = 0,
        flags,
        payload = [],
        vlanId = null,
    } = opts;

    const payloadBytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);

    const tcp = tcpHeader({srcPort, dstPort, seq, ack, flags});
    const segment = concat(tcp, payloadBytes);
    new DataView(segment.buffer, segment.byteOffset).setUint16(16, tcpChecksum6(segment, srcIp, dstIp), false);

    const ip = ipv6Header({src: srcIp, dst: dstIp, nextHeader: 6, payloadLength: segment.length});

    let eth;
    if (vlanId === null) {
        eth = concat(macBytes(dstMac), macBytes(srcMac), u16be(0x86dd));
    } else {
        eth = concat(macBytes(dstMac), macBytes(srcMac), u16be(0x8100), u16be(vlanId & 0x0fff), u16be(0x86dd));
    }

    return concat(eth, ip, segment);
}


/**
 * 构造一个完整的以太网 + IPv4 + TCP 帧。
 *
 * @param {Object} opts
 * @param {string} [opts.srcMac="66:77:88:99:aa:bb"]
 * @param {string} [opts.dstMac="00:11:22:33:44:55"]
 * @param {string} opts.srcIp
 * @param {string} opts.dstIp
 * @param {number} opts.srcPort
 * @param {number} opts.dstPort
 * @param {number} opts.seq
 * @param {number} [opts.ack=0]
 * @param {number} opts.flags - SYN/ACK/FIN/PSH/RST 位组合
 * @param {Uint8Array|number[]} [opts.payload=[]] - 应用层载荷
 * @param {number|null} [opts.vlanId=null] - 非 null 则插入 802.1Q 标签
 * @returns {Uint8Array} 完整帧
 */
export function tcpFrame(opts) {
    const {
        srcMac = "66:77:88:99:aa:bb",
        dstMac = "00:11:22:33:44:55",
        srcIp, dstIp, srcPort, dstPort, seq,
        ack = 0,
        flags,
        payload = [],
        vlanId = null,
    } = opts;

    const payloadBytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);

    // --- 步骤 1：TCP 首部 + 载荷，并回填校验和 ---
    const tcp = tcpHeader({srcPort, dstPort, seq, ack, flags});
    const segment = concat(tcp, payloadBytes);
    new DataView(segment.buffer, segment.byteOffset).setUint16(16, tcpChecksum(segment, srcIp, dstIp), false);

    // --- 步骤 2：IP 首部 ---
    const ip = ipv4Header({src: srcIp, dst: dstIp, protocol: 6, payloadLength: segment.length});

    // --- 步骤 3：以太网首部（可选 VLAN 标签）---
    let eth;
    if (vlanId === null) {
        eth = concat(macBytes(dstMac), macBytes(srcMac), u16be(0x0800));
    } else {
        // 802.1Q：类型 0x8100 + 2 字节 TCI（PCP 3 位 | DEI 1 位 | VID 12 位）
        const tci = u16be((vlanId & 0x0fff));
        eth = concat(macBytes(dstMac), macBytes(srcMac), u16be(0x8100), tci, u16be(0x0800));
    }

    return concat(eth, ip, segment);
}


/**
 * 构造一个完整的以太网 + IPv4 + UDP 帧。
 *
 * @param {Object} opts
 * @param {string} opts.srcIp
 * @param {string} opts.dstIp
 * @param {number} opts.srcPort
 * @param {number} opts.dstPort
 * @param {Uint8Array|number[]} [opts.payload=[]]
 * @returns {Uint8Array}
 */
export function udpFrame(opts) {
    const {srcIp, dstIp, srcPort, dstPort, payload = []} = opts;
    const payloadBytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);

    const udp = new Uint8Array(8);
    const dv = new DataView(udp.buffer);
    dv.setUint16(0, srcPort, false);
    dv.setUint16(2, dstPort, false);
    dv.setUint16(4, 8 + payloadBytes.length, false);
    dv.setUint16(6, 0, false);

    const datagram = concat(udp, payloadBytes);
    new DataView(datagram.buffer, datagram.byteOffset).setUint16(6, udpChecksum(datagram, srcIp, dstIp), false);

    const ip = ipv4Header({src: srcIp, dst: dstIp, protocol: 17, payloadLength: datagram.length});
    const eth = concat(macBytes("00:11:22:33:44:55"), macBytes("66:77:88:99:aa:bb"), u16be(0x0800));

    return concat(eth, ip, datagram);
}


/**
 * 构造经典 pcap 文件。
 *
 * @param {Object[]} packets - 形如 {data: Uint8Array, timestamp: number, origLen?: number}
 * @param {Object} [opts={}]
 * @param {boolean} [opts.littleEndian=true] - 端序
 * @param {boolean} [opts.nanosecond=false] - 是否用纳秒精度（pcap-ns）
 * @param {number} [opts.linkType=1] - 链路层类型
 * @param {number} [opts.snaplen=262144]
 * @returns {Uint8Array}
 */
export function buildPcap(packets, opts = {}) {
    const {
        littleEndian = true,
        nanosecond = false,
        linkType = 1,
        snaplen = 262144,
    } = opts;

    // 魔数：小端文件用 setUint32(le=true) 写入 0xa1b2c3d4 效果等价于
    // 大端文件的 0xd4c3b2a1，两者都表示"这是 pcap"
    const magic = nanosecond ? 0xa1b23c4d : 0xa1b2c3d4;

    const global = new Uint8Array(24);
    const gdv = new DataView(global.buffer);
    gdv.setUint32(0, magic, littleEndian);
    gdv.setUint16(4, 2, littleEndian);
    gdv.setUint16(6, 4, littleEndian);
    gdv.setUint32(8, 0, littleEndian);           // thiszone
    gdv.setUint32(12, 0, littleEndian);          // sigfigs
    gdv.setUint32(16, snaplen, littleEndian);
    gdv.setUint32(20, linkType, littleEndian);

    const parts = [global];
    const ticksPerSecond = nanosecond ? 1000000000 : 1000000;

    for (const pkt of packets) {
        const tsSec = Math.floor(pkt.timestamp);
        const tsFrac = Math.round((pkt.timestamp - tsSec) * ticksPerSecond);

        const rec = new Uint8Array(16);
        const rdv = new DataView(rec.buffer);
        rdv.setUint32(0, tsSec, littleEndian);
        rdv.setUint32(4, tsFrac, littleEndian);
        rdv.setUint32(8, pkt.data.length, littleEndian);
        rdv.setUint32(12, pkt.origLen ?? pkt.data.length, littleEndian);

        parts.push(rec, pkt.data);
    }

    return concat(...parts);
}


/**
 * 构造一个 pcapng 块。
 *
 * 块结构：类型(4) + 总长(4) + 块体(4 字节对齐补齐) + 总长副本(4)。
 *
 * @param {number} type - 块类型
 * @param {Uint8Array} body - 块体
 * @param {boolean} littleEndian
 * @returns {Uint8Array}
 */
export function pcapngBlock(type, body, littleEndian) {
    const padLength = (4 - (body.length % 4)) % 4;
    const padded = concat(body, new Uint8Array(padLength));
    const totalLength = 12 + padded.length;

    return concat(
        u32WithOrder(type, littleEndian),
        u32WithOrder(totalLength, littleEndian),
        padded,
        u32WithOrder(totalLength, littleEndian)
    );
}


/**
 * 按指定端序构造 4 字节无符号整数。
 *
 * @param {number} value
 * @param {boolean} littleEndian
 * @returns {Uint8Array}
 */
function u32WithOrder(value, littleEndian) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, value >>> 0, littleEndian);
    return b;
}


/**
 * 构造 pcapng 文件。
 *
 * 生成 SHB + 一个 IDB + 每个包一个 EPB 的标准结构。
 *
 * @param {Object[]} packets - 形如 {data: Uint8Array, timestamp: number}
 * @param {Object} [opts={}]
 * @param {boolean} [opts.littleEndian=true]
 * @param {number} [opts.linkType=1]
 * @param {number} [opts.tsResolution=1000000] - 每秒钟多少 tick
 * @param {Object} [opts.interfaceOptions={}] - 额外的 IDB 选项，如 {name, description}
 * @returns {Uint8Array}
 */
export function buildPcapng(packets, opts = {}) {
    const {
        littleEndian = true,
        linkType = 1,
        tsResolution = 1000000,
        interfaceOptions = {},
    } = opts;

    const le = littleEndian;

    // --- SHB：节头块。BOM 用小端写入时读出来正是 0x1a2b3c4d ---
    const shbBody = concat(
        u32WithOrder(0x1a2b3c4d, le),            // Byte-Order Magic
        new Uint8Array([1, 0]),                  // 主版本 1（大端 2 字节）
        new Uint8Array([0, 0]),                  // 次版本 0
        new Uint8Array(8).fill(0xff)             // 节长度 -1（未知）
    );
    const shb = pcapngBlock(0x0a0d0d0a, shbBody, le);

    // --- IDB：接口描述块。默认带 if_tsresol 选项 ---
    const tsresolExp = Math.round(Math.log10(tsResolution));
    const optionParts = [
        new Uint8Array([9, 0]),                  // if_tsresol 选项码
        new Uint8Array([1, 0]),                  // 长度 1
        new Uint8Array([tsresolExp]),
        new Uint8Array(3),                       // 补齐到 4 字节
    ];
    if (interfaceOptions.name) {
        const nameBytes = new TextEncoder().encode(interfaceOptions.name);
        const pad = (4 - (nameBytes.length % 4)) % 4;
        optionParts.push(
            new Uint8Array([2, 0]),
            u16beOf(nameBytes.length, le),
            nameBytes,
            new Uint8Array(pad)
        );
    }
    optionParts.push(new Uint8Array([0, 0]), new Uint8Array([0, 0]));   // opt_endofopt

    const idbBody = concat(
        u16beOf(linkType, le),
        new Uint8Array([0, 0]),                  // 保留字段
        u32WithOrder(262144, le),                // snaplen
        concat(...optionParts)
    );
    const idb = pcapngBlock(0x00000001, idbBody, le);

    // --- EPB：每个包一个增强分组块 ---
    const epbs = packets.map(pkt => {
        const ticks = BigInt(Math.round(pkt.timestamp * tsResolution));
        const body = concat(
            u32WithOrder(0, le),                                             // 接口号
            u32WithOrder(Number(ticks >> BigInt(32)), le),                   // 时间戳高位
            u32WithOrder(Number(ticks & BigInt(0xffffffff)), le),            // 时间戳低位
            u32WithOrder(pkt.data.length, le),                               // 捕获长度
            u32WithOrder(pkt.origLen ?? pkt.data.length, le),                // 原始长度
            pkt.data,
            new Uint8Array([0, 0, 0, 0])                                     // opt_endofopt
        );
        return pcapngBlock(0x00000006, body, le);
    });

    return concat(shb, idb, ...epbs);
}


/**
 * 按指定端序构造 2 字节无符号整数。
 *
 * @param {number} value
 * @param {boolean} littleEndian
 * @returns {Uint8Array}
 */
function u16beOf(value, littleEndian) {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, value, littleEndian);
    return b;
}


/**
 * 构造一个完整的 HTTP 会话抓包，用于单元测试与界面演示。
 *
 * 会话内容：三次握手 → GET 请求 → 响应（分两段）→ 四次挥手。
 * 客户端 192.168.1.10:49152 访问服务端 93.184.216.34:80。
 *
 * @param {Object} [opts={}]
 * @param {"pcap"|"pcapng"} [opts.format="pcap"] - 输出容器格式
 * @param {boolean} [opts.littleEndian=true] - 端序
 * @param {boolean} [opts.includeHandshake=true] - 是否包含三次握手
 * @returns {Object} {bytes: Uint8Array, hex: string, linkType: number, meta: Object}
 */
export function httpSessionFixture(opts = {}) {
    const {
        format = "pcap",
        littleEndian = true,
        includeHandshake = true,
        clientIp = "192.168.1.10",
        serverIp = "93.184.216.34",
        clientPort = 49152,
        serverPort = 80,
        clientISN = 1000,
        serverISN = 5000,
        requestBody = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: CyberChef-Test/1.0\r\nAccept: */*\r\n\r\n",
        responseHead = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nContent-Length: 25\r\n\r\n",
        responseBody = "<html><body>Hello!</body>",
    } = opts;


    const packets = [];
    let t = 1600000000.0;

    /**
     * 追加一个 TCP 帧。
     * @param {string} srcIp 源 IP
     * @param {string} dstIp 目的 IP
     * @param {number} srcPort 源端口
     * @param {number} dstPort 目的端口
     * @param {number} seq 序列号
     * @param {number} ack 确认号
     * @param {number} flags 标志位
     * @param {Uint8Array|number[]} payload 载荷
     * @param {number} advance 时间推进秒数
     */
    function push(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload, advance) {
        t += advance;
        const data = tcpFrame({srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload});
        packets.push({
            data,
            timestamp: t,
            // 源/目的 MAC 依方向互换，让抓包更真实
            meta: {srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payloadLength: payload.length},
        });
    }

    const SYN = 0x02, SYNACK = 0x12, ACK = 0x10, PSHACK = 0x18, FINACK = 0x11;

    let clientNext = clientISN;
    let serverNext = serverISN;

    if (includeHandshake) {
        // --- 三次握手 ---
        push(clientIp, serverIp, clientPort, serverPort, clientISN, 0, SYN, [], 0.001);
        push(serverIp, clientIp, serverPort, clientPort, serverISN, clientISN + 1, SYNACK, [], 0.002);
        push(clientIp, serverIp, clientPort, serverPort, clientISN + 1, serverISN + 1, ACK, [], 0.001);
        clientNext = clientISN + 1;
        serverNext = serverISN + 1;
    }

    // --- HTTP 请求 ---
    const reqBytes = new TextEncoder().encode(requestBody);
    push(clientIp, serverIp, clientPort, serverPort, clientNext, serverNext, PSHACK, reqBytes, 0.010);
    clientNext += reqBytes.length;

    // --- 服务端确认 ---
    push(serverIp, clientIp, serverPort, clientPort, serverNext, clientNext, ACK, [], 0.005);

    // --- HTTP 响应，故意拆成两段以测试流重组 ---
    const headBytes = new TextEncoder().encode(responseHead);
    const bodyBytes = new TextEncoder().encode(responseBody);
    push(serverIp, clientIp, serverPort, clientPort, serverNext, clientNext, PSHACK, headBytes, 0.020);
    serverNext += headBytes.length;
    push(serverIp, clientIp, serverPort, clientPort, serverNext, clientNext, PSHACK, bodyBytes, 0.003);
    serverNext += bodyBytes.length;
    push(clientIp, serverIp, clientPort, serverPort, clientNext, serverNext, ACK, [], 0.004);

    // --- 四次挥手 ---
    push(clientIp, serverIp, clientPort, serverPort, clientNext, serverNext, FINACK, [], 0.015);
    clientNext += 1;
    push(serverIp, clientIp, serverPort, clientPort, serverNext, clientNext, FINACK, [], 0.008);
    serverNext += 1;
    push(clientIp, serverIp, clientPort, serverPort, clientNext, serverNext, ACK, [], 0.002);

    const bytes = format === "pcapng" ?
        buildPcapng(packets, {littleEndian, linkType: 1}) :
        buildPcap(packets, {littleEndian, linkType: 1});

    return {
        bytes,
        hex: toHex(bytes),
        linkType: 1,
        meta: {
            clientIp, serverIp, clientPort, serverPort,
            clientISN, serverISN,
            packetCount: packets.length,
            requestBody, responseHead, responseBody,
            expectedResponse: responseHead + responseBody,
        },
        packets,
    };
}
