/**
 * Pcap.mjs 冒烟测试：手工构造 pcap 与 pcapng 字节流，验证解析结果。
 * 在仓库内运行：node tests/lib/pcap-smoke.mjs
 */
const LIB = new URL("../../src/core/lib/Pcap.mjs", import.meta.url).href;
const {parsePcap, isPcap, getLinkTypeName, LINKTYPE} = await import(LIB);

let pass = 0, fail = 0;
function check(name, actual, expected) {
    const ok = JSON.stringify(actual) === JSON.stringify(expected);
    if (ok) { pass++; console.log(`  ok   ${name}`); }
    else { fail++; console.log(`  FAIL ${name}\n       期望 ${JSON.stringify(expected)}\n       实际 ${JSON.stringify(actual)}`); }
}

// ---------- 构造工具 ----------
function u8(...bytes) { return new Uint8Array(bytes.flat()); }
function u16(v, le) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, v, le); return b; }
function u32(v, le) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, le); return b; }
function big64(v, le) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), le); return b; }
function cat(...arrs) {
    const total = arrs.reduce((a, x) => a + x.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
}

// 以太网 + IPv4 + TCP 帧
function frame(srcPort, dstPort, seq, payload) {
    const eth = cat(
        u8(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),   // dst mac
        u8(0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb),   // src mac
        u16(0x0800, false)                        // IPv4
    );
    const totalIpLen = 20 + 20 + payload.length;
    const ip = cat(
        u8(0x45, 0x00), u16(totalIpLen, false),
        u16(0x1c46, false), u16(0x4000, false),
        u8(64, 6), u16(0x0000, false),
        u8(192, 168, 1, 10), u8(192, 168, 1, 20)
    );
    const tcp = cat(
        u16(srcPort, false), u16(dstPort, false),
        u32(seq, false), u32(0, false),
        u8(0x50, 0x18), u16(0x7210, false), u16(0x0000, false), u16(0, false)
    );
    return cat(eth, ip, tcp, new Uint8Array(payload));
}

// ---------- 1. 经典 pcap（小端，微秒） ----------
console.log("\n[1] 经典 pcap，小端 + 微秒精度");
const pkt1 = frame(1024, 80, 1000, [0x47, 0x45, 0x54, 0x20]);
const pkt2 = frame(80, 1024, 5000, [0x4f, 0x4b]);
const pcapBytes = cat(
    u32(0xa1b2c3d4, true),          // 小端写入 → 文件为小端
    u16(2, true), u16(4, true),
    u32(0, true), u32(0, true),
    u32(65535, true),               // snaplen
    u32(1, true),                   // LINKTYPE_ETHERNET
    u32(1600000000, true), u32(250000, true), u32(pkt1.length, true), u32(pkt1.length, true), pkt1,
    u32(1600000001, true), u32(750000, true), u32(pkt2.length, true), u32(pkt2.length, true), pkt2
);

const c1 = parsePcap(pcapBytes);
check("识别格式", c1.format, "pcap");
check("识别端序", c1.byteOrder, "le");
check("版本", c1.version, "2.4");
check("包数", c1.packetCount, 2);
check("链路类型名", getLinkTypeName(c1.linkType), "Ethernet");
check("包0 时间戳", c1.packets[0].timestamp, 1600000000.25);
check("包1 时间戳", c1.packets[1].timestamp, 1600000001.75);
check("时长", c1.duration, 1.5);
check("包0 数据长度", c1.packets[0].data.length, pkt1.length);
check("包0 前6字节", Array.from(c1.packets[0].data.slice(0, 6)), [0, 0x11, 0x22, 0x33, 0x44, 0x55]);
check("snaplen", c1.snaplen, 65535);
check("接口数(合成)", c1.interfaces.length, 1);
check("无警告", c1.warnings.length, 0);

// ---------- 2. 大端 pcap + 纳秒 ----------
console.log("\n[2] 经典 pcap，大端 + 纳秒精度");
const pcapBE = cat(
    u32(0xa1b23c4d, false),         // 大端写入 → 文件为大端，纳秒
    u16(2, false), u16(4, false),
    u32(0, false), u32(0, false),
    u32(262144, false),
    u32(113, false),                // Linux SLL
    u32(1600000000, false), u32(123456789, false), u32(pkt1.length, false), u32(pkt1.length, false), pkt1
);
const c2 = parsePcap(pcapBE);
check("识别端序", c2.byteOrder, "be");
check("纳秒精度", c2.nanosecond, true);
check("链路类型名", getLinkTypeName(c2.linkType), "Linux SLL (Cooked)");
check("纳秒换算", c2.packets[0].timestamp, 1600000000.123456789);

// ---------- 3. pcapng（小端，含 IDB 与 EPB） ----------
console.log("\n[3] pcapng，小端");
function block(type, body, le) {
    const total = 12 + body.length;
    const pad = (4 - (body.length % 4)) % 4;
    const padded = cat(body, new Uint8Array(pad));
    const totalPadded = 12 + padded.length;
    return cat(u32(type, le), u32(totalPadded, le), padded, u32(totalPadded, le));
}
const shbBody = cat(u32(0x1a2b3c4d, true), u16(1, true), u16(0, true), big64(-1, true));
const shb = block(0x0a0d0d0a, shbBody, true);
// IDB：linkType=1 以太网，snaplen=65535，选项 if_tsresol=9（10^9 纳秒）
const idbBody = cat(u16(1, true), u16(0, true), u32(65535, true),
    u16(9, true), u16(1, true), u8(9), new Uint8Array(3),
    u16(0, true), u16(0, true));
const idb = block(0x00000001, idbBody, true);
// EPB：interface 0，时间戳 1600000000 秒 + 500000000 纳秒
const ticks = BigInt(1600000000) * BigInt(1000000000) + BigInt(500000000);
const epbBody = cat(
    u32(0, true),
    u32(Number(ticks >> BigInt(32)), true),
    u32(Number(ticks & BigInt(0xffffffff)), true),
    u32(pkt1.length, true), u32(pkt1.length, true), pkt1
);
const epb = block(0x00000006, epbBody, true);
const epb2Body = cat(
    u32(0, true),
    u32(Number((ticks + BigInt(1500000000)) >> BigInt(32)), true),
    u32(Number((ticks + BigInt(1500000000)) & BigInt(0xffffffff)), true),
    u32(pkt2.length, true), u32(pkt2.length, true), pkt2
);
const epb2 = block(0x00000006, epb2Body, true);

const ngBytes = cat(shb, idb, epb, epb2);
const c3 = parsePcap(ngBytes);
check("识别格式", c3.format, "pcapng");
check("识别端序", c3.byteOrder, "le");
check("版本", c3.version, "1.0");
check("包数", c3.packetCount, 2);
check("接口数", c3.interfaces.length, 1);
check("接口链路类型", c3.interfaces[0].linkType, LINKTYPE.ETHERNET);
check("if_tsresol 分辨率", c3.interfaces[0].tsResolution, 1000000000);
check("包0 时间戳", c3.packets[0].timestamp, 1600000000.5);
check("包1 时间戳", c3.packets[1].timestamp, 1600000002.0);
check("包0 数据长度", c3.packets[0].data.length, pkt1.length);
check("包0 数据内容一致", Array.from(c3.packets[0].data.slice(0, 8)), Array.from(pkt1.slice(0, 8)));
check("包0 接口号", c3.packets[0].interfaceId, 0);
check("无警告", c3.warnings.length, 0);

// ---------- 4. 边界与容错 ----------
console.log("\n[4] 边界与容错");
check("嗅探 pcap", isPcap(pcapBytes), true);
check("嗅探 pcapng", isPcap(ngBytes), true);
check("嗅探 非抓包", isPcap(u8(1, 2, 3, 4, 5, 6, 7, 8)), false);
check("嗅探 过短", isPcap(u8(1, 2)), false);

// 损坏魔数应抛错
let threw = false;
try { parsePcap(u8(0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0)); } catch (e) { threw = true; }
check("非法魔数抛错", threw, true);

// 空输入应抛错
threw = false;
try { parsePcap(new Uint8Array(0)); } catch (e) { threw = true; }
check("空输入抛错", threw, true);

// 只有全局头、没有包 → 0 包 + 警告
const emptyPcap = cat(
    u32(0xa1b2c3d4, true), u16(2, true), u16(4, true),
    u32(0, true), u32(0, true), u32(65535, true), u32(1, true)
);
const c4 = parsePcap(emptyPcap);
check("空抓包 包数", c4.packetCount, 0);
check("空抓包 有警告", c4.warnings.length > 0, true);

// 截断的包（声明长度超过实际）
const truncBytes = cat(
    u32(0xa1b2c3d4, true), u16(2, true), u16(4, true),
    u32(0, true), u32(0, true), u32(65535, true), u32(1, true),
    u32(1600000000, true), u32(0, true), u32(1000, true), u32(1000, true),
    pkt1.slice(0, 30)   // 只给 30 字节
);
const c5 = parsePcap(truncBytes);
check("截断包 仍解析出1包", c5.packetCount, 1);
check("截断包 长度为剩余", c5.packets[0].data.length, 30);
check("截断包 有警告", c5.warnings.length > 0, true);

// maxPackets 限制
const c6 = parsePcap(pcapBytes, {maxPackets: 1});
check("maxPackets 截断", c6.packetCount, 1);
check("maxPackets 记录位置", c6.truncatedAt, 1);

// ---------- 5. summary ----------
console.log("\n[5] 汇总信息");
const s = c1.summary;
check("summary.format", s.format, "pcap");
check("summary.packetCount", s.packetCount, 2);
check("summary.durationSeconds", s.durationSeconds, 1.5);

console.log(`\n===== 通过 ${pass} / 失败 ${fail} =====`);
process.exit(fail ? 1 : 0);
