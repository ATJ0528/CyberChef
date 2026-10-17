/**
 * 应用层识别与 UDP 归并的分支覆盖测试。
 * 重点验证：TLS 二进制路径、端口兜底、未知回退、UDP 四元组归并。
 */
import {pathToFileURL, fileURLToPath} from "node:url";
import path from "node:path";

const P = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fix = await import(pathToFileURL(`${P}/tests/lib/PcapFixtures.mjs`).href);
const {parsePcap} = await import(pathToFileURL(`${P}/src/core/lib/Pcap.mjs`).href);
const {dissectCapture} = await import(pathToFileURL(`${P}/src/core/lib/PcapPacket.mjs`).href);
const {analysePcap, detectApplicationProtocol, buildUdpFlows, APP_PROTOCOL} =
    await import(pathToFileURL(`${P}/src/core/lib/PcapSession.mjs`).href);

let pass = 0, fail = 0;
function check(name, actual, expected) {
    const ok = JSON.stringify(actual) === JSON.stringify(expected);
    if (ok) { pass++; console.log(`  ok   ${name}`); }
    else { fail++; console.log(`  FAIL ${name}\n       期望 ${JSON.stringify(expected)}\n       实际 ${JSON.stringify(actual)}`); }
}
const enc = s => new TextEncoder().encode(s);
const ep = (port) => ({a: {ip: "10.0.0.1", port: 40000}, b: {ip: "10.0.0.2", port}});

console.log("\n[1] TLS 二进制载荷（端口 443，非文本）");
{
    // 真实 TLS ClientHello 开头：内容类型 22、版本 3.1
    const hello = new Uint8Array([0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const r = detectApplicationProtocol(
        {aToB: hello, bToA: new Uint8Array(0)}, ep(443), "TCP");
    check("识别为 TLS", r.protocol, APP_PROTOCOL.TLS);
    check("可信度 high", r.confidence, "high");

    // 关键：即便跑在非标准端口上，二进制 TLS 也应被认出
    const r2 = detectApplicationProtocol({aToB: hello, bToA: new Uint8Array(0)}, ep(31337), "TCP");
    check("非常规端口仍识别为 TLS", r2.protocol, APP_PROTOCOL.TLS);
}

console.log("\n[2] TLS 记录头边界");
{
    const mk = (ct, maj, min) => new Uint8Array([ct, maj, min, 0x00, 0x10, 9, 9, 9, 9, 9]);
    check("内容类型 20 (CCS) 合法", looksTLS(mk(20, 3, 3)), true);
    check("内容类型 23 (AppData) 合法", looksTLS(mk(23, 3, 3)), true);
    check("内容类型 19 非法", looksTLS(mk(19, 3, 3)), false);
    check("内容类型 24 非法", looksTLS(mk(24, 3, 3)), false);
    check("版本高字节非 3 非法", looksTLS(mk(22, 2, 0)), false);
    check("不足 5 字节非法", looksTLS(new Uint8Array([0x16, 0x03, 0x01])), false);

    function looksTLS(bytes) {
        return detectApplicationProtocol({aToB: bytes, bToA: new Uint8Array(0)}, ep(9999), "TCP")
            .protocol === APP_PROTOCOL.TLS;
    }
}

console.log("\n[3] 文本协议特征");
{
    const cases = [
        ["GET / HTTP/1.1\r\nHost: a\r\n\r\n", 9999, APP_PROTOCOL.HTTP],
        ["HTTP/1.0 404 Not Found\r\n\r\n", 9999, APP_PROTOCOL.HTTP],
        ["SSH-2.0-OpenSSH_9.0\r\n", 9999, APP_PROTOCOL.SSH],
        ["EHLO mail.example.com\r\n", 9999, APP_PROTOCOL.SMTP],
        ["USER anonymous\r\n", 9999, APP_PROTOCOL.FTP],
        ["+OK POP3 ready\r\n", 9999, APP_PROTOCOL.POP3],
        ["a001 CAPABILITY\r\n", 9999, APP_PROTOCOL.IMAP],
        ["*1\r\n$4\r\nPING\r\n", 9999, APP_PROTOCOL.REDIS],
    ];
    for (const [payload, port, expected] of cases) {
        const r = detectApplicationProtocol({aToB: enc(payload), bToA: new Uint8Array(0)}, ep(port), "TCP");
        check(`载荷识别 ${expected}`, r.protocol, expected);
        check(`  ↑ 可信度 high`, r.confidence, "high");
    }
}

console.log("\n[4] 端口兜底与未知回退");
{
    // 32000 端口上放不可识别的二进制载荷 → 只能靠端口
    const binary = new Uint8Array(64).fill(0x80);
    const r = detectApplicationProtocol({aToB: binary, bToA: new Uint8Array(0)}, ep(443), "TCP");
    check("443 + 二进制 → 端口兜底 TLS", r.protocol, APP_PROTOCOL.TLS);
    check("可信度 medium", r.confidence, "medium");

    const r2 = detectApplicationProtocol({aToB: binary, bToA: new Uint8Array(0)}, ep(12345), "TCP");
    check("未知端口 → Unknown", r2.protocol, APP_PROTOCOL.UNKNOWN);
    check("可信度 unknown", r2.confidence, "unknown");

    const r3 = detectApplicationProtocol(
        {aToB: new Uint8Array(0), bToA: new Uint8Array(0)}, ep(12345), "TCP");
    check("空载荷不崩", r3.protocol, APP_PROTOCOL.UNKNOWN);

    // UDP 端口表与 TCP 端口表必须分开：53 在 UDP 上是 DNS
    const r4 = detectApplicationProtocol({aToB: binary, bToA: new Uint8Array(0)}, ep(53), "UDP");
    check("UDP/53 → DNS", r4.protocol, APP_PROTOCOL.DNS);
    // UDP 443 是 QUIC，不是 TLS
    const r5 = detectApplicationProtocol({aToB: binary, bToA: new Uint8Array(0)}, ep(443), "UDP");
    check("UDP/443 → QUIC", r5.protocol, APP_PROTOCOL.QUIC);
}

console.log("\n[5] UDP 四元组归并");
{
    const dnsQuery = enc("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01");
    const dnsReply = enc("\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01");

    const f1 = fix.udpFrame({srcIp: "192.168.1.10", dstIp: "8.8.8.8", srcPort: 50123, dstPort: 53, payload: dnsQuery});
    const f2 = fix.udpFrame({srcIp: "8.8.8.8", dstIp: "192.168.1.10", srcPort: 53, dstPort: 50123, payload: dnsReply});
    // 另一对端点，应归并成独立的第二条流
    const f3 = fix.udpFrame({srcIp: "192.168.1.11", dstIp: "8.8.8.8", srcPort: 50124, dstPort: 53, payload: dnsQuery});

    const bytes = fix.buildPcap([
        {data: f1, timestamp: 1600000000.0},
        {data: f2, timestamp: 1600000000.1},
        {data: f3, timestamp: 1600000000.2},
    ], {littleEndian: true, linkType: 1});

    const analysis = analysePcap(parsePcap(bytes), {dissectCapture});
    check("解出 3 个包", analysis.packets.length, 3);
    check("无 TCP 流", analysis.streams.length, 0);
    check("归并成 2 条 UDP 流", analysis.conversations.length, 2);
    check("都是 UDP", analysis.conversations.every(c => c.transportProtocol === "UDP"), true);

    const flows = buildUdpFlows(analysis.packets);
    check("flows 数", flows.length, 2);
    const main = flows.find(f => f.packets.length === 2);
    check("主流向 aToB 为查询", Buffer.from(main.aToB).length, dnsQuery.length);
    check("主流向 bToA 为应答", Buffer.from(main.bToA).length, dnsReply.length);
    check("两条流端点不混淆", new Set(flows.map(f => f.key)).size, 2);

    check("会话识别为 DNS", analysis.conversations.every(c => c.app.protocol === APP_PROTOCOL.DNS), true);
    const st = analysis.stats;
    check("统计：UDP 包数", st.udpPacketCount, 3);
    check("统计：TCP 包数", st.tcpPacketCount, 0);
    check("统计：会话数", st.conversationCount, 2);
}

console.log(`\n===== 通过 ${pass} / 失败 ${fail} =====`);
process.exit(fail ? 1 : 0);
