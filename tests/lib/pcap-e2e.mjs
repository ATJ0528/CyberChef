/**
 * 端到端集成测试：夹具字节 → parsePcap → dissectCapture → analysePcap
 * 验证五个模块能真正串成一条流水线，且恢复出的应用层数据逐字节正确。
 */
import {pathToFileURL, fileURLToPath} from "node:url";
import path from "node:path";

const P = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fix = await import(pathToFileURL(`${P}/tests/lib/PcapFixtures.mjs`).href);
const {parsePcap} = await import(pathToFileURL(`${P}/src/core/lib/Pcap.mjs`).href);
const {dissectCapture} = await import(pathToFileURL(`${P}/src/core/lib/PcapPacket.mjs`).href);
const {analysePcap, APP_PROTOCOL} = await import(pathToFileURL(`${P}/src/core/lib/PcapSession.mjs`).href);

let pass = 0, fail = 0;
function check(name, actual, expected) {
    const ok = JSON.stringify(actual) === JSON.stringify(expected);
    if (ok) { pass++; console.log(`  ok   ${name}`); }
    else { fail++; console.log(`  FAIL ${name}\n       期望 ${JSON.stringify(expected)}\n       实际 ${JSON.stringify(actual)}`); }
}
function text(u8) { return Buffer.from(u8).toString("utf8"); }

for (const fmt of ["pcap", "pcapng"]) {
    console.log(`\n===== 端到端流水线 [${fmt}] =====`);
    const sess = fix.httpSessionFixture({format: fmt});
    const cap = parsePcap(sess.bytes);

    console.log("\n[1] 容器层");
    check("格式", cap.format, fmt);
    check("包数", cap.packetCount, 11);
    check("无警告", cap.warnings.length, 0);

    console.log("\n[2] 逐包分层解析");
    const analysis = analysePcap(cap, {dissectCapture});
    check("解包数", analysis.packets.length, 11);

    const first = analysis.packets[0];
    check("首包链路层非空", first.link !== null, true);
    check("首包网络层 src", first.network.src, sess.meta.clientIp);
    check("首包网络层 dst", first.network.dst, sess.meta.serverIp);
    check("首包传输层协议", first.transport.protocol, "TCP");
    check("首包传输层 srcPort", first.transport.srcPort, sess.meta.clientPort);
    check("首包传输层 dstPort", first.transport.dstPort, sess.meta.serverPort);
    check("首包无截断", first.truncated, false);
    check("首包时间戳有效", Number.isFinite(first.timestamp), true);

    console.log("\n[3] TCP 流重组");
    check("流数", analysis.streams.length, 1);
    const stream = analysis.streams[0];
    check("流端点 a.ip", stream.endpoints.a.ip, sess.meta.clientIp);
    check("流端点 b.ip", stream.endpoints.b.ip, sess.meta.serverIp);
    check("连接终态", stream.state, "closed");
    check("无重传", analysis.streamStats.retransmissionCount, 0);

    const re = stream.reassemble();
    check("恢复出的请求逐字节一致", text(re.aToB.data), sess.meta.requestBody);
    check("恢复出的响应逐字节一致", text(re.bToA.data), sess.meta.expectedResponse);
    check("请求方向无缺口", re.aToB.gaps.length, 0);
    check("响应方向无缺口", re.bToA.gaps.length, 0);

    console.log("\n[4] 会话归并与应用层识别");
    check("会话数", analysis.conversations.length, 1);
    const conv = analysis.conversations[0];
    check("会话传输层", conv.transportProtocol, "TCP");
    check("识别出 HTTP", conv.app.protocol, APP_PROTOCOL.HTTP);
    check("识别可信度 high", conv.app.confidence, "high");
    check("会话包数", conv.packets.length, 11);
    check("会话键与流键一致", conv.key, stream.key);

    console.log("\n[5] 统计汇总");
    const st = analysis.stats;
    check("总包数", st.packetCount, 11);
    check("TCP 包数", st.tcpPacketCount, 11);
    check("UDP 包数", st.udpPacketCount, 0);
    check("流数", st.streamCount, 1);
    check("会话数", st.conversationCount, 1);
    check("时长 > 0", st.duration > 0, true);
    check("协议分布含 HTTP", st.protocols[0].protocol, APP_PROTOCOL.HTTP);
    check("HTTP 会话数", st.protocols[0].conversations, 1);

    const expectedPayload =
        Buffer.byteLength(sess.meta.requestBody, "utf8") +
        Buffer.byteLength(sess.meta.expectedResponse, "utf8");
    check("载荷总字节 = 请求+响应", st.payloadBytes, expectedPayload);
}

console.log("\n===== 端口兜底与未知协议 =====");
{
    // 构造一个加密样载荷的 443 会话，验证"端口兜底"路径
    const tls = fix.httpSessionFixture({
        srcPort: 51000, dstPort: 443,
        requestBody: "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    });
    const a = analysePcap(parsePcap(tls.bytes), {dissectCapture});
    check("443 端口识别（载荷优先）", a.conversations[0].app.protocol, APP_PROTOCOL.HTTP);
    check("且为高可信度", a.conversations[0].app.confidence, "high");
}

console.log("\n===== 客户端 / 服务端判定（回归） =====");
{
    // 回归：endpoints.a 只是规范排序，不能当成客户端。
    // 服务端 IP 字典序更小时（"104.x" < "192.x"），旧实现会把两端写反。
    const tls = fix.httpSessionFixture({
        clientIp: "192.168.1.10",
        clientPort: 50200,
        serverIp: "104.18.22.19",
        serverPort: 443,
        requestBody: "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    });
    const a = analysePcap(parsePcap(tls.bytes), {dissectCapture});
    const s = a.conversations[0].summary;
    check("服务端 IP 字典序更小时 client 仍为发起方", s.client.ip, "192.168.1.10");
    check("对应端口", s.client.port, 50200);
    check("server 为对端", s.server.ip, "104.18.22.19");
    check("server 端口", s.server.port, 443);

    // UDP：没有 SYN，按端口惯例把较小端口当服务端
    const udpPkts = [
        {data: fix.udpFrame({srcIp: "10.0.0.5", dstIp: "9.9.9.9", srcPort: 53000, dstPort: 53, payload: new Uint8Array([1, 2, 3])}), timestamp: 1600000000.1},
    ];
    const ua = analysePcap(parsePcap(fix.buildPcap(udpPkts)), {dissectCapture});
    const us = ua.conversations[0].summary;
    check("UDP client = 高端口一端", us.client.port, 53000);
    check("UDP server = 53", us.server.port, 53);
}

console.log(`\n===== 通过 ${pass} / 失败 ${fail} =====`);
process.exit(fail ? 1 : 0);
