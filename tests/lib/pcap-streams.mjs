/**
 * Extract PCAP streams 操作测试。
 *
 * 重点覆盖两件事：
 *   1. 客户端 / 服务端的判定。夹具特意让服务端 IP 的字典序更小，
 *      若实现把规范排序的 endpoints.a 当成客户端，方向会整体反转。
 *   2. 方向、流序号、标注开关、分隔符四组参数的组合行为。
 */
import {pathToFileURL, fileURLToPath} from "node:url";
import path from "node:path";

const P = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fix = await import(pathToFileURL(`${P}/tests/lib/PcapFixtures.mjs`).href);
const ExtractPcapStreams = (await import(pathToFileURL(`${P}/src/core/operations/ExtractPcapStreams.mjs`).href)).default;

const op = new ExtractPcapStreams();

let pass = 0, fail = 0;
/**
 * 断言辅助：用 JSON 序列化比较实际值与期望值。
 *
 * @param {string} name - 用例名
 * @param {*} actual - 实际值
 * @param {*} expected - 期望值
 * @returns {void}
 */
function check(name, actual, expected) {
    const ok = JSON.stringify(actual) === JSON.stringify(expected);
    if (ok) {
        pass++; console.log(`  ok   ${name}`);
    } else {
        fail++; console.log(`  FAIL ${name}\n       期望 ${JSON.stringify(expected)}\n       实际 ${JSON.stringify(actual)}`);
    }
}

const ab = (u8) => u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
const enc = (s) => new TextEncoder().encode(s);

const CLIENT_IP = "192.168.1.10", SERVER_IP = "10.0.0.1";
const CLIENT_PORT = 49152, SERVER_PORT = 80;
const REQ = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: CyberChef-Test/1.0\r\nAccept: */*\r\n\r\n";
const RESP_HEAD = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nContent-Length: 25\r\n\r\n";
const RESP_BODY = "<html><body>Hello!</body>";

/**
 * 按给定夹具参数生成抓包并执行一次操作。
 *
 * @param {Object} opts - 传给 httpSessionFixture 的参数
 * @param {Array} args - 操作的参数列表
 * @returns {{sess: Object, out: string}}
 */
function runSession(opts, args) {
    const sess = fix.httpSessionFixture(opts);
    return {sess, out: op.run(ab(sess.bytes), args)};
}

const DEFAULTS = ["TCP streams", "Client to server", -1, true, "Double newline"];

console.log("\n[1] 客户端 / 服务端方向判定");
{
    // 服务端 IP "10.0.0.1" 字典序小于客户端 "192.168.1.10"
    const {out} = runSession({clientIp: CLIENT_IP, serverIp: SERVER_IP,
        clientPort: CLIENT_PORT, serverPort: SERVER_PORT}, DEFAULTS);
    check("标注里客户端在前", out.includes(`${CLIENT_IP}:${CLIENT_PORT} ${SERVER_IP}:${SERVER_PORT}`), true);
    check("标注里客户端在后（不应出现）", out.includes(`${SERVER_IP}:${SERVER_PORT} ${CLIENT_IP}:${CLIENT_PORT}`), false);
    check("方向标注是 client -> server", out.includes("(client -> server,"), true);
    check("取到的是请求而不是响应", out.includes("GET /index.html HTTP/1.1"), true);
    check("响应不在客户端方向里", out.includes("HTTP/1.1 200 OK"), false);
}

console.log("\n[2] 三个方向选项");
{
    const c2s = runSession({}, DEFAULTS).out;
    const s2c = runSession({}, ["TCP streams", "Server to client", -1, true, "Double newline"]).out;
    const both = runSession({}, ["TCP streams", "Both", -1, true, "Double newline"]).out;
    check("客户端方向不含响应", c2s.includes("Hello!"), false);
    check("服务端方向含响应头", s2c.includes("HTTP/1.1 200 OK"), true);
    check("服务端方向不含请求行", s2c.includes("GET /index.html"), false);
    check("服务端方向标注", s2c.includes("(server -> client,"), true);
    check("双向都含请求", both.includes("GET /index.html HTTP/1.1"), true);
    check("双向都含响应", both.includes("HTTP/1.1 200 OK"), true);
    check("双向有两个标注", (both.match(/--- Stream 1 /g) || []).length, 2);
}

console.log("\n[3] 载荷长度与内容");
{
    const {out} = runSession({}, DEFAULTS);
    check("请求长度与标注一致", out.includes(`, ${enc(REQ).length} bytes)`), true);
    check("请求体完整", out.includes(REQ), true);

    const s2c = runSession({}, ["TCP streams", "Server to client", -1, true, "Double newline"]).out;
    check("响应头完整", s2c.includes(RESP_HEAD), true);
    check("响应体完整", s2c.includes(RESP_BODY), true);
    check("响应总长与标注一致", s2c.includes(`, ${enc(RESP_HEAD + RESP_BODY).length} bytes)`), true);
}

console.log("\n[4] 标注开关");
{
    const on = runSession({}, DEFAULTS).out;
    const off = runSession({}, ["TCP streams", "Client to server", -1, false, "Double newline"]).out;
    check("开启时有标注", on.includes("--- Stream 1"), true);
    check("关闭时无标注", off.includes("--- Stream"), false);
    check("关闭时直接是请求", off.startsWith("GET /index.html HTTP/1.1"), true);
}

console.log("\n[5] 分隔符");
{
    const parts = (delim) => runSession({}, ["TCP streams", "Both", -1, true, delim]).out;
    const dbl = parts("Double newline");
    const nl = parts("Newline");
    const crlf = parts("CRLF");
    const none = parts("None");

    check("Double newline 生效", dbl.includes("---\n\nGET /index.html"), true);
    check("Newline 生效", nl.includes("---\nGET /index.html"), true);
    check("CRLF 生效", crlf.includes("---\r\nGET /index.html"), true);
    check("None 生效", none.includes("---GET /index.html"), true);
    check("四种分隔符互不相同", new Set([dbl, nl, crlf, none]).size, 4);
}

console.log("\n[6] 流序号");
{
    const all = runSession({}, DEFAULTS).out;
    const first = runSession({}, ["TCP streams", "Client to server", 0, true, "Double newline"]).out;
    const oob = runSession({}, ["TCP streams", "Client to server", 1, true, "Double newline"]).out;
    const neg = runSession({}, ["TCP streams", "Client to server", -1, true, "Double newline"]).out;

    check("只有一条流时全部与 0 相同", first, all);
    check("-1 也返回全部", neg, all);
    check("越界返回空串", oob, "");
}

console.log("\n[7] 传输层筛选（UDP）");
{
    const dnsQuery = new Uint8Array([
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01,
    ]);
    const udpCapture = fix.buildPcap([{
        data: fix.udpFrame({srcIp: "192.168.1.10", dstIp: "8.8.8.8",
            srcPort: 53000, dstPort: 53, payload: dnsQuery}),
        timestamp: 1600000000.5,
    }]);

    const udpOnly = op.run(ab(udpCapture), ["UDP flows", "Client to server", -1, true, "Double newline"]);
    check("UDP 流被提取", udpOnly.includes("[UDP/"), true);
    check("客户端端口较大，判定为客户端", udpOnly.includes("192.168.1.10:53000 8.8.8.8:53"), true);
    check("DNS 查询内容完整", udpOnly.includes("\x07example\x03com"), true);
    check("UDP 方向标注", udpOnly.includes("(client -> server,"), true);

    const tcpOnly = op.run(ab(udpCapture), ["TCP streams", "Both", -1, true, "Double newline"]);
    check("只取 TCP 时为空", tcpOnly, "");
}

console.log("\n[8] pcapng 容器");
{
    const sess = fix.httpSessionFixture({format: "pcapng"});
    const out = op.run(ab(sess.bytes), DEFAULTS);
    check("pcapng 也能提取", out.includes("GET /index.html HTTP/1.1"), true);
    check("pcapng 标注格式一致", out.includes("(client -> server,"), true);
}

console.log("\n[9] 错误处理");
{
    let empty = "";
    try {
        op.run(new ArrayBuffer(0), DEFAULTS);
    } catch (err) {
        empty = err.message;
    }
    check("空输入给出明确提示", empty, "No input data. Drop a .pcap or .pcapng capture file into the input.");

    let bad = "";
    try {
        op.run(ab(new Uint8Array([1, 2, 3, 4])), DEFAULTS);
    } catch (err) {
        bad = err.message;
    }
    check("非抓包文件提示前缀", bad.startsWith("Not a valid capture file: "), true);
    check("提示里只出现一次结论", (bad.match(/Not a valid capture file/g) || []).length, 1);
}

console.log(`\n===== 通过 ${pass} / 失败 ${fail} =====`);
process.exitCode = fail === 0 ? 0 : 1;
