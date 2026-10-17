/**
 * FilterPcap / ConvertPcapFormat 操作测试。
 * 期望值尽量从夹具实际数据算出，避免写死数字导致的假失败。
 */
import {pathToFileURL, fileURLToPath} from "node:url";
import path from "node:path";

const P = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fix = await import(pathToFileURL(`${P}/tests/lib/PcapFixtures.mjs`).href);
const {parsePcap} = await import(pathToFileURL(`${P}/src/core/lib/Pcap.mjs`).href);
const {dissectCapture} = await import(pathToFileURL(`${P}/src/core/lib/PcapPacket.mjs`).href);
const FilterPcap = (await import(pathToFileURL(`${P}/src/core/operations/FilterPcap.mjs`).href)).default;
const ConvertPcapFormat = (await import(pathToFileURL(`${P}/src/core/operations/ConvertPcapFormat.mjs`).href)).default;

const op = new FilterPcap();
const conv = new ConvertPcapFormat();

let pass = 0, fail = 0;
function check(name, actual, expected) {
    const ok = JSON.stringify(actual) === JSON.stringify(expected);
    if (ok) { pass++; console.log(`  ok   ${name}`); }
    else { fail++; console.log(`  FAIL ${name}\n       期望 ${JSON.stringify(expected)}\n       实际 ${JSON.stringify(actual)}`); }
}
const ab = (u8) => u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);

const sess = fix.httpSessionFixture();
const buf = ab(sess.bytes);

// ---- 从夹具实际数据算出基准 ----
const FULL = parsePcap(sess.bytes);
const DIS = dissectCapture(FULL);
const FRAMES = DIS.map(p => FULL.packets[p.index].data.length);
const PAYLOADS = DIS.map(p => p.payload.length);
const cnt = (arr, pred) => arr.filter(pred).length;

const frameOver = (n) => cnt(FRAMES, l => l > n);
const payloadOver = (n) => cnt(PAYLOADS, l => l > n);

console.log(`基准：包数 ${FULL.packetCount}，帧长 ${JSON.stringify(FRAMES)}`);
console.log(`      载荷长 ${JSON.stringify(PAYLOADS)}`);

function runFilter(expr, fmt = "Same as input") {
    return parsePcap(new Uint8Array(op.run(buf, [expr, fmt])));
}
const tryRun = (expr) => {
    try { return runFilter(expr).packetCount; } catch (e) { return "error"; }
};

console.log("\n[1] 协议关键字");
check("tcp 命中全部", runFilter("tcp").packetCount, 11);
check("http 命中全部", runFilter("http").packetCount, 11);
check("大小写不敏感 HTTP", runFilter("HTTP").packetCount, 11);
check("ip 命中全部（IPv4）", runFilter("ip").packetCount, 11);
check("not tcp 命中 0 → 报错", tryRun("not tcp"), "error");
check("udp 命中 0 → 报错", tryRun("udp"), "error");

console.log("\n[2] 字段比较（方向语义）");
check("tcp.port == 80（双向）", runFilter("tcp.port == 80").packetCount, 11);
check("tcp.srcport == 49152（客户端发）", runFilter("tcp.srcport == 49152").packetCount, 6);
check("tcp.srcport == 80（服务端发）", runFilter("tcp.srcport == 80").packetCount, 5);
check("tcp.dstport == 80（客户端发）", runFilter("tcp.dstport == 80").packetCount, 6);
check("tcp.dstport == 49152（服务端发）", runFilter("tcp.dstport == 49152").packetCount, 5);
check("ip.addr == 客户端（双向）", runFilter("ip.addr == 192.168.1.10").packetCount, 11);
check("ip.src == 服务端", runFilter("ip.src == 93.184.216.34").packetCount, 5);
check("ip.dst == 服务端", runFilter("ip.dst == 93.184.216.34").packetCount, 6);
check("udp.port == 80（UDP 包不存在）", tryRun("udp.port == 80"), "error");

console.log("\n[3] 长度字段：len 是整帧，payload 是应用层载荷");
check("len > 100 == 帧长>100 的包数", runFilter("len > 100").packetCount, frameOver(100));
check("  ↑ 且阈值确实筛掉了包", frameOver(100) > 0 && frameOver(100) < 11, true);
check("payload > 100 无匹配 → 报错", tryRun("payload > 100"), "error");
check("payload > 50 == 载荷>50 的包数", runFilter("payload > 50").packetCount, payloadOver(50));
// 数值比较不是字符串比较："100" < "9" 字典序成立，若按字符串比 len>9 会漏掉长帧
check("len > 9 命中数 ≥ len > 100", frameOver(9) >= frameOver(100), true);
check("len > 9 命中数 > len > 100", frameOver(9) > frameOver(100), true);
check("len > 9 实测", runFilter("len > 9").packetCount, frameOver(9));

console.log("\n[4] TCP 标志位");
check("tcp.flags.syn == 1", runFilter("tcp.flags.syn == 1").packetCount, 2);
check("tcp.flags.fin == 1", runFilter("tcp.flags.fin == 1").packetCount, 2);
check("tcp.flags.rst == 1 → 0 包报错", tryRun("tcp.flags.rst == 1"), "error");
check("tcp.flags.ack == 1", runFilter("tcp.flags.ack == 1").packetCount,
    cnt(DIS, p => p.transport.protocol === "TCP" && p.transport.flags.ack === 1));
check("tcp.flags.syn == 0", runFilter("tcp.flags.syn == 0").packetCount, 9);

console.log("\n[5] 逻辑运算与优先级");
check("syn or fin", runFilter("tcp.flags.syn == 1 or tcp.flags.fin == 1").packetCount, 4);
check("tcp and ip.addr", runFilter("tcp and ip.addr == 192.168.1.10").packetCount, 11);
check("三条件与", runFilter("tcp and port == 80 and len > 100").packetCount, frameOver(100));
// 优先级：a or b and c 必须解析为 a or (b and c)，否则结果会变
check("or 优先级低于 and", runFilter("http or tcp and len > 100").packetCount, 11);
check("括号改变结合", runFilter("(http or tcp) and len > 100").packetCount, frameOver(100));
check("not 与括号", runFilter("tcp and not (len > 100)").packetCount, 11 - frameOver(100));
check("&& 写法", runFilter("tcp && len > 100").packetCount, frameOver(100));
check("|| 写法", runFilter("tcp || udp and len > 100").packetCount, 11);
check("嵌套括号", runFilter("tcp and (len > 100 or len < 60)").packetCount,
    frameOver(100) + cnt(FRAMES, l => l < 60));

console.log("\n[6] 错误处理");
const expectThrow = (name, fn, mustMatch) => {
    try { fn(); check(name, "no-error", "error"); }
    catch (e) { check(name, mustMatch.test(e.message) ? "error" : `错误信息不符: ${e.message}`, "error"); }
};
expectThrow("未知关键字", () => runFilter("bogusproto"), /Unknown protocol keyword/);
expectThrow("缺右括号", () => runFilter("(tcp"), /closing parenthesis/i);
expectThrow("非法字符", () => runFilter("tcp @ udp"), /Unexpected character/);
expectThrow("缺比较值", () => runFilter("len >"), /Expected a value/);
expectThrow("尾部多余词元", () => runFilter("tcp 80"), /trailing token/i);
expectThrow("空表达式", () => op.run(buf, ["  ", "Same as input"]), /No filter expression/);
expectThrow("空输入", () => op.run(new ArrayBuffer(0), ["tcp", "Same as input"]), /No input data/);
expectThrow("非抓包输入", () => op.run(ab(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])), ["tcp", "Same as input"]), /Not a valid capture file/);

console.log("\n[7] 输出文件可被重新读取");
{
    const out = runFilter("tcp.flags.syn == 1");
    check("过滤结果包数", out.packetCount, 2);
    check("过滤结果无警告", out.warnings.length, 0);
    check("仍是合法 pcap", out.format, "pcap");
    check("过滤后确实都是 SYN", out.packets.every(p => (p.data[47] & 0x02) === 0x02), true);

    const outNg = runFilter("tcp and len > 100", "pcapng");
    check("可输出 pcapng", outNg.format, "pcapng");
    check("pcapng 过滤包数", outNg.packetCount, frameOver(100));

    const outPcap = runFilter("tcp and len > 100", "pcap");
    check("可输出 pcap", outPcap.format, "pcap");
    check("两种输出包数一致", outPcap.packetCount, outNg.packetCount);

    // 过滤 → 再过滤，链式可用
    const chained = parsePcap(new Uint8Array(op.run(
        op.run(buf, ["tcp", "Same as input"]), ["len > 100", "Same as input"])));
    check("链式过滤", chained.packetCount, frameOver(100));
}

console.log("\n[8] 格式转换操作");
{
    const ng = conv.run(buf, ["pcapng", "Little endian", "Microseconds"]);
    const c = parsePcap(new Uint8Array(ng));
    check("pcap -> pcapng", c.format, "pcapng");
    check("包数不变", c.packetCount, 11);

    const back = conv.run(ng, ["pcap", "Little endian", "Microseconds"]);
    const c2 = parsePcap(new Uint8Array(back));
    check("pcapng -> pcap", c2.format, "pcap");
    check("包数仍为 11", c2.packetCount, 11);
    check("数据逐字节保持",
        c2.packets.every((p, i) => Array.from(p.data).join() === Array.from(FULL.packets[i].data).join()), true);
    check("时间戳保持在微秒精度",
        c2.packets.every((p, i) => Math.abs(p.timestamp - FULL.packets[i].timestamp) < 1e-6), true);

    const be = conv.run(buf, ["pcap", "Big endian", "Nanoseconds"]);
    const c3 = parsePcap(new Uint8Array(be));
    check("可转大端+纳秒", [c3.byteOrder, c3.nanosecond], ["be", true]);
    check("大端包数", c3.packetCount, 11);
    check("大端数据不变",
        c3.packets.every((p, i) => Array.from(p.data).join() === Array.from(FULL.packets[i].data).join()), true);

    const ngBE = conv.run(buf, ["pcapng", "Big endian", "Microseconds"]);
    const c4 = parsePcap(new Uint8Array(ngBE));
    check("pcapng 大端", c4.byteOrder, "be");
    check("pcapng 大端包数", c4.packetCount, 11);
}

console.log(`\n===== 通过 ${pass} / 失败 ${fail} =====`);
process.exit(fail ? 1 : 0);
