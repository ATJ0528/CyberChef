/**
 * 抓包解析的错误处理与边界条件测试。
 *
 * 覆盖：输入校验、魔数预检、文件截断、包数上限、版本警告，
 * 以及三个操作层入口对非法输入给出的提示。
 */
import {pathToFileURL, fileURLToPath} from "node:url";
import path from "node:path";

const P = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fix = await import(pathToFileURL(`${P}/tests/lib/PcapFixtures.mjs`).href);
const {parsePcap, isPcap} = await import(pathToFileURL(`${P}/src/core/lib/Pcap.mjs`).href);
const ParsePcap = (await import(pathToFileURL(`${P}/src/core/operations/ParsePcap.mjs`).href)).default;
const FilterOp = (await import(pathToFileURL(`${P}/src/core/operations/FilterPcap.mjs`).href)).default;
const ConvertOp = (await import(pathToFileURL(`${P}/src/core/operations/ConvertPcapFormat.mjs`).href)).default;

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

/**
 * 捕获一段同步代码抛出的错误消息。
 *
 * @param {Function} fn - 待执行的函数
 * @returns {string} 错误消息；未抛出时为空串
 */
function messageOf(fn) {
    try {
        fn();
    } catch (err) {
        return err.message;
    }
    return "";
}

const SESS = fix.httpSessionFixture();
const BASE = SESS.bytes;

console.log("\n[1] parsePcap 输入校验");
{
    check("空输入", messageOf(() => parsePcap(new Uint8Array(0))),
        "No data was provided to parse as a capture file.");
    check("不足 4 字节", messageOf(() => parsePcap(new Uint8Array([1, 2, 3]))),
        "Capture file is too short to contain a valid header (3 bytes).");
    check("魔数不识别", messageOf(() => parsePcap(new Uint8Array([0x11, 0x22, 0x33, 0x44]))),
        "Expected a pcap or pcapng magic number, got 0x11223344.");
    check("只有全局头魔数", messageOf(() => parsePcap(BASE.slice(0, 4))),
        "Capture file is too short for a pcap global header (expected 24 bytes, got 4).");
}

console.log("\n[2] isPcap 格式预检");
{
    check("undefined", isPcap(undefined), false);
    check("空数组", isPcap(new Uint8Array(0)), false);
    check("不足 4 字节", isPcap(new Uint8Array([0xa1, 0xb2, 0xc3])), false);
    check("经典 pcap 小端", isPcap(new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])), true);
    check("经典 pcap 大端", isPcap(new Uint8Array([0xa1, 0xb2, 0xc3, 0xd4])), true);
    check("pcapng", isPcap(new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a])), true);
    check("普通文本", isPcap(new TextEncoder().encode("hello")), false);
    check("完整样本", isPcap(BASE), true);
    check("pcapng 样本", isPcap(fix.httpSessionFixture({format: "pcapng"}).bytes), true);
}

console.log("\n[3] 文件截断");
{
    // 全局头完整 + 包记录头完整 + 只留 5 字节载荷
    const cut = BASE.slice(0, 24 + 16 + 5);
    const cap = parsePcap(cut);
    check("仍解析出 1 个包", cap.packetCount, 1);
    check("载荷只剩 5 字节", cap.packets[0].data.length, 5);
    check("给出截断告警", cap.warnings.some((w) => w.includes("file appears to be truncated")), true);
    check("记录截断位置", cap.packets[0].inclLen, 5);

    // 包记录头都不完整
    const headOnly = parsePcap(BASE.slice(0, 24 + 10));
    check("没有完整包", headOnly.packetCount, 0);
    check("提示没有包记录", headOnly.warnings.some((w) => w.includes("no packet records")), true);

    // 包记录头恰好完整，但声明的长度超出剩余字节
    const noPayload = parsePcap(BASE.slice(0, 24 + 16));
    check("有包头无载荷", noPayload.packetCount, 1);
    check("载荷为空", noPayload.packets[0].data.length, 0);
    check("声明长度保留原值", noPayload.packets[0].origLen > 0, true);
}

console.log("\n[4] maxPackets 上限");
{
    const cap = parsePcap(BASE, {maxPackets: 3});
    check("只解析 3 个包", cap.packetCount, 3);
    check("记录停止位置", cap.truncatedAt, 3);
    check("告警说明上限", cap.warnings.some((w) => w.includes("Stopped after 3 packets")), true);

    const all = parsePcap(BASE);
    check("默认不限包数", all.packetCount, 11);
    check("默认不标记截断", all.truncatedAt, null);
}

console.log("\n[5] 版本警告");
{
    const bytes = new Uint8Array(BASE);
    new DataView(bytes.buffer).setUint16(4, 3, true);   // 主版本号改为 3
    const cap = parsePcap(bytes);
    check("不拒绝未知版本", cap.packetCount, 11);
    check("给出主版本告警", cap.warnings.some((w) => w.includes("Unexpected pcap major version 3")), true);
}

console.log("\n[6] 操作层错误提示");
{
    const parseOp = new ParsePcap();
    check("Parse PCAP 空输入",
        messageOf(() => parseOp.run(new ArrayBuffer(0), [10000, "Packet list"])),
        "No input data. Drop a .pcap or .pcapng capture file into the input, " +
        "or paste its bytes using a 'From Hex' operation first.");

    const filterOp = new FilterOp();
    const badExpr = messageOf(() => filterOp.run(ab(BASE), ["tcp.port ==", "Same as input"]));
    check("过滤表达式错误有前缀", badExpr.startsWith("Invalid filter expression: "), true);
    check("过滤表达式错误非空", badExpr.length > 24, true);

    const convOp = new ConvertOp();
    check("转换操作空输入",
        messageOf(() => convOp.run(new ArrayBuffer(0), ["pcapng", "Little endian", "Nanoseconds"])),
        "No input data. Drop a .pcap or .pcapng capture file into the input.");
}

console.log(`\n===== 通过 ${pass} / 失败 ${fail} =====`);
process.exitCode = fail === 0 ? 0 : 1;
