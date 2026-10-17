/**
 * 写出能力往返测试：parse → write → parse，验证字节级还原。
 */
import {pathToFileURL, fileURLToPath} from "node:url";
import path from "node:path";

const P = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fix = await import(pathToFileURL(`${P}/tests/lib/PcapFixtures.mjs`).href);
const pcap = await import(pathToFileURL(`${P}/src/core/lib/Pcap.mjs`).href);

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
const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

const sess = fix.httpSessionFixture();

console.log("\n[1] pcap 往返");
{
    const c1 = pcap.parsePcap(sess.bytes);
    const out = pcap.writePcap(c1);
    const c2 = pcap.parsePcap(out);

    check("重写后可识别为 pcap", pcap.isPcap(out), true);
    check("格式", c2.format, "pcap");
    check("包数一致", c2.packetCount, c1.packetCount);
    check("链路类型一致", c2.linkType, c1.linkType);
    check("端序一致", c2.byteOrder, c1.byteOrder);
    check("无警告", c2.warnings.length, 0);
    check("全部包逐字节一致",
        c2.packets.every((p, i) => sameBytes(p.data, c1.packets[i].data)), true);
    check("全部时间戳一致（微秒精度）",
        c2.packets.every((p, i) => Math.abs(p.timestamp - c1.packets[i].timestamp) < 1e-6), true);
    check("origLen 保留", c2.packets[0].origLen, c1.packets[0].origLen);
}

console.log("\n[2] pcapng 往返");
{
    const ng = fix.httpSessionFixture({format: "pcapng"});
    const c1 = pcap.parsePcap(ng.bytes);
    const out = pcap.writePcapng(c1);
    const c2 = pcap.parsePcap(out);

    check("格式", c2.format, "pcapng");
    check("包数一致", c2.packetCount, 11);
    check("接口数一致", c2.interfaces.length, c1.interfaces.length);
    check("接口链路类型", c2.interfaces[0].linkType, c1.interfaces[0].linkType);
    check("无警告", c2.warnings.length, 0);
    check("全部包逐字节一致",
        c2.packets.every((p, i) => sameBytes(p.data, c1.packets[i].data)), true);
    // 容差取 1 微秒（源文件本身的分辨率）。注意不能取 1e-9：
    // float64 在 1.6e9 附近的表示间隔约 4.8e-7 秒，比 1 纳秒大近 500 倍，
    // 那样的容差在数学上就不可能满足。
    check("全部时间戳一致（源分辨率 1 微秒）",
        c2.packets.every((p, i) => Math.abs(p.timestamp - c1.packets[i].timestamp) < 1e-6), true);
}

console.log("\n[3] 跨格式转换 pcap → pcapng → pcap");
{
    const c1 = pcap.parsePcap(sess.bytes);
    const ngBytes = pcap.writePcapng(c1);
    const back = pcap.writePcap(pcap.parsePcap(ngBytes), {littleEndian: true});
    const c3 = pcap.parsePcap(back);
    check("三次转换后包数不变", c3.packetCount, 11);
    check("三次转换后数据不变",
        c3.packets.every((p, i) => sameBytes(p.data, c1.packets[i].data)), true);
}

console.log("\n[4] 子集写出（过滤场景）");
{
    const c1 = pcap.parsePcap(sess.bytes);
    const subset = c1.packets.filter(p => p.data.length > 60);
    check("子集非空且少于全部", subset.length > 0 && subset.length < c1.packetCount, true);

    const out = pcap.writePcap(c1, {packets: subset});
    const c2 = pcap.parsePcap(out);
    check("只写出子集", c2.packetCount, subset.length);
    check("子集数据一致",
        c2.packets.every((p, i) => sameBytes(p.data, subset[i].data)), true);
    check("子集时间戳一致",
        c2.packets.every((p, i) => Math.abs(p.timestamp - subset[i].timestamp) < 1e-6), true);
}

console.log("\n[5] 大端写出与强制端序");
{
    const c1 = pcap.parsePcap(sess.bytes);
    const beBytes = pcap.writePcap(c1, {littleEndian: false});
    const c2 = pcap.parsePcap(beBytes);
    check("写出为大端", c2.byteOrder, "be");
    check("大端重写后可解析", c2.packetCount, 11);
    check("数据不变",
        c2.packets.every((p, i) => sameBytes(p.data, c1.packets[i].data)), true);

    const nsBytes = pcap.writePcap(c1, {littleEndian: true, nanosecond: true});
    const c3 = pcap.parsePcap(nsBytes);
    check("纳秒标志", c3.nanosecond, true);
    check("纳秒时间戳一致",
        c3.packets.every((p, i) => Math.abs(p.timestamp - c1.packets[i].timestamp) < 1e-9), true);
}

console.log("\n[6] 边界：空抓包");
{
    const empty = pcap.writePcap(pcap.parsePcap(pcap.writePcap({
        byteOrder: "le", nanosecond: false, snaplen: 65535,
        linkType: 1, packets: [], format: "pcap", warnings: [], interfaces: [],
    })));
    const c = pcap.parsePcap(empty);
    check("空抓包写出后可解析", c.packetCount, 0);
    check("空抓包有警告", c.warnings.length > 0, true);

    // 非 4 字节对齐的载荷，验证 pcapng 的补零逻辑
    const oddPkt = {data: new Uint8Array([1, 2, 3]), timestamp: 1600000000, origLen: 3, linkType: 1};
    const ngOut = pcap.writePcapng({byteOrder: "le", packets: [oddPkt], snaplen: 65535, linkType: 1});
    const cOdd = pcap.parsePcap(ngOut);
    check("奇数长度包可往返", cOdd.packetCount, 1);
    check("奇数长度数据完好", Array.from(cOdd.packets[0].data), [1, 2, 3]);
}

console.log(`\n===== 通过 ${pass} / 失败 ${fail} =====`);
process.exit(fail ? 1 : 0);
