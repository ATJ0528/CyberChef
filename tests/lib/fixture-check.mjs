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

console.log("\n[1] 帧构造：以太网/IPv4/TCP 各层字段位置");
const frame = fix.tcpFrame({
    srcIp: "192.168.1.10", dstIp: "192.168.1.20",
    srcPort: 1024, dstPort: 80, seq: 1000, ack: 0, flags: 0x02,
    payload: [1, 2, 3, 4],
});
check("帧总长 = 14+20+20+4", frame.length, 58);
check("以太网类型 0x0800", [frame[12], frame[13]], [0x08, 0x00]);
check("IP 版本/IHL", frame[14], 0x45);
check("IP 总长", (frame[16] << 8) | frame[17], 44);
check("IP 协议号 (TCP)", frame[23], 6);
check("目的 IP 字节", Array.from(frame.slice(30, 34)), [192, 168, 1, 20]);
check("源 IP 字节", Array.from(frame.slice(26, 30)), [192, 168, 1, 10]);
check("TCP 源端口", (frame[34] << 8) | frame[35], 1024);
check("TCP 目的端口", (frame[36] << 8) | frame[37], 80);
check("TCP 序列号", (frame[38] * 16777216) + (frame[39] << 16) + (frame[40] << 8) + frame[41], 1000);
check("TCP 数据偏移", frame[46] >> 4, 5);
check("TCP 标志位 SYN", frame[47], 0x02);
check("TCP 载荷", Array.from(frame.slice(54)), [1, 2, 3, 4]);

console.log("\n[2] IP 校验和自校验（把校验和字段置 0 重算应得 0）");
const ipCopy = frame.slice(14, 34);
const stored = (ipCopy[10] << 8) | ipCopy[11];
ipCopy[10] = 0; ipCopy[11] = 0;
check("IP 校验和正确", fix.checksum16(ipCopy), stored);
check("校验和非零", stored !== 0, true);

console.log("\n[3] VLAN 标签帧");
const vlanFrame = fix.tcpFrame({
    srcIp: "10.0.0.1", dstIp: "10.0.0.2",
    srcPort: 1234, dstPort: 443, seq: 1, flags: 0x02, vlanId: 100,
});
check("VLAN 帧比普通帧多 4 字节", vlanFrame.length, 14 + 4 + 20 + 20);
check("外层类型 0x8100", [vlanFrame[12], vlanFrame[13]], [0x81, 0x00]);
check("TCI 含 VLAN ID 100", ((vlanFrame[14] << 8) | vlanFrame[15]) & 0x0fff, 100);
check("内层类型 0x0800", [vlanFrame[16], vlanFrame[17]], [0x08, 0x00]);

console.log("\n[4] pcap 往返");
const pkts = [frame, vlanFrame].map((d, i) => ({data: d, timestamp: 1600000000 + i * 0.5}));
const pcapBytes = fix.buildPcap(pkts, {littleEndian: true});
const cap = pcap.parsePcap(pcapBytes);
check("包数", cap.packetCount, 2);
check("时间戳 0", cap.packets[0].timestamp, 1600000000);
check("时间戳 1", cap.packets[1].timestamp, 1600000000.5);
check("数据长度 0", cap.packets[0].data.length, frame.length);
check("数据一致", Array.from(cap.packets[0].data), Array.from(frame));

const pcapBE = fix.buildPcap(pkts, {littleEndian: false, nanosecond: true});
const capBE = pcap.parsePcap(pcapBE);
check("大端解析", capBE.byteOrder, "be");
check("纳秒标志", capBE.nanosecond, true);
check("大端包数", capBE.packetCount, 2);

console.log("\n[5] pcapng 往返");
const ngBytes = fix.buildPcapng(pkts, {littleEndian: true, tsResolution: 1000000});
const ng = pcap.parsePcap(ngBytes);
check("格式", ng.format, "pcapng");
check("包数", ng.packetCount, 2);
check("接口数", ng.interfaces.length, 1);
check("时间戳 0", ng.packets[0].timestamp, 1600000000);
check("时间戳 1", ng.packets[1].timestamp, 1600000000.5);
check("数据一致", Array.from(ng.packets[0].data), Array.from(frame));
check("无警告", ng.warnings.length, 0);

const ngBE = fix.buildPcapng(pkts, {littleEndian: false});
const ngB = pcap.parsePcap(ngBE);
check("大端 pcapng 端序", ngB.byteOrder, "be");
check("大端 pcapng 包数", ngB.packetCount, 2);
check("大端 pcapng 时间戳", ngB.packets[0].timestamp, 1600000000);

const ngNs = fix.buildPcapng(pkts, {tsResolution: 1000000000});
const ngN = pcap.parsePcap(ngNs);
check("纳秒分辨率 pcapng", ngN.interfaces[0].tsResolution, 1000000000);
check("纳秒分辨率时间戳", ngN.packets[1].timestamp, 1600000000.5);

console.log("\n[6] HTTP 会话夹具");
const sess = fix.httpSessionFixture();
check("包数 (含握手)", sess.meta.packetCount, 11);
const sessCap = pcap.parsePcap(sess.bytes);
check("可解析包数", sessCap.packetCount, 11);
check("无警告", sessCap.warnings.length, 0);
check("时长 > 0", sessCap.duration > 0, true);

const sessNoHandshake = fix.httpSessionFixture({includeHandshake: false});
check("不含握手包数", sessNoHandshake.meta.packetCount, 8);

const sessNg = fix.httpSessionFixture({format: "pcapng"});
const sessNgCap = pcap.parsePcap(sessNg.bytes);
check("pcapng 会话格式", sessNgCap.format, "pcapng");
check("pcapng 会话包数", sessNgCap.packetCount, 11);

console.log("\n[7] hex 输出可用于 From Hex");
check("hex 长度为偶数", sess.hex.length % 2, 0);
check("hex 是小写", sess.hex === sess.hex.toLowerCase(), true);

console.log(`\n===== 通过 ${pass} / 失败 ${fail} =====`);
process.exit(fail ? 1 : 0);
