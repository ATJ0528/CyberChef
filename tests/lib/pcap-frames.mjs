/**
 * 链路层 / 网络层帧构造与解析测试。
 *
 * 覆盖 IPv6 地址编码、IPv6 首部、802.1Q VLAN 标签，
 * 以及"非 IP 的以太网类型（ARP）不继续解析网络层"这一约定。
 */
import {pathToFileURL, fileURLToPath} from "node:url";
import path from "node:path";

const P = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const fix = await import(pathToFileURL(`${P}/tests/lib/PcapFixtures.mjs`).href);
const {parsePcap} = await import(pathToFileURL(`${P}/src/core/lib/Pcap.mjs`).href);
const {dissectCapture} = await import(pathToFileURL(`${P}/src/core/lib/PcapPacket.mjs`).href);

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

const enc = (s) => new TextEncoder().encode(s);

/**
 * 把一帧包进 pcap 容器并解包。
 *
 * @param {Uint8Array} frame - 完整链路层帧
 * @returns {Object} 解包结果
 */
function dissectOne(frame) {
    const cap = parsePcap(fix.buildPcap([{data: frame, timestamp: 1600000000.25}]));
    return dissectCapture(cap)[0];
}

console.log("\n[1] IPv6 地址编码");
{
    const loopback = fix.ipv6Bytes("::1");
    check("::1 长度", loopback.length, 16);
    check("::1 只有最后一字节为 1", Array.from(loopback), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    const full = fix.ipv6Bytes("1:2:3:4:5:6:7:8");
    check("完整写法 16 字节", full.length, 16);
    check("完整写法首组", [full[0], full[1]], [0, 1]);
    check("完整写法末组", [full[14], full[15]], [0, 8]);

    const compressed = fix.ipv6Bytes("2001:db8::1");
    check("压缩写法长度", compressed.length, 16);
    check("压缩写法前缀", [compressed[0], compressed[1], compressed[2], compressed[3]], [0x20, 0x01, 0x0d, 0xb8]);
    check("压缩写法末字节", compressed[15], 1);

    const embedded = fix.ipv6Bytes("::ffff:192.168.1.1");
    check("内嵌 IPv4 末四字节", Array.from(embedded.slice(12)), [192, 168, 1, 1]);

    let bad = "";
    try {
        fix.ipv6Bytes("2001:db8:::1");
    } catch (err) {
        bad = err.message;
    }
    check("多重 :: 报错", bad.startsWith("Invalid IPv6 address:"), true);
}

console.log("\n[2] IPv6 + TCP 帧");
{
    const frame = fix.tcpFrame6({
        srcIp: "2001:db8::1", dstIp: "2001:db8::2",
        srcPort: 50000, dstPort: 443,
        seq: 1000, ack: 2000, flags: 0x18,
        payload: enc("hello over ipv6"),
    });
    const p = dissectOne(frame);

    check("链路层类型", p.link.etherType, 0x86dd);
    check("以太网首部长度", p.link.headerLength, 14);
    check("网络层版本", p.network.version, 6);
    check("源地址（含 :: 压缩）", p.network.src, "2001:db8::1");
    check("目的地址（含 :: 压缩）", p.network.dst, "2001:db8::2");
    check("网络层协议号为 TCP", p.network.protocol, 6);
    check("跳数限制", p.network.hopLimit, 64);
    check("载荷长度", p.network.payloadLength, 20 + enc("hello over ipv6").length);
    check("传输层协议", p.transport.protocol, "TCP");
    check("源端口", p.transport.srcPort, 50000);
    check("目的端口", p.transport.dstPort, 443);
    check("负载内容", Buffer.from(p.payload).toString("utf8"), "hello over ipv6");
    check("未截断", p.truncated, false);
}

console.log("\n[3] 802.1Q VLAN 标签");
{
    const p4 = dissectOne(fix.tcpFrame({
        srcIp: "192.168.1.10", dstIp: "93.184.216.34",
        srcPort: 49152, dstPort: 80,
        seq: 1, flags: 0x02, vlanId: 100,
    }));
    check("剥掉一层 VLAN", p4.link.vlan.length, 1);
    check("VLAN ID", p4.link.vlan[0].id, 100);
    check("VLAN 后的以太网类型", p4.link.etherType, 0x0800);
    check("以太网首部含标签", p4.link.headerLength, 18);
    check("仍能解析 IPv4", p4.network.src, "192.168.1.10");
    check("TCP 端口", p4.transport.dstPort, 80);

    const p6 = dissectOne(fix.tcpFrame6({
        srcIp: "2001:db8::1", dstIp: "2001:db8::2",
        srcPort: 50000, dstPort: 443,
        seq: 1, flags: 0x02, vlanId: 200,
    }));
    check("VLAN + IPv6 的 VLAN ID", p6.link.vlan[0].id, 200);
    check("VLAN + IPv6 的以太网类型", p6.link.etherType, 0x86dd);
    check("VLAN + IPv6 仍能解析地址", p6.network.src, "2001:db8::1");
}

console.log("\n[4] 非 IP 的以太网类型（ARP）");
{
    const eth = fix.concat(
        fix.macBytes("ff:ff:ff:ff:ff:ff"),
        fix.macBytes("66:77:88:99:aa:bb"),
        new Uint8Array([0x08, 0x06])          // ARP
    );
    const arp = new Uint8Array(28);           // ARP 报文体，内容不影响解包
    const p = dissectOne(fix.concat(eth, arp));

    check("以太网类型为 ARP", p.link.etherType, 0x0806);
    check("不继续解析网络层", p.network, null);
    check("也不解析传输层", p.transport, null);
    check("类型名可读", p.link.etherTypeName, "ARP");
}

console.log(`\n===== 通过 ${pass} / 失败 ${fail} =====`);
process.exitCode = fail === 0 ? 0 : 1;
