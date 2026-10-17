/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2022
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— TCP 首部解析
 * 【操作】Parse TCP
 * 【功能】解析 TCP 报文的首部（含可变长 Options）与载荷，产出结构化对象
 * 【输入】string —— Hex 串或 Raw 原始字符流（由 "Input format" 参数决定）
 * 【输出】json —— run() 返回对象，框架再调用 present() 渲染成 HTML 表格
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 按 "Input format" 归一化为字节数组（Hex → fromHex；Raw → strToArrayBuffer）
 *   2. 用 Stream 顺序读取；不足 20 字节（TCP 最小首部）则报错
 *   3. 依次读源端口、目的端口、序列号、确认号、Data offset、标志位、窗口、校验和、紧急指针
 *   4. 若 Data offset > 5，说明带 Options，按首部实际长度循环解析每个选项
 *   5. 仍有剩余字节则作为 Data（以 0x 前缀十六进制呈现）
 *   6. 事后修饰：Data offset 换算为字节数；窗口大小按 Window Scale 选项放大后展示
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 32 位无符号序列号：JS 的 `<<`/`|` 按 32 位有符号处理，超过 2^31 会溢出为负数，
 *     故序列号用 bytesToLargeNumber()（内部 BigNumber）而非位运算拼接
 *   - 半字节/位域拆分：Data offset（4 位）与 Reserved（3 位）、NS（1 位）共处第 13 个字节，
 *     后续 8 个标志位（CWR/ECE/URG/ACK/PSH/RST/SYN/FIN）位于第 14 个字节；
 *     Stream.readBits(n) 按位连续读取，自动跨字节推进
 *   - 窗口缩放：真实窗口 = 窗口字段 × 2^shift，shift 由 Window Scale 选项（Kind=3）给出，
 *     用 BigNumber 的 multipliedBy / pow 计算避免精度丢失
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - Options 解析由 IANA 查表 TCP_OPTION_KIND_LOOKUP 驱动：表项 length 标志决定是否还有
 *     长度字节，可选 parser 决定 Value 如何解析，使新增选项只需改表
 *   - present() 统一委托 objToTable()，解析逻辑与呈现逻辑解耦
 * ============================================================
 */

import Operation from "../Operation.mjs";
import Stream from "../lib/Stream.mjs";
import {toHexFast, fromHex} from "../lib/Hex.mjs";
import {toBinary} from "../lib/Binary.mjs";
import {objToTable, bytesToLargeNumber} from "../lib/Protocol.mjs";
import Utils from "../Utils.mjs";
import OperationError from "../errors/OperationError.mjs";
import BigNumber from "bignumber.js";

/**
 * Parse TCP operation
 *
 * 继承自 Operation 基类。run() 产出结构化对象，由 present() 统一渲染为表格。
 */
class ParseTCP extends Operation {

    /**
     * 构造函数 —— 声明元信息与参数
     *
     * inputType   = "string" 框架先把 Dish 转成字符串再交给 run()
     * outputType  = "json"   run() 返回对象时框架不做表格化
     * presentType = "html"   框架随后调用 present() 把 json 渲染为 HTML
     * args[0] Input format —— 选项：Hex / Raw，决定输入如何解码
     */
    constructor() {
        super();

        this.name = "Parse TCP";
        this.module = "Default";
        this.description = "Parses a TCP header and payload (if present).";
        this.infoURL = "https://wikipedia.org/wiki/Transmission_Control_Protocol";
        this.inputType = "string";
        this.outputType = "json";
        this.presentType = "html";
        this.args = [
            {
                name: "Input format",
                type: "option",
                value: ["Hex", "Raw"]
            }
        ];
    }

    /**
     * 【主流程】解析 TCP 首部、选项与载荷
     *
     * 参数 args[0] = 输入格式（Hex / Raw）
     * 返回值：结构化 TCPPacket 对象（由框架交给 present() 渲染）
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {html}
     */
    run(input, args) {
        const format = args[0];

        // --- 步骤 1：输入归一化 ---
        if (format === "Hex") {
            input = fromHex(input);
        } else if (format === "Raw") {
            input = Utils.strToArrayBuffer(input);
        } else {
            throw new OperationError("Unrecognised input format.");
        }

        // --- 步骤 2：用 Stream 包装并从长度上做最小首部校验（20 字节）---
        const s = new Stream(new Uint8Array(input));
        if (s.length < 20) {
            throw new OperationError("Need at least 20 bytes for a TCP Header");
        }

        // --- 步骤 3：顺序读取固定首部各字段 ---
        // 注意：序列号用 bytesToLargeNumber（BigNumber）承担 32 位无符号语义，
        // 因为 JS 位运算按 32 位有符号处理，直接拼接会在 >2^31 时溢出为负数
        const TCPPacket = {
            "Source port": s.readInt(2),
            "Destination port": s.readInt(2),
            "Sequence number": bytesToLargeNumber(s.getBytes(4)),
            "Acknowledgement number": s.readInt(4),
            "Data offset": s.readBits(4),
            // 位域说明：Data offset(4) + Reserved(3) + NS(1) 恰好拼满第 13 字节；
            // 紧接着的 CWR…FIN 共 8 位构成第 14 字节，故此处按位连续读取不会错位
            "Flags": {
                "Reserved": toBinary(s.readBits(3), "", 3),
                "NS": s.readBits(1),
                "CWR": s.readBits(1),
                "ECE": s.readBits(1),
                "URG": s.readBits(1),
                "ACK": s.readBits(1),
                "PSH": s.readBits(1),
                "RST": s.readBits(1),
                "SYN": s.readBits(1),
                "FIN": s.readBits(1),
            },
            "Window size": s.readInt(2),
            "Checksum": "0x" + toHexFast(s.getBytes(2)),
            "Urgent pointer": "0x" + toHexFast(s.getBytes(2))
        };

        // --- 步骤 4：若 Data offset > 5，则首部含 Options，逐个解析 ---
        let windowScaleShift = 0;
        if (TCPPacket["Data offset"] > 5) {
            // Options 区字节数 = 首部总长（Data offset × 4）− 20 字节固定部分
            let remainingLength = TCPPacket["Data offset"] * 4 - 20;

            const options = {};
            while (remainingLength > 0) {
                const option = {
                    "Kind": s.readInt(1)
                };

                let opt = { name: "Reserved", length: true };
                if (Object.prototype.hasOwnProperty.call(TCP_OPTION_KIND_LOOKUP, option.Kind)) {
                    opt = TCP_OPTION_KIND_LOOKUP[option.Kind];
                }

                // Add Length and Value fields
                if (opt.length) {
                    option.Length = s.readInt(1);

                    if (option.Length > 2) {
                        if (Object.prototype.hasOwnProperty.call(opt, "parser")) {
                            option.Value = opt.parser(s.getBytes(option.Length - 2));
                        } else {
                            option.Value = option.Length <= 6 ?
                                s.readInt(option.Length - 2):
                                "0x" + toHexFast(s.getBytes(option.Length - 2));
                        }

                        // Store Window Scale shift for later
                        if (option.Kind === 3 && option.Value) {
                            windowScaleShift = option.Value["Shift count"];
                        }
                    }
                }
                options[opt.name] = option;

                const length = option.Length || 1;
                remainingLength -= length;
            }
            TCPPacket.Options = options;
        }

        // --- 步骤 5：首部之后若还有字节，即为 TCP 载荷 Data ---
        if (s.hasMore()) {
            TCPPacket.Data = "0x" + toHexFast(s.getBytes());
        }

        // --- 步骤 6：修饰展示值 ---
        // Data offset 单位为 4 字节（32 位字），×4 换算成字节数一并展示
        TCPPacket["Data offset"] = `${TCPPacket["Data offset"]} (${TCPPacket["Data offset"] * 4} bytes)`;
        // 真实窗口 = 窗口字段 × 2^shift（shift 来自 Window Scale 选项），
        // 用 BigNumber 计算大数幂与乘法，避免 32 位精度问题
        const trueWndSize = BigNumber(TCPPacket["Window size"]).multipliedBy(BigNumber(2).pow(BigNumber(windowScaleShift)));
        TCPPacket["Window size"] = `${TCPPacket["Window size"]} (Scaled: ${trueWndSize})`;

        return TCPPacket;
    }

    /**
     * 呈现钩子 —— run() 返回 json 后由框架调用，把结构化对象渲染为 HTML 表格
     * @param {Object} data
     * @returns {html}
     */
    present(data) {
        return objToTable(data);
    }

}

// 选项 Kind → 元信息查表：name 为展示名；length 表示该选项是否含长度字节；
// 可选 parser 指定 Value 的特殊解析函数（未提供时按长度读数值或十六进制）
// Taken from https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
// on 2022-05-30
const TCP_OPTION_KIND_LOOKUP = {
    0: { name: "End of Option List", length: false },
    1: { name: "No-Operation", length: false },
    2: { name: "Maximum Segment Size", length: true },
    3: { name: "Window Scale", length: true, parser: windowScaleParser },
    4: { name: "SACK Permitted", length: true },
    5: { name: "SACK", length: true },
    6: { name: "Echo (obsoleted by option 8)", length: true },
    7: { name: "Echo Reply (obsoleted by option 8)", length: true },
    8: { name: "Timestamps", length: true, parser: tcpTimestampParser },
    9: { name: "Partial Order Connection Permitted (obsolete)", length: true },
    10: { name: "Partial Order Service Profile (obsolete)", length: true },
    11: { name: "CC (obsolete)", length: true },
    12: { name: "CC.NEW (obsolete)", length: true },
    13: { name: "CC.ECHO (obsolete)", length: true },
    14: { name: "TCP Alternate Checksum Request (obsolete)", length: true, parser: tcpAlternateChecksumParser },
    15: { name: "TCP Alternate Checksum Data (obsolete)", length: true },
    16: { name: "Skeeter", length: true },
    17: { name: "Bubba", length: true },
    18: { name: "Trailer Checksum Option", length: true },
    19: { name: "MD5 Signature Option (obsoleted by option 29)", length: true },
    20: { name: "SCPS Capabilities", length: true },
    21: { name: "Selective Negative Acknowledgements", length: true },
    22: { name: "Record Boundaries", length: true },
    23: { name: "Corruption experienced", length: true },
    24: { name: "SNAP", length: true },
    25: { name: "Unassigned (released 2000-12-18)", length: true },
    26: { name: "TCP Compression Filter", length: true },
    27: { name: "Quick-Start Response", length: true },
    28: { name: "User Timeout Option (also, other known unauthorized use)", length: true },
    29: { name: "TCP Authentication Option (TCP-AO)", length: true },
    30: { name: "Multipath TCP (MPTCP)", length: true },
    69: { name: "Encryption Negotiation (TCP-ENO)", length: true },
    70: { name: "Reserved (known unauthorized use without proper IANA assignment)", length: true },
    76: { name: "Reserved (known unauthorized use without proper IANA assignment)", length: true },
    77: { name: "Reserved (known unauthorized use without proper IANA assignment)", length: true },
    78: { name: "Reserved (known unauthorized use without proper IANA assignment)", length: true },
    253: { name: "RFC3692-style Experiment 1 (also improperly used for shipping products) ", length: true },
    254: { name: "RFC3692-style Experiment 2 (also improperly used for shipping products) ", length: true }
};

/**
 * 私有辅助 —— 解析 TCP Alternate Checksum Request 选项的值
 *
 * 输入：选项 Value 字节（首字节为校验算法编号）
 * 输出：算法名 + 原始十六进制，编号不在表内则显示 undefined
 * @param {Uint8Array} data
 */
function tcpAlternateChecksumParser(data) {
    const lookup = {
        0: "TCP Checksum",
        1: "8-bit Fletchers's algorithm",
        2: "16-bit Fletchers's algorithm",
        3: "Redundant Checksum Avoidance"
    }[data[0]];

    return `${lookup} (0x${toHexFast(data)})`;
}

/**
 * 私有辅助 —— 解析 TCP Timestamps 选项的值
 *
 * 输入：8 字节 Value（前 4 字节 TSval，后 4 字节 TSecr）
 * 输出：{ "Current Timestamp", "Echo Reply" }；长度不符则返回错误说明字符串。
 * 两个时间戳均为 32 位无符号数，故同样用 bytesToLargeNumber 处理
 * @param {Uint8Array} data
 */
function tcpTimestampParser(data) {
    const s = new Stream(data);

    if (s.length !== 8)
        return `Error: Timestamp field should be 8 bytes long (received 0x${toHexFast(data)})`;

    const tsval = bytesToLargeNumber(s.getBytes(4)),
        tsecr = bytesToLargeNumber(s.getBytes(4));

    return {
        "Current Timestamp": tsval,
        "Echo Reply": tsecr
    };
}

/**
 * 私有辅助 —— 解析 Window Scale 选项的值
 *
 * 输入：1 字节 Value（即移位位数 shift）
 * 输出：{ "Shift count": shift, "Multiplier": 1 << shift }；长度不符返回错误说明字符串。
 * 该 shift 会回传到 run() 用于放大窗口字段
 * @param {Uint8Array} data
 */
function windowScaleParser(data) {
    if (data.length !== 1)
        return `Error: Window Scale should be one byte long (received 0x${toHexFast(data)})`;

    return {
        "Shift count": data[0],
        "Multiplier": 1 << data[0]
    };
}

export default ParseTCP;
