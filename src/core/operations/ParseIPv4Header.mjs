/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— IPv4 首部解析
 * 【操作】Parse IPv4 header
 * 【功能】把一段原始 IPv4 报文（RFC 791 首部）拆解成可读的字段表
 * 【输入】string —— Hex 串（如 "4500003c..."）或 Raw 原始字符流
 * 【输出】html —— 字段表格；或按参数输出纯载荷（Data hex / Data raw）
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 按参数 "Input format" 把入参归一化为字节序列
 *        Hex → fromHex()；Raw → UTF-8 拆字节
 *   2. 按 RFC 791 固定 20 字节首部做位运算解包（版本/长度/TTL/协议/校验和/地址…）
 *   3. 合法性校验：Version 必须为 4；IHL 必须 ≥ 5
 *   4. 依 IHL 计算首部真实长度，切出可变长 Options 与载荷 Data
 *   5. 用协议号查表得传输层协议名；重算首部校验和并与报文中的值比对
 *   6. 按参数 "Output format" 渲染为 HTML 表格或裸数据
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 大端解包：`input[2] << 8 | input[3]` 这类移位拼接，两字节一次成值，
 *     避免逐字节循环，是解析二进制协议的通用范式
 *   - 半字节位域：首个字节高 4 位是 Version、低 4 位是 IHL，
 *     分别用 `>>> 4` 与 `& 0x0f` 取出
 *   - 校验和自校验：把原报文的校验和字段清零后重算，与报文原值比对，
 *     与 TCP/IP 校验和操作（TCPIPChecksum）复用同一实现
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 非法字段不抛异常，而是把错误说明**拼到字段值里**（如 "5 (Error: ...)"），
 *     让操作在容错模式下仍能输出尽可能多的可用信息，便于人工研判畸形包
 *   - `input.slice(ihl * 4)` 直接得到载荷，无需手工算偏移
 * ============================================================
 */

import Operation from "../Operation.mjs";
import Utils from "../Utils.mjs";
import OperationError from "../errors/OperationError.mjs";
import {fromHex, toHex} from "../lib/Hex.mjs";
import {ipv4ToStr, protocolLookup} from "../lib/IP.mjs";
import TCPIPChecksum from "./TCPIPChecksum.mjs";

/**
 * Parse IPv4 header operation
 *
 * 继承自 Operation 基类。只需实现 run()，在构造函数里声明
 * 元信息（名称、描述、输入输出类型、参数列表），
 * 其余（参数校验、类型转换、结果呈现）由框架统一处理。
 */
class ParseIPv4Header extends Operation {

    /**
     * 构造函数 —— 声明本操作的元信息与参数
     *
     * inputType  = "string" 表示框架会先把 Dish 转成字符串再交给 run()
     * outputType = "html"   表示 run() 的返回值会被当作 HTML 片段渲染
     * args 中每个元素对应界面上一个输入控件：
     *   [0] Input format  —— 选项：Hex / Raw，决定输入如何解码
     *   [1] Output format —— 选项：Table / Data (hex) / Data (raw)，决定输出形态
     */
    constructor() {
        super();

        this.name = "Parse IPv4 header";
        this.module = "Default";
        this.description = "Given an IPv4 header, this operations parses and displays each field in an easily readable format.";
        this.infoURL = "https://wikipedia.org/wiki/IPv4#Header";
        this.inputType = "string";
        this.outputType = "html";
        this.args = [
            {
                "name": "Input format",
                "type": "option",
                "value": ["Hex", "Raw"]
            },
            {
                "name": "Output format",
                "type": "option",
                "value": ["Table", "Data (hex)", "Data (raw)"],
                defaultIndex: 0,
            }
        ];
    }

    /**
     * 【主流程】解析 IPv4 首部
     *
     * 参数 args[0] = 输入格式，args[1] = 输出格式
     * 返回值：outputFormat 为 Table 时返回 HTML 表格字符串，否则返回纯数据串
     *
     * @param {string} input - Hex 或 Raw 形式的 IPv4 报文
     * @param {Object[]} args - 操作参数（见构造函数注释）
     * @returns {html}
     */
    run(input, args) {
        const format = args[0];
        const outputFormat = args[1];

        let output;

        // --- 步骤 1：输入归一化，统一转成可按下标取字节的 Uint8Array ---
        if (format === "Hex") {
            input = fromHex(input);
        } else if (format === "Raw") {
            input = new Uint8Array(Utils.strToArrayBuffer(input));
        } else {
            throw new OperationError("Unrecognised input format.");
        }

        // --- 步骤 2：按 RFC 791 逐字段位运算解包（大端序）---
        // 每两字节用 `<< 8 |` 拼成一个 16 位值；跨字节的位域用掩码拆分
        let ihl = input[0] & 0x0f;
        const dscp = (input[1] >>> 2) & 0x3f,
            ecn = input[1] & 0x03,
            length = input[2] << 8 | input[3],
            identification = input[4] << 8 | input[5],
            flags = (input[6] >>> 5) & 0x07,
            fragOffset = (input[6] & 0x1f) << 8 | input[7],
            ttl = input[8],
            protocol = input[9],
            checksum = input[10] << 8 | input[11],
            srcIP = input[12] << 24 | input[13] << 16 | input[14] << 8 | input[15],
            dstIP = input[16] << 24 | input[17] << 16 | input[18] << 8 | input[19],
            checksumHeader = [...input.slice(0, 10), 0, 0, ...input.slice(12, 20)];
        let version = (input[0] >>> 4) & 0x0f,
            options = [];


        // --- 步骤 3：字段合法性校验 ---
        // 注意这里不抛异常，而是把错误说明拼进字段值，保证畸形包仍能尽可能多地展示信息

        // Version：IPv4 报文该位域恒为 4
        if (version !== 4) {
            version = version + " (Error: for IPv4 headers, this should always be set to 4)";
        }

        // IHL：以 4 字节为单位，最小值 5（即 20 字节固定首部）；大于 5 说明带 Options
        if (ihl < 5) {
            ihl = ihl + " (Error: this should always be at least 5)";
        } else if (ihl > 5) {
            // 首部长度 = IHL × 4 字节，减去 20 字节固定部分即 Options 长度
            const optionsLen = ihl * 4 - 20;
            options = input.slice(20, optionsLen + 20);
        }

        // 【查表】协议号 → 传输层协议名（TCP=6 / UDP=17 / ICMP=1 …），查不到则留空
        const protocolInfo = protocolLookup[protocol] || {keyword: "", protocol: ""};

        // --- 步骤 5：首部校验和自校验 ---
        // checksumHeader 已在解包时把校验和字段（第 11、12 字节）置 0，
        // 复用 TCPIPChecksum 操作重算后与报文原值比对
        const correctChecksum = (new TCPIPChecksum).run(checksumHeader),
            givenChecksum = Utils.hex(checksum);
        let checksumResult;
        if (correctChecksum === givenChecksum) {
            checksumResult = givenChecksum + " (correct)";
        } else {
            checksumResult = givenChecksum + " (incorrect, should be " + correctChecksum + ")";
        }

        // --- 步骤 4：首部之后即为载荷，偏移量 = IHL × 4 ---
        const data = input.slice(ihl * 4);

        // --- 步骤 6：按 Output format 渲染结果 ---
        if (outputFormat === "Table") {
            output = `<table class='table table-hover table-sm table-bordered table-nonfluid'><tr><th>Field</th><th>Value</th></tr>
<tr><td>Version</td><td>${version}</td></tr>
<tr><td>Internet Header Length (IHL)</td><td>${ihl} (${ihl * 4} bytes)</td></tr>
<tr><td>Differentiated Services Code Point (DSCP)</td><td>${dscp}</td></tr>
<tr><td>Explicit Congestion Notification (ECN)</td><td>${ecn}</td></tr>
<tr><td>Total length</td><td>${length} bytes
  IP header: ${ihl * 4} bytes
  Data: ${length - ihl * 4} bytes</td></tr>
<tr><td>Identification</td><td>0x${Utils.hex(identification)} (${identification})</td></tr>
<tr><td>Flags</td><td>0x${Utils.hex(flags, 2)}
  Reserved bit:${flags >> 2} (must be 0)
  Don't fragment:${flags >> 1 & 1}
  More fragments:${flags & 1}</td></tr>
<tr><td>Fragment offset</td><td>${fragOffset}</td></tr>
<tr><td>Time-To-Live</td><td>${ttl}</td></tr>
<tr><td>Protocol</td><td>${protocol}, ${protocolInfo.protocol} (${protocolInfo.keyword})</td></tr>
<tr><td>Header checksum</td><td>${checksumResult}</td></tr>
<tr><td>Source IP address</td><td>${ipv4ToStr(srcIP)}</td></tr>
<tr><td>Destination IP address</td><td>${ipv4ToStr(dstIP)}</td></tr>
<tr><td>Data (hex)</td><td>${toHex(data)}</td></tr>`;

            if (ihl > 5) {
                output += `<tr><td>Options</td><td>${toHex(options)}</td></tr>`;
            }

            return output + "</table>";
        } else if (outputFormat === "Data (hex)") {
            return toHex(data);
        } else if (outputFormat === "Data (raw)") {
            return Utils.escapeHtml(Utils.byteArrayToChars(data));
        }
    }

}

export default ParseIPv4Header;
