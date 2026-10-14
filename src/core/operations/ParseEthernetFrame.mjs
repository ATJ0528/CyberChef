/**
 * @author tedk [tedk@ted.do]
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 以太网帧解析
 * 【操作】Parse Ethernet frame
 * 【功能】解析以太网帧（Ethernet frame）首部，取出目的/源 MAC 地址与 VLAN 标签，并可按需返回帧载荷
 * 【输入】string —— Raw 原始字符流，或 Hex 字符串（由 "Input type" 参数决定）
 * 【输出】html —— "Text output" 下为可读字段清单；"Packet data" / "Packet data (hex)" 下为帧载荷
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 按 "Input type" 把入参归一化为 Uint8Array（Hex → fromHex；Raw → UTF-8 拆字节）
 *   2. 取前 6 字节为目的 MAC、第 6~11 字节为源 MAC
 *   3. 从偏移 12 开始读 2 字节 EtherType（以太网类型字段）
 *   4. 若 EtherType 为 0x8100（802.1Q）或 0x88A8（802.1ad），
 *      则再读 2 字节 VLAN tag 记录 VLAN ID，并继续循环以支持嵌套 VLAN（QinQ 标签栈）
 *   5. 遇到非 VLAN 的 EtherType 即 break，其后所有字节即帧载荷 packetData
 *   6. 按 "Return type" 参数渲染为文本清单或裸载荷
 * ------------------------------------------------------------
 * 【关键算法】
 *   - VLAN tag 位域拆分：2 字节 tag 中，高 4 位为 PRIO（优先级，本例忽略）、
 *     第 5~8 位为 DEI（丢弃资格，忽略）、低 12 位为 VLAN ID，
 *     故 VLAN ID = (tag[0] & 0b00001111) << 8 | tag[1]
 *   - 大端 EtherType 比较：先用 byteArrayToChars 把两字节还原成 "\x81\x00" 形式字符串，
 *     再与字面量直接比较，规避手工 `<< 8 |` 拼接
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 用 toHex(bytes, ":") 一步把 MAC 格式化成 "aa:bb:cc:dd:ee:ff"
 *   - VLAN 解析放在 while 循环内，天然支持多层 VLAN 标签栈而无需额外分支
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Utils from "../Utils.mjs";
import {fromHex, toHex} from "../lib/Hex.mjs";

/**
 * Parse Ethernet frame operation
 *
 * 继承自 Operation 基类。只需实现 run()，在构造函数声明元信息与参数列表，
 * 参数校验与结果呈现由框架统一处理。
 */
class ParseEthernetFrame extends Operation {

    /**
     * 构造函数 —— 声明元信息与参数
     *
     * inputType  = "string" 表示框架先把 Dish 转成字符串再交给 run()
     * outputType = "html"   表示 run() 返回值按 HTML 片段呈现
     * args 中每个元素对应界面一个输入控件：
     *   [0] Input type  —— 选项：Raw / Hex，决定输入如何解码
     *   [1] Return type —— 选项：Text output / Packet data / Packet data (hex)
     */
    constructor() {
        super();

        this.name = "Parse Ethernet frame";
        this.module = "Default";
        this.description = "Parses an Ethernet frame and either shows the deduced values (Source and destination MAC, VLANs) or returns the packet data.<br /><br />Good for use in conjunction with the Parse IPv4, and Parse TCP/UDP recipes.";
        this.infoURL = "https://en.wikipedia.org/wiki/Ethernet_frame#Frame_%E2%80%93_data_link_layer";
        this.inputType = "string";
        this.outputType = "html";
        this.args = [
            {
                name: "Input type",
                type: "option",
                value: [
                    "Raw", "Hex"
                ],
                defaultIndex: 0,
            },
            {
                name: "Return type",
                type: "option",
                value: [
                    "Text output", "Packet data", "Packet data (hex)",
                ],
                defaultIndex: 0,
            }
        ];
    }


    /**
     * 【主流程】解析以太网帧首部并切出载荷
     *
     * 参数 args[0] = 输入类型，args[1] = 返回类型
     * 返回值：Text output 时返回文本清单字符串；否则返回帧载荷（raw 字符串或 hex 串）
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {html}
     */
    run(input, args) {
        const format = args[0];
        const outputFormat = args[1];

        // --- 步骤 1：输入归一化，统一转成可按下标取字节的 Uint8Array ---
        if (format === "Hex") {
            input = fromHex(input);
        } else if (format === "Raw") {
            input = new Uint8Array(Utils.strToArrayBuffer(input));
        } else {
            throw new OperationError("Invalid input format selected.");
        }

        // --- 步骤 2：帧首部前 12 字节 —— 目的 MAC（0~5）与源 MAC（6~11）---
        const destinationMac = input.slice(0, 6);
        const sourceMac = input.slice(6, 12);

        // --- 步骤 3~4：从偏移 12 起循环读取 EtherType，逐层剥离 VLAN 标签 ---
        let offset = 12;
        const vlans = [];

        while (offset < input.length) {
            const ethType = Utils.byteArrayToChars(input.slice(offset, offset+2));
            offset += 2;

            if (ethType === "\x81\x00" || ethType === "\x88\xA8") {
                // Parse the VLAN tag:
                // [0000] 0000 0000 0000
                //  ^^^ PRIO  - Ignored
                //     ^ DEI  - Ignored
                //        ^^^^ ^^^^ ^^^^ VLAN ID
                const vlanTag = input.slice(offset, offset+2);
                vlans.push(((vlanTag[0] & 0b00001111) << 8) | vlanTag[1]);

                offset += 2;
            } else {
                break;
            }
        }

        // --- 步骤 5：VLAN 标签之后剩余的字节即帧载荷 ---
        const packetData = input.slice(offset);

        // --- 步骤 6：按 "Return type" 分派输出形态 ---
        if (outputFormat === "Packet data") {
            return Utils.escapeHtml(Utils.byteArrayToChars(packetData));
        } else if (outputFormat === "Packet data (hex)") {
            return toHex(packetData);
        } else if (outputFormat === "Text output") {
            let retval = `Source MAC: ${toHex(sourceMac, ":")}\nDestination MAC: ${toHex(destinationMac, ":")}\n`;
            if (vlans.length > 0) {
                retval += `VLAN: ${vlans.join(", ")}\n`;
            }
            retval += `Data:\n${toHex(packetData)}`;
            return retval;
        }

    }


}

export default ParseEthernetFrame;
