/**
 * @author h345983745 []
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— UDP 首部解析
 * 【操作】Parse UDP
 * 【功能】解析 UDP 报文首部（固定 8 字节）与载荷，产出结构化对象
 * 【输入】string —— Hex 串或 Raw 原始字符流（由 "Input format" 参数决定）
 * 【输出】json —— run() 返回对象，框架再调用 present() 渲染成 HTML 表格
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 按 "Input format" 归一化为字节数组（Hex → fromHex；Raw → strToArrayBuffer）
 *   2. 用 Stream 顺序读取；不足 8 字节（UDP 固定首部）则报错
 *   3. 依次读源端口、目的端口、长度、校验和四个字段
 *   4. 若仍有剩余字节，按 Length − 8 读取载荷
 *   5. 返回对象，由 present() 渲染成表格
 * ------------------------------------------------------------
 * 【关键算法】
 *   - UDP Length 字段表示“首部 + 载荷”的总长度，故载荷字节数 = Length − 8（首部定长 8）
 *   - 端口与长度为大端 16 位整数，用 Stream.readInt(2) 一次读出
 *   - 校验和以 "0x" 前缀的十六进制原样展示（无需重算，UDP 校验和可选）
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 用 Stream 顺序读取，字段顺序与协议定义一致，可读性高
 *   - present() 统一委托 objToTable()，解析与呈现解耦
 * ============================================================
 */

import Operation from "../Operation.mjs";
import Stream from "../lib/Stream.mjs";
import {toHexFast, fromHex} from "../lib/Hex.mjs";
import {objToTable} from "../lib/Protocol.mjs";
import Utils from "../Utils.mjs";
import OperationError from "../errors/OperationError.mjs";

/**
 * Parse UDP operation
 *
 * 继承自 Operation 基类。run() 产出结构化对象，由 present() 统一渲染为表格。
 */
class ParseUDP extends Operation {

    /**
     * 构造函数 —— 声明元信息与参数
     *
     * inputType   = "string" 框架先把 Dish 转成字符串再交给 run()
     * outputType  = "json"   run() 返回对象
     * presentType = "html"   框架随后调用 present() 渲染为 HTML
     * args[0] Input format —— 选项：Hex / Raw，决定输入如何解码
     */
    constructor() {
        super();

        this.name = "Parse UDP";
        this.module = "Default";
        this.description = "Parses a UDP header and payload (if present).";
        this.infoURL = "https://wikipedia.org/wiki/User_Datagram_Protocol";
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
     * 【主流程】解析 UDP 首部与载荷
     *
     * 参数 args[0] = 输入格式（Hex / Raw）
     * 返回值：结构化 UDPPacket 对象（由框架交给 present() 渲染）
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {Object}
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

        // --- 步骤 2：Stream 包装并做 UDP 最小首部（8 字节）校验 ---
        const s = new Stream(new Uint8Array(input));
        if (s.length < 8) {
            throw new OperationError("Need 8 bytes for a UDP Header");
        }

        // --- 步骤 3：顺序读取固定 8 字节首部 ---
        const UDPPacket = {
            "Source port": s.readInt(2),
            "Destination port": s.readInt(2),
            "Length": s.readInt(2),
            "Checksum": "0x" + toHexFast(s.getBytes(2))
        };
        // --- 步骤 4：Length 为首部+载荷总长，故载荷 = Length − 8 ---
        if (s.hasMore()) {
            UDPPacket.Data = "0x" + toHexFast(s.getBytes(UDPPacket.Length - 8));
        }

        return UDPPacket;
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


export default ParseUDP;
