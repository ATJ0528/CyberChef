/**
 * @author c65722 []
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 剥离 UDP 首部
 * 【操作】Strip UDP header
 * 【功能】去掉 UDP 数据报固定 8 字节首部，只输出其后的载荷
 * 【输入】ArrayBuffer —— 原始 UDP 数据报字节
 * 【输出】ArrayBuffer —— 首部之后的载荷字节
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 用 Stream 包装输入；长度小于 8（UDP 固定首部）则报错
 *   2. moveTo(8) 直接跳过首部
 *   3. 返回剩余字节的 buffer
 * ------------------------------------------------------------
 * 【关键算法】
 *   - UDP 首部长度恒定（源端口 2 + 目的端口 2 + 长度 2 + 校验和 2 = 8 字节），
 *     因此无需像 IPv4/TCP 那样读取变长字段，直接跳过 8 字节即可
 * ============================================================
 */

import Operation from "../Operation.mjs";
import Stream from "../lib/Stream.mjs";
import OperationError from "../errors/OperationError.mjs";

/**
 * Strip UDP header operation
 *
 * 继承自 Operation 基类。输入输出均为 ArrayBuffer（二进制透传），无参数。
 */
class StripUDPHeader extends Operation {

    /**
     * 构造函数 —— 声明元信息
     *
     * inputType / outputType 均为 "ArrayBuffer"，直接处理原始字节流；
     * args 为空数组，界面上没有可配置参数
     */
    constructor() {
        super();

        this.name = "Strip UDP header";
        this.module = "Default";
        this.description = "Strips the UDP header from a UDP datagram, outputting the payload.";
        this.infoURL = "https://wikipedia.org/wiki/User_Datagram_Protocol";
        this.inputType = "ArrayBuffer";
        this.outputType = "ArrayBuffer";
        this.args = [];
    }

    /**
     * 【主流程】剥离 UDP 首部
     *
     * 参数：无（args 忽略）
     * 返回值：首部之后的载荷 ArrayBuffer
     *
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {ArrayBuffer}
     */
    run(input, args) {
        const HEADER_LEN = 8;

        const s = new Stream(new Uint8Array(input));
        if (s.length < HEADER_LEN) {
            throw new OperationError("Need 8 bytes for a UDP Header");
        }

        // UDP 首部定长 8 字节，直接跳过
        s.moveTo(HEADER_LEN);

        return s.getBytes().buffer;
    }

}

export default StripUDPHeader;
