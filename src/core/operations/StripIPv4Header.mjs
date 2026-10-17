/**
 * @author c65722 []
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 剥离 IPv4 首部
 * 【操作】Strip IPv4 header
 * 【功能】去掉 IPv4 报文的整个首部（含可变长 Options），只输出其后的载荷
 * 【输入】ArrayBuffer —— 原始 IPv4 报文字节
 * 【输出】ArrayBuffer —— 首部之后的载荷字节
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 用 Stream 包装输入；长度小于 20（IPv4 最小首部）则报错
 *   2. 读首字节低 4 位得到 IHL（首部长度，以 4 字节为单位）
 *   3. 换算首部字节数 = IHL × 4；若输入比首部还短则报错
 *   4. moveTo 跳过首部，返回剩余字节的 buffer
 * ------------------------------------------------------------
 * 【关键算法】
 *   - IHL 位域：IPv4 首字节高 4 位为 Version、低 4 位为 IHL，
 *     故用 `readInt(1) & 0x0f` 取出 IHL；IHL 单位为 4 字节，×4 才是实际字节偏移
 *   - Stream.moveTo(n) 只移动读指针、不读取内容，用于跳过首部
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Stream from "../lib/Stream.mjs";

/**
 * Strip IPv4 header operation
 *
 * 继承自 Operation 基类。输入输出均为 ArrayBuffer（二进制透传），无参数。
 */
class StripIPv4Header extends Operation {

    /**
     * 构造函数 —— 声明元信息
     *
     * inputType / outputType 均为 "ArrayBuffer"，表示本操作直接处理原始字节流，
     * args 为空数组，界面上没有可配置参数
     */
    constructor() {
        super();

        this.name = "Strip IPv4 header";
        this.module = "Default";
        this.description = "Strips the IPv4 header from an IPv4 packet, outputting the payload.";
        this.infoURL = "https://wikipedia.org/wiki/IPv4";
        this.inputType = "ArrayBuffer";
        this.outputType = "ArrayBuffer";
        this.args = [];
    }

    /**
     * 【主流程】剥离 IPv4 首部
     *
     * 参数：无（args 忽略）
     * 返回值：首部之后的载荷 ArrayBuffer
     *
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {ArrayBuffer}
     */
    run(input, args) {
        const MIN_HEADER_LEN = 20;

        const s = new Stream(new Uint8Array(input));
        if (s.length < MIN_HEADER_LEN) {
            throw new OperationError("Input length is less than minimum IPv4 header length");
        }

        // 取首字节低 4 位为 IHL，再 ×4 换算成首部字节数（含 Options）
        const ihl = s.readInt(1) & 0x0f;
        const dataOffsetBytes = ihl * 4;
        if (s.length < dataOffsetBytes) {
            throw new OperationError("Input length is less than IHL");
        }

        s.moveTo(dataOffsetBytes);

        return s.getBytes().buffer;
    }

}

export default StripIPv4Header;
