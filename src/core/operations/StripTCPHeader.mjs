/**
 * @author c65722 []
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 剥离 TCP 首部
 * 【操作】Strip TCP header
 * 【功能】去掉 TCP 报文段首部（含 Options），只输出其后的载荷
 * 【输入】ArrayBuffer —— 原始 TCP 报文段字节
 * 【输出】ArrayBuffer —— 首部之后的载荷字节
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 用 Stream 包装输入；长度小于 20（TCP 最小首部）则报错
 *   2. moveTo(12) 定位到 Data offset 所在字节
 *   3. 读该字节高 4 位（readBits(4)）得到 Data offset，×4 换算为首部字节数
 *   4. 校验长度后 moveTo 跳过首部，返回剩余字节的 buffer
 * ------------------------------------------------------------
 * 【关键算法】
 *   - Data offset 位于首部第 13 字节（偏移 12）的高 4 位，故先 moveTo(12)，
 *     再用 Stream.readBits(4) 只读高半字节；其余 4 位是 Reserved，本操作不关心
 *   - Data offset 以 4 字节（32 位字）为单位，×4 才是首部实际字节长度，从而跳过 Options
 *   - moveTo 只移动读指针不消费数据，readBits 会按位读取并推进指针
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Stream from "../lib/Stream.mjs";

/**
 * Strip TCP header operation
 *
 * 继承自 Operation 基类。输入输出均为 ArrayBuffer（二进制透传），无参数。
 */
class StripTCPHeader extends Operation {

    /**
     * 构造函数 —— 声明元信息
     *
     * inputType / outputType 均为 "ArrayBuffer"，直接处理原始字节流；
     * args 为空数组，界面上没有可配置参数
     */
    constructor() {
        super();

        this.name = "Strip TCP header";
        this.module = "Default";
        this.description = "Strips the TCP header from a TCP segment, outputting the payload.";
        this.infoURL = "https://wikipedia.org/wiki/Transmission_Control_Protocol";
        this.inputType = "ArrayBuffer";
        this.outputType = "ArrayBuffer";
        this.args = [];
    }

    /**
     * 【主流程】剥离 TCP 首部
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
        const DATA_OFFSET_OFFSET = 12;
        const DATA_OFFSET_LEN_BITS = 4;

        const s = new Stream(new Uint8Array(input));
        if (s.length < MIN_HEADER_LEN) {
            throw new OperationError("Need at least 20 bytes for a TCP Header");
        }

        // 定位到 Data offset 字段（首部第 13 字节）并只读其高 4 位
        s.moveTo(DATA_OFFSET_OFFSET);
        const dataOffsetWords = s.readBits(DATA_OFFSET_LEN_BITS);
        const dataOffsetBytes = dataOffsetWords * 4;
        if (s.length < dataOffsetBytes) {
            throw new OperationError("Input length is less than data offset");
        }

        s.moveTo(dataOffsetBytes);

        return s.getBytes().buffer;
    }

}

export default StripTCPHeader;
