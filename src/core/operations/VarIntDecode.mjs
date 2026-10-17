/**
 * @author GCHQ Contributor [3]
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】数据编码（Default）— 变长整数
 * 【操作】VarInt Decode
 * 【功能】把 VarInt（LEB128）字节数组解码为非负整数字符串
 * 【输入】byteArray —— 变长整数字节（如 [0xac, 0x02]）
 * 【输出】string —— 十进制数字符串（如 "300"）
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 支持 BigInt 时：result=0、offset=0，逐字节读取
 *   2. 每字节取低 7 位左移 offset 位后并入 result
 *   3. 若该字节最高位为 0（无续接）则结束；否则 offset += 7 继续读下一字节
 *   4. 返回 result.toString()；不支持 BigInt 时降级 Protobuf.varIntDecode
 * ------------------------------------------------------------
 * 【关键算法】LEB128（Little Endian Base 128）变长整数解码
 *   - 每字节低 7 位是有效数据，最高位是"还有后续字节"的续接标志
 *   - 数据低位在前：第 1 字节承载 bit0-6，第 2 字节承载 bit7-13，依此类推，
 *     故解码时按 7 位一组、offset 每次 +7 左移后按位或拼接
 *   - 用 BigInt 保存 result 与 offset，避免数值超过 2^53-1 时 Number 丢精度；
 *     最终以字符串返回，让大整数值能不失真地展示给用户
 *   - `typeof BigInt === "function"` 是特性探测，无 BigInt 时降级到
 *     lib/Protobuf.mjs 的 varIntDecode（基于 Number，仅支持 < 2^53）
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 一旦读到最高位为 0 的字节应立即停止，忽略其后的多余字节
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Protobuf from "../lib/Protobuf.mjs";

/**
 * VarInt Decode operation
 *
 * 继承自 Operation；因解码逻辑较短且需处理超长整数，核心实现内联在本类，
 * 仅在无 BigInt 的环境降级调用 lib/Protobuf.mjs 的 varIntDecode。
 */
class VarIntDecode extends Operation {

    /**
     * VarIntDecode constructor
     *
     * 声明元信息：inputType = "byteArray"（字节数组），
     * outputType = "string"（十进制数字文本），无参数（args 为空数组）。
     */
    constructor() {
        super();

        this.name = "VarInt Decode";
        this.module = "Default";
        this.description = "Decodes a VarInt encoded integer. VarInt is an efficient way of encoding variable length integers and is commonly used with Protobuf.";
        this.infoURL = "https://developers.google.com/protocol-buffers/docs/encoding#varints";
        this.inputType = "byteArray";
        this.outputType = "string";
        this.args = [];
    }

    /**
     * 【主流程】VarInt 解码
     *
     * 用 BigInt 逐字节按 7 位一组左移拼接，遇到续接位为 0 的字节即停止。
     *
     * @param {byteArray} input
     * @param {Object[]} args
     * @returns {number}
     */
    run(input, args) {
        try {
            if (typeof BigInt === "function") {
                // --- 步骤 1：result 累加值，offset 记录当前应左移的位数 ---
                let result = BigInt(0);
                let offset = BigInt(0);
                // --- 步骤 2：逐字节取低 7 位并入，续接位为 0 则结束 ---
                for (let i = 0; i < input.length; i++) {
                    result |= BigInt(input[i] & 0x7f) << offset;
                    if (!(input[i] & 0x80)) break;
                    offset += BigInt(7);
                }
                return result.toString();
            } else {
                // --- 无 BigInt：降级为 Number 实现（仅支持 < 2^53）---
                return Protobuf.varIntDecode(input).toString();
            }
        } catch (err) {
            throw new OperationError(err);
        }
    }

}

export default VarIntDecode;
