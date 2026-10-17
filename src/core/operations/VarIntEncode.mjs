/**
 * @author GCHQ Contributor [3]
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】数据编码（Default）— 变长整数
 * 【操作】VarInt Encode
 * 【功能】把一个非负整数字符串编码为 Protobuf 风格的 VarInt（LEB128）字节数组
 * 【输入】string —— 十进制整数字符串（如 "300"）
 * 【输出】byteArray —— 变长整数字节（如 "300" → [0xac, 0x02]）
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 若运行环境支持 BigInt：先 BigInt(input) 取精确值，负数直接报错
 *   2. 循环：只要 value >= 0x80，就取低 7 位并置最高位为 1 后推入结果，再右移 7 位
 *   3. 循环结束把剩余不足 7 位的 value 作为最后一字节推入（最高位为 0，标记结束）
 *   4. 不支持 BigInt 的环境降级为 Protobuf.varIntEncode(Number(input))
 * ------------------------------------------------------------
 * 【关键算法】LEB128（Little Endian Base 128）变长整数
 *   - 每个字节只用低 7 位承载有效数据，最高位（bit7 / MSB）是"续接标志"：
 *       1 = 后面还有字节，0 = 这是最后一个字节
 *   - 数据低位在前（little-endian），解码时按 7 位一组向上移位拼接回来
 *   - 因此小数值只占 1 字节，数值越大占用越多字节，实现了"变长"
 *   - 超长整数必须用 BigInt：JS 的 Number 是 IEEE-754 双精度，安全整数上限仅 2^53-1，
 *     更大的值会丢精度，而 BigInt 可精确表示任意长度整数，故循环中用 BigInt(0x7f)、
 *     BigInt(7) 做运算
 *   - `typeof BigInt === "function"` 是特性探测：老环境/无 BigInt 时降级到
 *     基于 Number 的旧实现，保证兼容性（代价是仅支持 < 2^53 的范围）
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 结果数组里 0x80~0xFF 的高位是续接标志位而非符号位，属正常现象
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Protobuf from "../lib/Protobuf.mjs";

/**
 * VarInt Encode operation
 *
 * 继承自 Operation；因编码逻辑较短且需处理超长整数，核心实现内联在本类，
 * 仅在无 BigInt 的环境降级调用 lib/Protobuf.mjs 的 varIntEncode。
 */
class VarIntEncode extends Operation {

    /**
     * VarIntEncode constructor
     *
     * 声明元信息：inputType = "string"（十进制数字文本），
     * outputType = "byteArray"（字节数组），无参数（args 为空数组）。
     */
    constructor() {
        super();

        this.name = "VarInt Encode";
        this.module = "Default";
        this.description = "Encodes a Vn integer as a VarInt. VarInt is an efficient way of encoding variable length integers and is commonly used with Protobuf.";
        this.infoURL = "https://developers.google.com/protocol-buffers/docs/encoding#varints";
        this.inputType = "string";
        this.outputType = "byteArray";
        this.args = [];
    }

    /**
     * 【主流程】VarInt 编码
     *
     * 优先用 BigInt 精确处理任意大小整数；不支持 BigInt 时降级到 Number 版本。
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {byteArray}
     */
    run(input, args) {
        try {
            if (typeof BigInt === "function") {
                // --- 步骤 1：BigInt 路径，可精确处理超出 2^53 的大整数 ---
                let value = BigInt(input);
                if (value < 0) throw new OperationError("Negative values cannot be represented as VarInt");
                const result = [];
                // --- 步骤 2：每轮取低 7 位、置续接位 0x80，再右移 7 位 ---
                while (value >= 0x80) {
                    result.push(Number(value & BigInt(0x7f)) | 0x80);
                    value >>= BigInt(7);
                }
                // --- 步骤 3：最后一字节不置 0x80，表示到此结束 ---
                result.push(Number(value));
                return result;
            } else {
                // --- 无 BigInt：降级为 Number 实现（仅支持 < 2^53）---
                return Protobuf.varIntEncode(Number(input));
            }
        } catch (err) {
            throw new OperationError(err);
        }
    }

}

export default VarIntEncode;
