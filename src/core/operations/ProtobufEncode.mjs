/**
 * @author GCHQ Contributor [3]
 * @copyright Crown Copyright 2021
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】Protobuf 编解码（Protobuf）— 序列化
 * 【操作】Protobuf Encode
 * 【功能】按给定的 .proto schema，把 JSON 对象编码为 Protobuf 二进制字节数组
 * 【输入】JSON —— 与 schema 对应的普通对象
 * 【输出】ArrayBuffer —— Protobuf 编码后的字节
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 调用 lib/Protobuf.mjs 的 Protobuf.encode(input, args)
 *   2. lib 内先用 protobufjs 解析 .proto 文本得到 root，并选取主 message
 *   3. 用 message.fromObject(input) 把普通对象转成 message 实例，
 *      再 message.verify() 校验字段合法性
 *   4. message.encode(input).finish() 得到字节，包成 ArrayBuffer 返回
 *   5. 任何异常统一转成 OperationError
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 每个字段写为 tag + 值：tag = (field_number << 3) | wire_type
 *     （低 3 位是 wire type），wire type 取值 0=VarInt / 1=64bit / 2=Length-delimited / 5=32bit
 *   - 整型字段用 VarInt（LEB128）写入；string/bytes/嵌套 message 用
 *     Length-delimited：先写 varint 长度，再写内容
 *   - 具体的位运算与字节拼装由 protobufjs 的 encode() 完成，本操作不手工处理
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - schema 为必填，否则 lib 会抛 "Schema Error: Schema not defined"
 *   - 编码前用 verify() 主动校验，能把参数错误尽早、清晰地暴露给用户
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Protobuf from "../lib/Protobuf.mjs";

/**
 * Protobuf Encode operation
 *
 * 继承自 Operation 基类，只做薄封装：把 JSON 与 schema 交给 lib/Protobuf.mjs，
 * 序列化细节（tag 拼装、varint、length-delimited）都由 protobufjs 完成。
 */
class ProtobufEncode extends Operation {

    /**
     * ProtobufEncode constructor
     *
     * 声明元信息与参数：
     *   inputType  = "JSON"，框架保证 run() 收到的是已解析好的 JS 对象
     *   outputType = "ArrayBuffer"，返回的二进制会以字节形式展示
     * args[0] Schema (.proto text) —— 必填的 .proto 文本，决定消息结构
     */
    constructor() {
        super();

        this.name = "Protobuf Encode";
        this.module = "Protobuf";
        this.description = "Encodes a valid JSON object into a protobuf byte array using the input .proto schema.";
        this.infoURL = "https://developers.google.com/protocol-buffers/docs/encoding";
        this.inputType = "JSON";
        this.outputType = "ArrayBuffer";
        this.args = [
            {
                name: "Schema (.proto text)",
                type: "text",
                value: "",
                rows: 8,
                hint: "Drag and drop is enabled on this ingredient"
            }
        ];
    }

    /**
     * 【主流程】编码 JSON 为 Protobuf 字节
     *
     * 把入参与参数整体交给 Protobuf.encode()，异常统一包装为 OperationError。
     *
     * @param {Object} input
     * @param {Object[]} args
     * @returns {ArrayBuffer}
     */
    run(input, args) {
        try {
            return Protobuf.encode(input, args);
        } catch (error) {
            throw new OperationError(error);
        }
    }

}

export default ProtobufEncode;
