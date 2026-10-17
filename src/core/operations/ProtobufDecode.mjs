/**
 * @author GCHQ Contributor [3]
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】Protobuf 编解码（Protobuf）— 反序列化
 * 【操作】Protobuf Decode
 * 【功能】把 Protobuf 序列化后的二进制数据解码成 JSON 表示；若提供了 .proto schema，则按 schema 解码
 * 【输入】ArrayBuffer —— Protobuf 编码后的裸字节
 * 【输出】JSON —— 以字段号（无 schema）或字段名（有 schema）为键的对象
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 把框架传入的 ArrayBuffer 包装成 Uint8Array（lib 只接受 Uint8Array/Array）
 *   2. 调用 lib/Protobuf.mjs 的 Protobuf.decode(input, args)，把参数整体透传
 *   3. 解码过程中的任何异常统一包装成 OperationError 抛出
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 无 schema（raw）解码：Protobuf._parse() 循环读取每个字段的 tag 字节，
 *     拆出 wire type 后按类型分派：
 *       0 = VarInt（int32/bool/enum）
 *       1 = 64-bit（fixed64/double，小端读 8 字节）
 *       2 = Length-delimited（string/bytes/嵌套 message：先读 varint 长度再切片）
 *       5 = 32-bit（fixed32/float，小端读 4 字节）
 *   - tag 拆解：tag 本身是 varint 编码，其值 = (field_number << 3) | wire_type，
 *     低 3 位是 wire type，其余高位是字段号；故先 & 0x07 取类型，再 >> 3 取字段号
 *   - 有 schema 时改用 protobufjs：解析 .proto 得到 message，用 message.decode()
 *     再 toObject() 转成普通对象；同时可对照 raw 结果列出 schema 中未定义的字段
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - Operation 层保持"薄壳"，复杂逻辑集中在 lib/Protobuf.mjs，便于独立测试与复用
 *   - Show Unknown Fields / Show Types 两个开关分别控制"未知字段对照"与"字段类型标注"的输出
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Protobuf from "../lib/Protobuf.mjs";

/**
 * Protobuf Decode operation
 *
 * 继承自 Operation 基类，只做一层薄封装：把字节交给 lib/Protobuf.mjs，
 * 真正的 wire type 分派、varint 读取等逻辑都在库中实现。
 */
class ProtobufDecode extends Operation {

    /**
     * ProtobufDecode constructor
     *
     * 声明本操作的元信息与参数：
     *   inputType  = "ArrayBuffer"，框架会先把 Dish 转成 ArrayBuffer 再交给 run()
     *   outputType = "JSON"，run() 返回的对象会被序列化为 JSON 展示
     * args 对应界面上的输入控件：
     *   [0] Schema (.proto text) —— 可选的 .proto 文本；为空则走无 schema 的 raw 解码
     *   [1] Show Unknown Fields —— 布尔；为 true 时把输入中有、schema 中无的字段单列出来
     *   [2] Show Types —— 布尔；为 true 时在字段名后附上其类型/wire type 说明
     */
    constructor() {
        super();

        this.name = "Protobuf Decode";
        this.module = "Protobuf";
        this.description = "Decodes any Protobuf encoded data to a JSON representation of the data using the field number as the field key.<br><br>If a .proto schema is defined, the encoded data will be decoded with reference to the schema. Only one message instance will be decoded. <br><br><u>Show Unknown Fields</u><br>When a schema is used, this option shows fields that are present in the input data but not defined in the schema.<br><br><u>Show Types</u><br>Show the type of a field next to its name. For undefined fields, the wiretype and example types are shown instead.";
        this.infoURL = "https://wikipedia.org/wiki/Protocol_Buffers";
        this.inputType = "ArrayBuffer";
        this.outputType = "JSON";
        this.args = [
            {
                name: "Schema (.proto text)",
                type: "text",
                value: "",
                rows: 8,
                hint: "Drag and drop is enabled on this ingredient"
            },
            {
                name: "Show Unknown Fields",
                type: "boolean",
                value: false
            },
            {
                name: "Show Types",
                type: "boolean",
                value: false
            }
        ];
    }

    /**
     * 【主流程】解码 Protobuf 数据
     *
     * 步骤：
     *   1. 把 ArrayBuffer 包装成 Uint8Array（lib 只接受 Uint8Array 或 Array）
     *   2. 调用 Protobuf.decode(input, args)，args 原样透传给库
     *   3. 用 try/catch 把底层异常统一转成 OperationError
     *
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {JSON}
     */
    run(input, args) {
        input = new Uint8Array(input);
        try {
            return Protobuf.decode(input, args);
        } catch (err) {
            throw new OperationError(err);
        }
    }

}

export default ProtobufDecode;
