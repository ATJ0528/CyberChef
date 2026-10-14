import Utils from "../Utils.mjs";
import protobuf from "protobufjs";

/**
 * Protobuf lib. Contains functions to decode protobuf serialised
 * data without a schema or .proto file.
 *
 * Provides utility functions to encode and decode variable length
 * integers (varint).
 *
 * @author GCHQ Contributor [3]
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 共享算法库
 * 【文件】src/core/lib/Protobuf.mjs
 * 【职责】在没有 .proto schema 的前提下，按 Protocol Buffers 二进制线格式
 *         （wire format）递归解码任意 protobuf 数据；同时提供不带 schema 的
 *         VarInt（LEB128）编解码，以及带 schema 的 encode/decode 封装。
 * 【被谁使用】（grep 查证）
 *   - src/core/operations/ProtobufDecode.mjs —— 无/有 schema 的解码操作
 *   - src/core/operations/ProtobufEncode.mjs —— 按 schema 编码为二进制
 *   - src/core/operations/VarIntDecode.mjs   —— 单值 VarInt 解码
 *   - src/core/operations/VarIntEncode.mjs   —— 单值 VarInt 编码
 * ------------------------------------------------------------
 * 【导出接口】
 *   - Protobuf constructor(data)                 : 绑定字节序列，初始化掩码/游标
 *   - Protobuf.varIntEncode(number) → byteArray  : 数值 → LEB128 字节序列
 *   - Protobuf.varIntDecode(input)  → number     : LEB128 字节序列 → 数值
 *   - Protobuf.encode(input, args)  → ArrayBuffer: 按 schema 把 JSON 编码为二进制
 *   - Protobuf.decode(input, args)  → Object     : 按 schema 解码并比对未知字段
 *   - 私有（下划线）：_parse / _parseField / _fieldHeader /
 *     _fieldType / _fieldNumber / _varInt / _uint64 / _lenDelim / _uint32
 * ------------------------------------------------------------
 * 【关键算法】← 务必写清楚
 *   1) VarInt（LEB128）编解码：每字节低 7 位为有效数据、最高位 MSB 为续接标志，
 *      低位在前（little-endian base-128）；MSB=1 表示「后面还有字节」。
 *      解码时第 n 字节数据左移 7n 位累加；编码时不断取低 7 位、右移 7 位直至清零。
 *   2) tag 拆解：每个字段以一个 varint 形的 tag 开头，
 *      tag = (field_number << 3) | wire_type，即低 3 位是 wire_type、
 *      其余高位是 field_number（字段号本身也是 varint，>15 时会跨字节）。
 *      wire_type：0=VarInt / 1=64-bit / 2=Length-delimited / 5=32-bit（3、4 已废弃）。
 *   3) 递归下降解码与嵌套深度：遇到 wire_type=2（L-delim）时，先读长度 varint 定出
 *      边界，再把这段子串交给「新的 Protobuf 实例」递归 _parse()；子实例自成
 *      一套 offset/LENGTH，天然隔离各层游标，递归深度即嵌套 message 层数。
 *      若子串不是合法 message（递归抛错），退化为 UTF-8 字符串/字节串输出。
 *   4) 编解码对称性：_varInt 与 varIntEncode 互为逆运算；_parseField/_fieldHeader
 *      的读取顺序与字节布局一一对应，「读多少字节、游标推进多少」在两侧一致。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 位掩码集中定义在构造器（TYPE/NUMBER/MSB/VALUE），比散落的魔法数字清晰
 *   - fieldTypes 逐字段累积（含递归子消息的合并），使「无 schema」也能推断 wire_type
 *   - 大于 2^31 的数值用浮点除法/幂运算规避 JS 32 位位运算溢出
 * ============================================================
 */
class Protobuf {

    /**
     * Protobuf constructor
     *
     * 构造器：绑定待解析的字节序列，并预置位掩码与游标状态。
     *   - this.data        待解析数据（Array 或 Uint8Array）
     *   - this.offset      当前读取游标，解码时逐字节推进
     *   - this.LENGTH      数据总长度，用于 _parse 的循环终止与越界检测
     *   - this.fieldTypes  「字段号 → wire_type」映射，供类型展示使用
     * 四个掩码：TYPE=低 3 位(wire_type)、NUMBER=tag 中段位(字段号)、
     * MSB=续接标志位、VALUE=低 7 位数据位。
     *
     * @param {byteArray|Uint8Array} data
     */
    constructor(data) {
        // Check we have a byteArray or Uint8Array
        if (data instanceof Array || data instanceof Uint8Array) {
            this.data = data;
        } else {
            throw new Error("Protobuf input must be a byteArray or Uint8Array");
        }

        // Set up masks
        this.TYPE = 0x07;
        this.NUMBER = 0x78;
        this.MSB = 0x80;
        this.VALUE = 0x7f;

        // Declare offset, length, and field type object
        this.offset = 0;
        this.LENGTH = data.length;
        this.fieldTypes = {};
    }

    // Public Functions

    /**
     * Encode a varint from a number
     *
     * 把数值编码为 LEB128 varint 字节序列（每字节低 7 位有效、最高位为续接标志）。
     *   第一个 while：当 number ≥ 2^31 时，规避 JS `>>>` 只作用于 32 位的问题，
     *     改用浮点除法 /128 逐次降位，每轮取低 8 位并置 MSB（number & 0xff | 0x80）。
     *   第二个 while：当高位仍有有效位（number & MSBALL）时，取低 8 位置 MSB、
     *     再 `>>>= 7` 右移 7 位；这是标准的 base-128 逐组输出。
     *   最后把剩余不足 7 位的值作为末字节写出（不置 MSB），编码结束。
     * 与 _varInt() 互为逆运算。
     *
     * @param {number} number
     * @returns {byteArray}
     */
    static varIntEncode(number) {
        const MSB = 0x80,
            VALUE = 0x7f,
            MSBALL = ~VALUE,
            INT = Math.pow(2, 31);
        const out = [];
        let offset = 0;

        while (number >= INT) {
            out[offset++] = (number & 0xff) | MSB;
            number /= 128;
        }
        while (number & MSBALL) {
            out[offset++] = (number & 0xff) | MSB;
            number >>>= 7;
        }
        out[offset] = number | 0;
        return out;
    }

    /**
     * Decode a varint from the byteArray
     *
     * 便捷入口：用输入字节序列新建一个 Protobuf 实例，转调其私有 _varInt()。
     * 之所以包一层，是因为 _varInt() 依赖实例的 offset 游标与 data 绑定。
     *
     * @param {byteArray} input
     * @returns {number}
     */
    static varIntDecode(input) {
        const pb = new Protobuf(input);
        return pb._varInt();
    }

    /**
     * Encode input JSON according to the given schema
     *
     * 带 schema 的编码入口（依赖 protobufjs 运行时）：
     *   1. updateProtoRoot(args[0]) 解析 .proto 文本，未定义 message 则报「Schema not defined」；
     *   2. 取主 message 类型；
     *   3. message.fromObject(input) 把普通 JSON 转成 message 实例；
     *   4. message.verify() 校验必填/类型，出错抛「Input Error」；
     *   5. message.encode().finish() 产出二进制，包成 ArrayBuffer 返回。
     * 注意这是「按 schema 编码」，与无 schema 的 _parse/_varInt 解码路径相互独立。
     *
     * @param {Object} input
     * @param {Object []} args
     * @returns {Object}
     */
    static encode(input, args) {
        this.updateProtoRoot(args[0]);
        if (!this.mainMessageName) {
            throw new Error("Schema Error: Schema not defined");
        }
        const message = this.parsedProto.root.nested[this.mainMessageName];

        // Convert input into instance of message, and verify instance
        input = message.fromObject(input);
        const error = message.verify(input);
        if (error) {
            throw new Error("Input Error: " + error);
        }
        // Encode input
        const output = message.encode(input).finish();
        return new Uint8Array(output).buffer;
    }

    /**
     * Parse Protobuf data
     *
     * 带 schema 的解码入口。除解析 .proto 外，还从参数取两个开关：
     *   - args[1] showUnknownFields：是否额外标出 schema 未定义的未知字段
     *   - args[2] showTypes         ：是否在字段名后附带 wire_type 说明
     * 随后交给 mergeDecodes() 做「raw 解码 + schema 解码」的双路合并。
     *
     * @param {byteArray} input
     * @param {Object []} args
     * @returns {Object}
     */
    static decode(input, args) {
        this.updateProtoRoot(args[0]);
        this.showUnknownFields = args[1];
        this.showTypes = args[2];
        return this.mergeDecodes(input);
    }

    /**
     * Update the parsedProto, throw parsing errors
     *
     * 用 protobufjs 的 protobuf.parse 把 .proto 文本编译成 Reflection 对象树：
     *   - 若 schema 声明了 package，则把 root 下移到该 package 命名空间，
     *     使后续 `.nested[messageName]` 能直接命中主 message；
     *   - 再刷新主 message 名；
     *   - 解析异常统一包成「Schema ...」抛出。
     *
     * @param {string} protoText
     */
    static updateProtoRoot(protoText) {
        try {
            this.parsedProto = protobuf.parse(protoText);
            if (this.parsedProto.package) {
                this.parsedProto.root = this.parsedProto.root.nested[this.parsedProto.package];
            }
            this.updateMainMessageName();
        } catch (error) {
            throw new Error("Schema " + error);
        }
    }

    /**
     * Set mainMessageName to the first instance of a message defined in the schema that is not a submessage
     *
     * 遍历 schema 顶层，收集所有 message 名及其字段类型；
     * 若一个 message 都没有则置 null（encode 会据此报「Schema not defined」）。
     * 下方被注释掉的逻辑本意是挑出「不被任何字段引用」的顶层 message 作为入口，
     * 但实际实现取的是第一个 message（messageNames[0]）。
     *
     */
    static updateMainMessageName() {
        const messageNames = [];
        const fieldTypes = [];
        this.parsedProto.root.nestedArray.forEach(block => {
            if (block instanceof protobuf.Type) {
                messageNames.push(block.name);
                this.parsedProto.root.nested[block.name].fieldsArray.forEach(field => {
                    fieldTypes.push(field.type);
                });
            }
        });

        if (messageNames.length === 0) {
            this.mainMessageName = null;
        } else {
            // for (const name of messageNames) {
            //     if (!fieldTypes.includes(name)) {
            //         this.mainMessageName = name;
            //         break;
            //     }
            // }
            this.mainMessageName = messageNames[0];
        }
    }

    /**
     * Decode input using Protobufjs package and raw methods, compare, and merge results
     *
     * 核心合并逻辑，同时跑两条解码路径再归并：
     *   1. 无 schema 的 raw 解码：new Protobuf(input)._parse()，按 wire format 逐字段读；
     *      若开启 showTypes，则用 showRawTypes 给字段名附上类型，
     *      并把 schema 字段名也改成「名字 (类型)」形式以便对照。
     *   2. 有 schema 的解码：message.toObject(message.decode(input), {...})，
     *      用 bytes:String / longs:Number / enums:String / defaults:true 做值归一。
     *   若 showUnknownFields 开启，输出分为「主 message」与「Unknown Fields」两块，
     *      未知字段来自 compareFields 把 raw 与 schema 求差集；
     *   若 schema 解码抛错且当时还没有 message（即根本取不到主消息），
     *      则直接回退返回 rawDecode；否则把错误包装后抛出。
     *
     * @param {byteArray} input
     * @returns {Object}
     */
    static mergeDecodes(input) {
        const pb = new Protobuf(input);
        let rawDecode = pb._parse();
        let message;

        if (this.showTypes) {
            rawDecode = this.showRawTypes(rawDecode, pb.fieldTypes);
            this.parsedProto.root = this.appendTypesToFieldNames(this.parsedProto.root);
        }

        try {
            message = this.parsedProto.root.nested[this.mainMessageName];
            const packageDecode = message.toObject(message.decode(input), {
                bytes: String,
                longs: Number,
                enums: String,
                defaults: true
            });
            const output = {};

            if (this.showUnknownFields) {
                output[message.name] = packageDecode;
                output["Unknown Fields"] = this.compareFields(rawDecode, message);
                return output;
            } else {
                return packageDecode;
            }

        } catch (error) {
            if (message) {
                throw new Error("Input " + error);
            } else {
                return rawDecode;
            }
        }
    }

    /**
     * Replace fieldnames with fieldname and type
     *
     * 遍历 schema 中每个 Type 的字段，先 remove 原字段、再 add 一个名为
     * 「原字段名 (类型)」的新 Field（保留 id/type/rule），使显示时能看出字段类型。
     * 副作用式地改写了 schemaRoot 并返回，供后续 toObject 输出带类型名的键。
     *
     * @param {Object} schemaRoot
     * @returns {Object}
     */
    static appendTypesToFieldNames(schemaRoot) {
        for (const block of schemaRoot.nestedArray) {
            if (block instanceof protobuf.Type) {
                for (const [fieldName, fieldData] of Object.entries(block.fields)) {
                    schemaRoot.nested[block.name].remove(block.fields[fieldName]);
                    schemaRoot.nested[block.name].add(new protobuf.Field(`${fieldName} (${fieldData.type})`, fieldData.id, fieldData.type, fieldData.rule));
                }
            }
        }
        return schemaRoot;
    }

    /**
     * Add field type to field name for fields in the raw decoded output
     *
     * 给 raw 解码结果里每个字段号换名，如 `3` → `field #3: L-delim (e.g. string, message)`：
     *   - fieldTypes[fieldNum] 若不是数字（isNaN），说明该字段是嵌套 message（wire_type 2），
     *     于是递归下钻：值若是数组（repeated 子消息）则逐项递归，
     *     否则作为单个子消息递归；字符串值（非子消息）原样保留；
     *   - 若是数字，直接用该 wire_type 走 getTypeInfo 取说明。
     * 最后把旧键删除、写入新键，原地改造并返回 rawDecode。
     *
     * @param {Object} rawDecode
     * @param {Object} fieldTypes
     * @returns {Object}
     */
    static showRawTypes(rawDecode, fieldTypes) {
        for (const [fieldNum, value] of Object.entries(rawDecode)) {
            const fieldType = fieldTypes[fieldNum];
            let outputFieldValue;
            let outputFieldType;

            // Submessages
            if (isNaN(fieldType)) {
                outputFieldType = 2;

                // Repeated submessages
                if (Array.isArray(value)) {
                    const fieldInstances = [];
                    for (const instance of Object.keys(value)) {
                        if (typeof(value[instance]) !== "string") {
                            fieldInstances.push(this.showRawTypes(value[instance], fieldType));
                        } else {
                            fieldInstances.push(value[instance]);
                        }
                    }
                    outputFieldValue = fieldInstances;

                // Single submessage
                } else {
                    outputFieldValue = this.showRawTypes(value, fieldType);
                }

            // Non-submessage field
            } else {
                outputFieldType = fieldType;
                outputFieldValue = value;
            }

            // Substitute fieldNum with field number and type
            rawDecode[`field #${fieldNum}: ${this.getTypeInfo(outputFieldType)}`] = outputFieldValue;
            delete rawDecode[fieldNum];
        }
        return rawDecode;
    }

    /**
     * Compare raw decode to package decode and return discrepancies
     *
     * 用 schema 反查 raw 解码结果，找出「未知字段 / 不一致」，返回差异对象：
     *   1. 建 schemaFieldProperties：字段 id(数字) → 字段名 的反向索引；
     *   2. 逐个 raw 字段（键可能是 `field #3` 形式，正则取出字段号）判断是否在 schema 中；
     *   3. 命中 schema 的：
     *        - 若 raw 值是数组而 schema 字段非 repeated → 标记「is a repeated field」；
     *        - 若该字段是子消息（resolvedType instanceof Type）：把多个实例「压平」成一个，
     *          再递归调用 compareFields 对比子消息缺失字段；
     *        - 处理完 delete 掉该键，未处理者即为 schema 中不存在的未知字段。
     * 返回的对象即最终展示的「Unknown Fields」。
     *
     * @param rawDecodedMessage
     * @param schemaMessage
     * @returns {Object}
     */
    static compareFields(rawDecodedMessage, schemaMessage) {
        // Define message data using raw decode output and schema
        const schemaFieldProperties = {};
        const schemaFieldNames = Object.keys(schemaMessage.fields);
        schemaFieldNames.forEach(field => schemaFieldProperties[schemaMessage.fields[field].id] = field);

        // Loop over each field present in the raw decode output
        for (const fieldName in rawDecodedMessage) {
            let fieldId;
            if (isNaN(fieldName)) {
                fieldId = fieldName.match(/^field #(\d+)/)[1];
            } else {
                fieldId = fieldName;
            }

            // Check if this field is defined in the schema
            if (fieldId in schemaFieldProperties) {
                const schemaFieldName = schemaFieldProperties[fieldId];

                // Extract the current field data from the raw decode and schema
                const rawFieldData = rawDecodedMessage[fieldName];
                const schemaField = schemaMessage.fields[schemaFieldName];

                // Check for repeated fields
                if (Array.isArray(rawFieldData) && !schemaField.repeated) {
                    rawDecodedMessage[`(${schemaMessage.name}) ${schemaFieldName} is a repeated field`] = rawFieldData;
                }

                // Check for submessage fields
                if (schemaField.resolvedType instanceof protobuf.Type) {
                    const subMessageType = schemaMessage.fields[schemaFieldName].type;
                    const schemaSubMessage = this.parsedProto.root.nested[subMessageType];
                    const rawSubMessages = rawDecodedMessage[fieldName];
                    let rawDecodedSubMessage = {};

                    // Squash multiple submessage instances into one submessage
                    if (Array.isArray(rawSubMessages)) {
                        rawSubMessages.forEach(subMessageInstance => {
                            const instanceFields = Object.entries(subMessageInstance);
                            instanceFields.forEach(subField => {
                                rawDecodedSubMessage[subField[0]] = subField[1];
                            });
                        });
                    } else {
                        rawDecodedSubMessage = rawSubMessages;
                    }

                    // Treat submessage as own message and compare its fields
                    rawDecodedSubMessage = Protobuf.compareFields(rawDecodedSubMessage, schemaSubMessage);
                    if (Object.entries(rawDecodedSubMessage).length !== 0) {
                        rawDecodedMessage[`${schemaFieldName} (${subMessageType}) has missing fields`] = rawDecodedSubMessage;
                    }
                }
                delete rawDecodedMessage[fieldName];
            }
        }
        return rawDecodedMessage;
    }

    /**
     * Returns wiretype information for input wiretype number
     *
     * wire_type 数值 → 人类可读说明的查表函数，对应 protobuf 线格式的四种有效编码：
     * 0=VarInt(int32/bool 等)、1=64-bit(fixed64/double)、2=L-delim(string/message)、
     * 5=32-bit(fixed32/float)；其余（3、4 为已废弃的 group）返回 undefined。
     *
     * @param {number} wireType
     * @returns {string}
     */
    static getTypeInfo(wireType) {
        switch (wireType) {
            case 0:
                return "VarInt (e.g. int32, bool)";
            case 1:
                return "64-Bit (e.g. fixed64, double)";
            case 2:
                return "L-delim (e.g. string, message)";
            case 5:
                return "32-Bit (e.g. fixed32, float)";
        }
    }

    // Private Class Functions

    /**
     * Main private parsing function
     *
     * 解析主循环（无 schema 解码的心脏）：
     *   while (offset < LENGTH) 逐个 _parseField() 读取一个字段，
     *   再用 _addField() 把 {key,value} 并入结果对象。
     *   offset 每读一个字段就按该字段实际长度推进，直到消费完所有字节；
     *   若循环结束后 offset > LENGTH，说明某次读取越过了缓冲区末端，
     *   抛「Exhausted Buffer」——这是截断/畸形数据的典型表现。
     * 递归调用（见 _lenDelim）时每个嵌套层都有独立的 offset/LENGTH，
     * 因此本函数天然可重入，深度即嵌套层数。
     *
     * @private
     * @returns {Object}
     */
    _parse() {
        let object = {};
        // Continue reading whilst we still have data
        while (this.offset < this.LENGTH) {
            const field = this._parseField();
            object = this._addField(field, object);
        }
        // Throw an error if we have gone beyond the end of the data
        if (this.offset > this.LENGTH) {
            throw new Error("Exhausted Buffer");
        }
        return object;
    }

    /**
     * Add a field read from the protobuf data into the Object. As
     * protobuf fields can appear multiple times, if the field already
     * exists we need to add the new field into an array of fields
     * for that key.
     *
     * protobuf 允许同一字段号重复出现（repeated / 非 packed 编码），
     * 因此这里做三段归并：键不存在→直接存值；
     * 键已存在且当前值不是数组→变成 [旧值, 新值]；
     * 键已存在且已是数组→concat 追加。用 hasOwnProperty 判断，避免原型链干扰。
     *
     * @private
     * @param {Object} field
     * @param {Object} object
     * @returns {Object}
     */
    _addField(field, object) {
        // Get the field key/values
        const key = field.key;
        const value = field.value;
        object[key] = Object.prototype.hasOwnProperty.call(object, key) ?
            object[key] instanceof Array ?
                object[key].concat([value]) :
                [object[key], value] :
            value;
        return object;
    }

    /**
     * Parse a field and return the Object read from the record
     *
     * 读一个完整字段：先 _fieldHeader() 拿到 tag 里的 type 与 field number，
     * 顺手把「字段号→wire_type」记入 this.fieldTypes（只在首次出现时记，
     * 不覆盖，避免子消息类型层级错乱）；
     * 再按 wire_type 分派到对应的读取函数：
     *   0 → _varInt()（VarInt）
     *   1 → _uint64()（64-bit 小端）
     *   2 → _lenDelim(key)（带长度前缀，可能是子消息或字符串）
     *   5 → _uint32()（32-bit 小端）
     * 其余（含 3/4 已废弃 group）抛「Unknown type 0x..」。
     * 返回统一的 {key, value} 结构供 _addField 消费。
     *
     * @private
     * @returns {Object}
     */
    _parseField() {
        // Get the field headers
        const header = this._fieldHeader();
        const type = header.type;
        const key = header.key;

        if (typeof(this.fieldTypes[key]) !== "object") {
            this.fieldTypes[key] = type;
        }

        switch (type) {
            // varint
            case 0:
                return { "key": key, "value": this._varInt() };
            // fixed 64
            case 1:
                return { "key": key, "value": this._uint64() };
            // length delimited
            case 2:
                return { "key": key, "value": this._lenDelim(key) };
            // fixed 32
            case 5:
                return { "key": key, "value": this._uint32() };
            // unknown type
            default:
                throw new Error("Unknown type 0x" + type.toString(16));
        }
    }

    /**
     * Parse the field header and return the type and key
     *
     * 拆解 tag：先用 _fieldType() 读低 3 位 wire_type（此步不移动 offset），
     * 再用 _fieldNumber() 读字段号（会推进 offset 越过 tag 的全部字节）。
     * 顺序不可颠倒——若先读 key 会移动游标、导致 type 读错。
     *
     * @private
     * @returns {Object}
     */
    _fieldHeader() {
        // Make sure we call type then number to preserve offset
        return { "type": this._fieldType(), "key": this._fieldNumber() };
    }

    /**
     * Parse the field type from the field header. Type is stored in the
     * lower 3 bits of the tag byte. This does not move the offset on as
     * we need to read the field number from the tag byte too.
     *
     * 取 tag 低 3 位得 wire_type：`data[offset] & 0x07`。
     * 有意不推进 offset，因为同一 tag 字节里还藏着字段号，留给 _fieldNumber() 读。
     *
     * @private
     * @returns {number}
     */
    _fieldType() {
        // Field type stored in lower 3 bits of tag byte
        return this.data[this.offset] & this.TYPE;
    }

    /**
     * Parse the field number (i.e. the key) from the field header. The
     * field number is stored in the upper 5 bits of the tag byte - but
     * is also varint encoded so the follow on bytes may need to be read
     * when field numbers are > 15.
     *
     * 从 tag 中还原字段号 field_number = tag >> 3。因为 tag 整体是 varint，
     * 字段号 > 15 时会跨字节，故用 do/while 逐字节读取：
     *   - 首字节：取 `data[offset] & NUMBER(0x78)` 再 `>> 3`（shift 从 -3 起步，
     *     即 `>> -shift`），因为字段号占 tag 中 bit3 起的位置；
     *   - 后续字节：取低 7 位 `& VALUE` 左移 shift；
     *   - shift 每轮 +7；≥28 时代入浮点乘法 `* Math.pow(2, shift)` 规避位运算溢出。
     * 循环条件同时用 `data[offset++]` 自增 offset——以 MSB 位判断是否还有后继字节。
     *
     * @private
     * @returns {number}
     */
    _fieldNumber() {
        let shift = -3;
        let fieldNumber = 0;
        do {
            fieldNumber += shift < 28 ?
                shift === -3 ?
                    (this.data[this.offset] & this.NUMBER) >> -shift :
                    (this.data[this.offset] & this.VALUE) << shift :
                (this.data[this.offset] & this.VALUE) * Math.pow(2, shift);
            shift += 7;
        } while ((this.data[this.offset++] & this.MSB) === this.MSB);
        return fieldNumber;
    }

    // Field Parsing Functions

    /**
     * Read off a varint from the data
     *
     * 解码 LEB128 varint：do/while 逐字节读，
     *   每字节取低 7 位 `& VALUE(0x7f)` 左移 shift 后累加；shift 每轮 +7。
     *   shift < 28 时用位运算 `<< shift`，≥28 时改用 `* Math.pow(2, shift)`
     *   （因为 JS 左移只保证 32 位内正确，高位需靠浮点保精度）。
     *   循环条件 `(data[offset++] & MSB) === MSB`：读出当前字节并推进 offset，
     *   只要最高位（续接标志）为 1 就继续读下一字节，为 0 则本次 varint 结束。
     * 与 varIntEncode() 互为逆运算。
     *
     * @private
     * @returns {number}
     */
    _varInt() {
        let value = 0;
        let shift = 0;
        // Keep reading while upper bit set
        do {
            value += shift < 28 ?
                (this.data[this.offset] & this.VALUE) << shift :
                (this.data[this.offset] & this.VALUE) * Math.pow(2, shift);
            shift += 7;
        } while ((this.data[this.offset++] & this.MSB) === this.MSB);
        return value;
    }

    /**
     * Read off a 64 bit unsigned integer from the data
     *
     * 读取 wire_type=1 的 64 位定长字段（fixed64/double）：
     * 按小端序分两次各取 4 字节——先低 4 字节拼成 lowerHalf，
     * 再高 4 字节拼成 upperHalf（每字节乘 0x100 的幂次累加）；
     * 最终值 = upperHalf * 2^32 + lowerHalf。
     * 因 JS Number 只有 53 位精度，超出部分会有精度损失（本库仅用于展示）。
     *
     * @private
     * @returns {number}
     */
    _uint64() {
        // Read off a Uint64 with little-endian
        const lowerHalf = this.data[this.offset++] + (this.data[this.offset++] * 0x100) + (this.data[this.offset++] * 0x10000) + this.data[this.offset++] * 0x1000000;
        const upperHalf = this.data[this.offset++] + (this.data[this.offset++] * 0x100) + (this.data[this.offset++] * 0x10000) + this.data[this.offset++] * 0x1000000;
        return upperHalf * 0x100000000 + lowerHalf;
    }

    /**
     * Read off a length delimited field from the data
     *
     * 读取 wire_type=2 的 Length-delimited 字段，是嵌套解码的关键：
     *   1. 先 _varInt() 读出长度 length，据此在 [offset, offset+length) 切出边界；
     *   2. 尝试用这段子串「新建 Protobuf 实例」并递归 _parse()——把子串当独立 message 解。
     *      之所以能定位边界，正因长度前缀显式给出了这段的字节数；
     *      子实例拥有独立的 offset/LENGTH，因此嵌套各层互不干扰（递归下降）。
     *   3. 递归成功则：合并子实例收集到的 fieldTypes 到本层（供类型展示）；
     *      递归抛错（不是合法 message）则退化为 Utils.byteArrayToChars 当字符串处理。
     *   4. 最后 offset += length 跳过整个字段体。
     * fieldNum 形参即该字段号，仅用于给 fieldTypes 记录/合并子消息的类型层级。
     *
     * @private
     * @returns {Object|string}
     */
    _lenDelim(fieldNum) {
        // Read off the field length
        const length = this._varInt();
        const fieldBytes = this.data.slice(this.offset, this.offset + length);
        let field;
        try {
            // Attempt to parse as a new Protobuf Object
            const pbObject = new Protobuf(fieldBytes);
            field = pbObject._parse();

            // Set field types object
            this.fieldTypes[fieldNum] = {...this.fieldTypes[fieldNum], ...pbObject.fieldTypes};

        } catch (err) {
            // Otherwise treat as bytes
            field = Utils.byteArrayToChars(fieldBytes);
        }
        // Move the offset and return the field
        this.offset += length;
        return field;
    }

    /**
     * Read a 32 bit unsigned integer from the data
     *
     * 读取 wire_type=5 的 32 位定长字段（fixed32/float）：
     * 截取 4 字节包进 DataView，用 getUint32(0, true) 以小端序取出，offset 前进 4。
     * 用 DataView 而非手写移位，避免符号位/溢出问题。
     *
     * @private
     * @returns {number}
     */
    _uint32() {
        // Use a dataview to read off the integer
        const dataview = new DataView(new Uint8Array(this.data.slice(this.offset, this.offset + 4)).buffer);
        const value = dataview.getUint32(0, true);
        this.offset += 4;
        return value;
    }
}

export default Protobuf;
