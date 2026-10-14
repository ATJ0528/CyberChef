/**
 * @author c65722 []
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— TLS 记录层与握手协议
 * 【操作】Parse TLS record
 * 【功能】把一段（或连续多段）原始 TLS Record 字节流，逐层拆解为
 *         记录层首部 + 握手子协议（Hello/Certificate/…）+ 扩展字段的可读结构
 * 【输入】ArrayBuffer —— 完整的 TLS 记录流（可含多条记录，也可只含一条）
 * 【输出】json —— 解析结果对象数组；presentType 为 html，界面按表格展示
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 用 Stream 包裹整个输入，while (s.hasMore()) 逐条读取 Record
 *   2. _readRecord()：读 5 字节记录头（ContentType / Version / Length），
 *      再按 Length 取出记录载荷 content
 *   3. 载荷若为 HANDSHAKE（类型码 22）则交给 HandshakeParser 继续拆；
 *      其它类型（Alert/AppData/CCS）直接把整段载荷转 hex 存入 value
 *   4. HandshakeParser：读 1 字节 msg_type + 3 字节 length，
 *      再按消息类型分派到各自的子解析器（ClientHello/ServerHello/…）
 *   5. 子解析器按 RFC 5246/8446 的定长或长度前缀结构逐字段读取
 *   6. present()：用 objToTable 把每个结果对象递归渲染成 HTML 表格
 * ------------------------------------------------------------
 * 【关键算法】TLV 解析 + Stream 游标状态机
 *   - 长度前缀（TLV）：TLS 里绝大多数变长字段都是"长度字段在前、内容在后"，
 *     统一用 readSizePrefixedBytesAsHex() 读取，避免每个解析器重复实现
 *   - Stream 游标：所有读取都靠 input.position 单向推进；一旦发现越界，
 *     一律 moveTo(length) 把游标推到流末尾，保证外层 while 能正常收敛退出
 *   - 名称查表：构造函数把 ContentType / HandshakeType 枚举反转成
 *     "数值 → 名称" 映射，未知类型用 ?? 退化为十进制数字字符串
 *   - 截断容错：每个长度前缀字段读完都比对声明长度与实读长度，
 *     不足则记 truncated: true，而不是抛异常中断解析
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 每个子解析器只关心"自己这一段字节"，因此都重新 new Stream(局部切片)，
 *     实现各协议层互相解耦
 *   - 用 Object.freeze 的枚举对象集中管理协议常量，可读性远好于散落的魔法数字
 *   - `{...recordHeader}` 与 `{...output, ...子结果}` 展开语法把头部字段
 *     与各层解析结果扁平合并，最终交给 present() 统一渲染
 * ============================================================
 */

import Operation from "../Operation.mjs";
import {toHexFast} from "../lib/Hex.mjs";
import {objToTable} from "../lib/Protocol.mjs";
import Stream from "../lib/Stream.mjs";

/**
 * 【类】ParseTLSRecord —— 顶层操作类，对应 CyberChef 界面上的
 *      "Parse TLS record" 操作，继承自 Operation 基类。
 *
 * 持有两个跨调用复用的对象：
 *   - _handshakeParser：握手消息解析器（内部又聚合了六个子消息解析器）
 *   - _contentTypes：ContentType 数值 → 小写名称的反向查找表，
 *     在构造函数里由 ContentType 枚举一次性构建
 */
/**
 * Parse TLS record operation.
 */
class ParseTLSRecord extends Operation {

    /**
     * 【构造函数】声明操作元信息并准备解析器
     *
     * inputType   = "ArrayBuffer" —— 直接拿到原始字节，不做文本转换
     * outputType  = "json"        —— run() 返回结构化对象数组
     * presentType = "html"        —— 呈现阶段用 present() 渲染成表格
     * args        = []            —— 本操作无参数，全自动解析
     *
     * for...in 遍历 ContentType 时，key 是枚举名、ContentType[key] 是数值，
     * 因此建立的是 "数值 → 名称" 映射，供 _readRecord 把 type 字段翻译成名字。
     */
    /**
     * ParseTLSRecord constructor.
     */
    constructor() {
        super();

        this.name = "Parse TLS record";
        this.module = "Default";
        this.description = "Parses one or more TLS records";
        this.infoURL = "https://wikipedia.org/wiki/Transport_Layer_Security";
        this.inputType = "ArrayBuffer";
        this.outputType = "json";
        this.presentType = "html";
        this.args = [];
        this._handshakeParser = new HandshakeParser();
        this._contentTypes = new Map();

        for (const key in ContentType) {
            this._contentTypes[ContentType[key]] = key.toString().toLocaleLowerCase();
        }
    }

    /**
     * 【主流程】解析一整段输入中的所有 TLS Record
     *
     * 用 Stream 包住输入并按游标推进，只要 hasMore() 为真就继续读下一条记录；
     * 当剩余字节连 5 字节记录头都读不全时，_readRecord 返回 null，循环自然收敛结束。
     */
    /**
     * @param {ArrayBuffer} input - Stream, containing one or more raw TLS Records.
     * @param {Object[]} args
     * @returns {Object[]} Array of Object representations of TLS Records contained within input.
     */
    run(input, args) {
        const s = new Stream(new Uint8Array(input));

        const output = [];

        while (s.hasMore()) {
            const record = this._readRecord(s);
            if (record) {
                output.push(record);
            }
        }

        return output;
    }

    /**
     * 【记录层解析】读取并解析一条 TLS Record
     *
     * RFC 5246 §6.2 记录层结构（共 5 字节头）：
     *   ContentType type;        // 1 字节：20=change_cipher_spec 21=alert
     *                            //        22=handshake 23=application_data
     *   ProtocolVersion version; // 2 字节：如 0x0303 表示 TLS 1.2
     *   uint16 length;           // 2 字节：后续 fragment 的字节数
     *   opaque fragment[...];    // length 字节的载荷
     *
     * 分支处理：剩余不足 5 字节（头都读不全）→ 游标推到末尾并返回 null；
     * 载荷为空 → 只返回记录头对象；类型为 HANDSHAKE → 交给 _handshakeParser 继续拆；
     * 其它类型 → 载荷整体转 hex 存进 value 字段。
     */
    /**
     * Reads a TLS Record from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw TLS Record.
     * @returns {Object} Object representation of TLS Record.
     */
    _readRecord(input) {
        const RECORD_HEADER_LEN = 5;

        if (input.position + RECORD_HEADER_LEN > input.length) {
            input.moveTo(input.length);

            return null;
        }

        const type = input.readInt(1);
        const typeString = this._contentTypes[type] ?? type.toString();
        const version = "0x" + toHexFast(input.getBytes(2));
        const length = input.readInt(2);
        const content = input.getBytes(length);
        const truncated = content.length < length;

        const recordHeader = new RecordHeader(typeString, version, length, truncated);

        if (!content.length) {
            return {...recordHeader};
        }

        if (type === ContentType.HANDSHAKE) {
            return this._handshakeParser.parse(new Stream(content), recordHeader);
        }

        const record = {...recordHeader};
        record.value = "0x" + toHexFast(content);

        return record;
    }

    /**
     * 【呈现】把解析结果数组渲染为 HTML
     *
     * 逐条调用 objToTable 递归生成字段表格（嵌套对象/数组会自动展开为子表），
     * 记录之间用空行分隔；返回值由框架以 presentType="html" 直接展示。
     */
    /**
     * Displays the parsed TLS Records in a tabular style.
     *
     * @param {Object[]} data - Array of Object representations of the TLS Records.
     * @returns {html} HTML representation of TLS Records contained within data.
     */
    present(data) {
        return data.map(r => objToTable(r)).join("\n\n");
    }
}

export default ParseTLSRecord;

/**
 * 【枚举】TLS Record 层 ContentType 取值（RFC 5246 §6.2.1）
 * 20=change_cipher_spec 21=alert 22=handshake 23=application_data
 * 用 Object.freeze 固化；构造函数会据此建立"数值 → 名称"反查表。
 */
/**
 * Repesents the known values of type field of a TLS Record header.
 */
const ContentType = Object.freeze({
    CHANGE_CIPHER_SPEC: 20,
    ALERT: 21,
    HANDSHAKE: 22,
    APPLICATION_DATA: 23,
});

/**
 * 【数据类】RecordHeader —— 仅用于承载记录层首部的三个字段
 * type=记录类型名，version=版本 hex 串，length=载荷长度；
 * 仅当载荷被截断（实读字节少于声明长度）时才附带 truncated=true。
 */
/**
 * Represents a TLS Record header
 */
class RecordHeader {
    /**
     * 【构造函数】保存记录头的 type / version / length 三个字段；
     * 仅当 truncated 为真时才写入 truncated 标记，避免结果中充斥无意义的 false。
     */
    /**
     * RecordHeader cosntructor.
     *
     * @param {string} type - String representation of TLS Record type field.
     * @param {string} version - Hex representation of TLS Record version field.
     * @param {int} length - Length of TLS Record.
     * @param {bool} truncated - Is TLS Record truncated.
     */
    constructor(type, version, length, truncated) {
        this.type = type;
        this.version = version;
        this.length = length;

        if (truncated) {
            this.truncated = true;
        }
    }
}

/**
 * 【类】HandshakeParser —— TLS 握手消息解析器
 *
 * 聚合了 ClientHello / ServerHello / NewSessionTicket / Certificate /
 * CertificateRequest / CertificateVerify 六个子解析器，
 * 并在构造时建立 HandshakeType（msg_type 数值）→ 名称 的反查表。
 */
/**
 * Parses TLS Handshake messages.
 */
class HandshakeParser {

    /**
     * 【构造函数】实例化六个握手子消息解析器，并构建
     * HandshakeType（msg_type 数值）→ 名称 的反查表。
     */
    /**
     * HandshakeParser constructor.
     */
    constructor() {
        this._clientHelloParser = new ClientHelloParser();
        this._serverHelloParser = new ServerHelloParser();
        this._newSessionTicketParser = new NewSessionTicketParser();
        this._certificateParser = new CertificateParser();
        this._certificateRequestParser = new CertificateRequestParser();
        this._certificateVerifyParser = new CertificateVerifyParser();
        this._handshakeTypes = new Map();

        for (const key in HandshakeType) {
            this._handshakeTypes[HandshakeType[key]] = key.toString().toLowerCase();
        }
    }

    /**
     * 【握手层解析】解析一条握手消息（记录载荷内部）
     *
     * RFC 5246 §7.4 握手消息结构：
     *   HandshakeType msg_type;    // 1 字节消息类型
     *   uint24 length;             // 3 字节消息体长度
     *   body[length];              // 变长消息体
     *
     * 关键分支：若 (handshakeLength + 4) !== 记录载荷长度，说明记录里不止
     * 这一条消息、或内容已被加密（TLS 1.3 的 Finished 等）——此时把游标复位
     * 后整体按 FINISHED 处理，直接把原始字节转 hex 输出，避免按错误结构误解析；
     * 否则按 msg_type 分派到对应子解析器，并用 {...output, ...子结果} 合并结果。
     */
    /**
     * Parses a single TLS handshake message.
     *
     * @param {Stream} input - Stream, containing a raw Handshake message.
     * @param {RecordHeader} recordHeader - TLS Record header.
     * @returns {Object} Object representation of Handshake.
     */
    parse(input, recordHeader) {
        const output = {...recordHeader};

        if (!input.hasMore()) {
            return output;
        }

        const handshakeType = input.readInt(1);
        output.handshakeType = this._handshakeTypes[handshakeType] ?? handshakeType.toString();

        if (input.position + 3 > input.length) {
            input.moveTo(input.length);

            return output;
        }

        const handshakeLength = input.readInt(3);

        if (handshakeLength + 4 !== recordHeader.length) {
            input.moveTo(0);

            output.handshakeType = this._handshakeTypes[HandshakeType.FINISHED];
            output.handshakeValue = "0x" + toHexFast(input.bytes);

            return output;
        }

        const content = input.getBytes(handshakeLength);
        if (!content.length) {
            return output;
        }

        switch (handshakeType) {
            case HandshakeType.CLIENT_HELLO:
                return {...output, ...this._clientHelloParser.parse(new Stream(content))};
            case HandshakeType.SERVER_HELLO:
                return {...output, ...this._serverHelloParser.parse(new Stream(content))};
            case HandshakeType.NEW_SESSION_TICKET:
                return {...output, ...this._newSessionTicketParser.parse(new Stream(content))};
            case HandshakeType.CERTIFICATE:
                return {...output, ...this._certificateParser.parse(new Stream(content))};
            case HandshakeType.CERTIFICATE_REQUEST:
                return {...output, ...this._certificateRequestParser.parse(new Stream(content))};
            case HandshakeType.CERTIFICATE_VERIFY:
                return {...output, ...this._certificateVerifyParser.parse(new Stream(content))};
            default:
                output.handshakeValue = "0x" + toHexFast(content);
        }

        return output;
    }
}

/**
 * 【枚举】TLS 握手消息类型 msg_type（RFC 5246 §7.4）
 * 0=hello_request 1=client_hello 2=server_hello 4=new_session_ticket
 * 11=certificate 12=server_key_exchange 13=certificate_request
 * 14=server_hello_done 15=certificate_verify 16=client_key_exchange 20=finished
 */
/**
 * Represents the known values of the msg_type field of a TLS Handshake message.
 */
const HandshakeType = Object.freeze({
    HELLO_REQUEST: 0,
    CLIENT_HELLO: 1,
    SERVER_HELLO: 2,
    NEW_SESSION_TICKET: 4,
    CERTIFICATE: 11,
    SERVER_KEY_EXCHANGE: 12,
    CERTIFICATE_REQUEST: 13,
    SERVER_HELLO_DONE: 14,
    CERTIFICATE_VERIFY: 15,
    CLIENT_KEY_EXCHANGE: 16,
    FINISHED: 20,
});

/**
 * 【类】ClientHelloParser —— 解析 ClientHello（客户端第一枪，RFC 5246 §7.4.1.2）
 *
 * 结构：ProtocolVersion client_version(2) | Random random(32) |
 *       SessionID session_id（1 字节长度前缀） |
 *       CipherSuite cipher_suites（2 字节长度前缀的列表） |
 *       CompressionMethod compression_methods（1 字节长度前缀的列表） |
 *       Extension extensions（2 字节总长度前缀）
 * 内置一个 ExtensionsParser 负责最后的扩展列表。
 */
/**
 * Parses TLS Handshake ClientHello messages.
 */
class ClientHelloParser {

    /**
     * 【构造函数】创建一个扩展解析器 ExtensionsParser 供后续使用。
     */
    /**
     * ClientHelloParser constructor.
     */
    constructor() {
        this._extensionsParser = new ExtensionsParser();
    }

    /**
     * 【主流程】严格按 RFC 5246 字段顺序读取 ClientHello：
     * 2 字节 client_version → 32 字节 random → session_id（长度前缀，可为空）→
     * cipher_suites（列表）→ compression_methods（列表）→ extensions（列表）。
     * session_id 为空时不写入 output，保持结果精简。
     */
    /**
     * Parses a single TLS Handshake ClientHello message.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message.
     * @returns {Object} Object representation of ClientHello.
     */
    parse(input) {
        const output = {};

        output.clientVersion =  this._readClientVersion(input);
        output.random = this._readRandom(input);

        const sessionID = this._readSessionID(input);
        if (sessionID) {
            output.sessionID = sessionID;
        }

        output.cipherSuites = this._readCipherSuites(input);
        output.compressionMethods = this._readCompressionMethods(input);
        output.extensions = this._readExtensions(input);

        return output;
    }

    /**
     * 【字段】client_version（2 字节）：客户端支持的最高协议版本，如 0x0303 = TLS 1.2。
     */
    /**
     * Reads the client_version field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before client_version field.
     * @returns {string} Hex representation of client_version.
     */
    _readClientVersion(input) {
        return readBytesAsHex(input, 2);
    }

    /**
     * 【字段】random（32 字节）：客户端随机数，前 4 字节通常为 Unix 时间戳，其余为随机值。
     */
    /**
     * Reads the random field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before random field.
     * @returns {string} Hex representation of random.
     */
    _readRandom(input) {
        return readBytesAsHex(input, 32);
    }

    /**
     * 【字段】session_id：1 字节长度前缀 + 变长会话 ID；用于会话复用，可为空。
     */
    /**
     * Reads the session_id field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before session_id length field.
     * @returns {string} Hex representation of session_id, or empty string if session_id not present.
     */
    _readSessionID(input) {
        return readSizePrefixedBytesAsHex(input, 1);
    }

    /**
     * 【字段】cipher_suites：2 字节总长度前缀，其后是若干 2 字节密码套件编号。
     * 先读长度；长度为 0 直接返回空对象；再按 2 字节一组循环读取。
     * 实读字节不足声明长度时标 truncated。
     */
    /**
     * Reads the cipher_suites field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before cipher_suites length field.
     * @returns {Object} Object represention of cipher_suites field.
     */
    _readCipherSuites(input) {
        const output = {};

        output.length = input.readInt(2);
        if (!output.length) {
            return {};
        }

        const cipherSuites = new Stream(input.getBytes(output.length));
        if (cipherSuites.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (cipherSuites.hasMore()) {
            const cipherSuite = readBytesAsHex(cipherSuites, 2);
            if (cipherSuite) {
                output.values.push(cipherSuite);
            }
        }

        return output;
    }

    /**
     * 【字段】compression_methods：1 字节长度前缀 + 若干 1 字节压缩方法（通常只有 0 = null）。
     */
    /**
     * Reads the compression_methods field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before compression_methods length field.
     * @returns {Object} Object representation of compression_methods field.
     */
    _readCompressionMethods(input) {
        const output = {};

        output.length = input.readInt(1);
        if (!output.length) {
            return {};
        }

        const compressionMethods = new Stream(input.getBytes(output.length));
        if (compressionMethods.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (compressionMethods.hasMore()) {
            const compressionMethod = readBytesAsHex(compressionMethods, 1);
            if (compressionMethod) {
                output.values.push(compressionMethod);
            }
        }

        return output;
    }

    /**
     * 【字段】extensions：2 字节总长度前缀，内容交给 ExtensionsParser 展开成数组。
     */
    /**
     * Reads the extensions field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ClientHello message, with position before extensions length field.
     * @returns {Object} Object representations of extensions field.
     */
    _readExtensions(input) {
        const output = {};

        output.length = input.readInt(2);
        if (!output.length) {
            return {};
        }

        const extensions = new Stream(input.getBytes(output.length));
        if (extensions.length < output.length) {
            output.truncated = true;
        }

        output.values = this._extensionsParser.parse(extensions);

        return output;
    }
}

/**
 * 【类】ServerHelloParser —— 解析 ServerHello（服务器应答，RFC 5246 §7.4.1.3）
 *
 * 结构与 ClientHello 类似，但密码套件/压缩方法是"单值"而非列表：
 *   server_version(2) | random(32) | session_id（1 字节前缀） |
 *   cipher_suite（2 字节单值） | compression_method（1 字节单值） | extensions（2 字节前缀）
 */
/**
 * Parses TLS Handshake ServeHello messages.
 */
class ServerHelloParser {

    /**
     * 【构造函数】创建一个扩展解析器 ExtensionsParser 供后续使用。
     */
    /**
     * ServerHelloParser constructor.
     */
    constructor() {
        this._extensionsParser = new ExtensionsParser();
    }

    /**
     * 【主流程】按序读取：server_version → random → session_id（可空）→
     * 服务器选定的 cipher_suite（单值 2 字节）→ compression_method（单值 1 字节）→ extensions。
     */
    /**
     *  Parses a single TLS Handshake ServerHello message.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message.
     * @return {Object} Object representation of ServerHello.
     */
    parse(input) {
        const output = {};

        output.serverVersion = this._readServerVersion(input);
        output.random = this._readRandom(input);

        const sessionID = this._readSessionID(input);
        if (sessionID) {
            output.sessionID = sessionID;
        }

        output.cipherSuite =  this._readCipherSuite(input);
        output.compressionMethod = this._readCompressionMethod(input);
        output.extensions = this._readExtensions(input);

        return output;
    }

    /**
     * 【字段】server_version（2 字节）：服务器最终选定的协议版本。
     */
    /**
     * Reads the server_version field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message, with position before server_version field.
     * @returns {string} Hex representation of server_version.
     */
    _readServerVersion(input) {
        return readBytesAsHex(input, 2);
    }

    /**
     * 【字段】random（32 字节）：服务器随机数。
     */
    /**
     * Reads the random field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message, with position before random field.
     * @returns {string} Hex representation of random.
     */
    _readRandom(input) {
        return readBytesAsHex(input, 32);
    }

    /**
     * 【字段】session_id：1 字节长度前缀 + 会话 ID；会话复用时与客户端保持一致。
     */
    /**
     * Reads the session_id field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServertHello message, with position before session_id length field.
     * @returns {string} Hex representation of session_id, or empty string if session_id not present.
     */
    _readSessionID(input) {
        return readSizePrefixedBytesAsHex(input, 1);
    }

    /**
     * 【字段】cipher_suite（2 字节单值）：服务器从客户端列表中选中的密码套件。
     */
    /**
     * Reads the cipher_suite field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message, with position before cipher_suite field.
     * @returns {string} Hex represention of cipher_suite.
     */
    _readCipherSuite(input) {
        return readBytesAsHex(input, 2);
    }

    /**
     * 【字段】compression_method（1 字节单值）：服务器选定的压缩方法。
     */
    /**
     * Reads the compression_method field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message, with position before compression_method field.
     * @returns {string} Hex represention of compression_method.
     */
    _readCompressionMethod(input) {
        return readBytesAsHex(input, 1);
    }

    /**
     * 【字段】extensions：2 字节总长度前缀，交由 ExtensionsParser 解析。
     */
    /**
     * Reads the extensions field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw ServerHello message, with position before extensions length field.
     * @returns {Object} Object representation of extensions field.
     */
    _readExtensions(input) {
        const output = {};

        output.length = input.readInt(2);
        if (!output.length) {
            return {};
        }

        const extensions = new Stream(input.getBytes(output.length));
        if (extensions.length < output.length) {
            output.truncated = true;
        }

        output.values = this._extensionsParser.parse(extensions);

        return output;
    }
}

/**
 * 【类】ExtensionsParser —— 解析 Hello 消息尾部的扩展列表
 *
 * 每个扩展是一个 TLV（RFC 5246 §7.4.1.4 / RFC 8446 §4.2）：
 *   ExtensionType extension_type; // 2 字节扩展类型
 *   uint16 extension_length;      // 2 字节扩展数据长度
 *   opaque extension_data[...];   // 变长扩展数据
 * 常见 type：0x0000=server_name(SNI) 0x002b=supported_versions
 * 0x0033=key_share 0x0010=ALPN 0x000a=supported_groups 等。
 * 本解析器只做通用 TLV 拆分，不逐类深入解释扩展内容，value 以 hex 呈现。
 */
/**
 * Parses TLS Handshake Hello Extensions.
 */
class ExtensionsParser {

    /**
     * 【主流程】循环调用 _readExtension，直到流耗尽，
     * 把连续多个扩展拆成 Object 数组（外层已保证总长度正确）。
     */
    /**
     * Parses a stream of TLS Handshake Hello Extensions.
     *
     * @param {Stream} input - Stream, containing multiple raw Extensions, with position before first extension length field.
     * @returns {Object[]} Array of Object representations of Extensions contained within input.
     */
    parse(input) {
        const output = [];

        while (input.hasMore()) {
            const extension = this._readExtension(input);
            if (extension) {
                output.push(extension);
            }
        }

        return output;
    }

    /**
     * 【单条扩展】读取一个 TLV 扩展：
     * 若剩余不足 4 字节（连 type + length 都读不全）→ 推到末尾返回 null；
     * 再读 2 字节 type（hex）、2 字节 length；长度为 0 直接返回；
     * 否则读 length 字节 value 并转 hex，实读不足则标 truncated。
     */
    /**
     * Reads a single Extension from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a list of Extensions, with position before the length field of the next Extension.
     * @returns {Object} Object representation of Extension.
     */
    _readExtension(input) {
        const output = {};

        if (input.position + 4 > input.length) {
            input.moveTo(input.length);
            return null;
        }

        output.type = "0x" + toHexFast(input.getBytes(2));
        output.length = input.readInt(2);
        if (!output.length) {
            return output;
        }

        const value = input.getBytes(output.length);
        if (!value || value.length !== output.length) {
            output.truncated = true;
        }

        if (value && value.length) {
            output.value = "0x" + toHexFast(value);
        }

        return output;
    }
}

/**
 * 【类】NewSessionTicketParser —— 解析 NewSessionTicket（RFC 5077 / RFC 8446 §4.6.1）
 *
 * 结构：uint32 ticket_lifetime_hint（4 字节）|
 *       opaque ticket<2..2^16-1>（2 字节长度前缀）。
 * 用于服务器下发会话票据，客户端后续可凭票据免完整握手续传。
 */
/**
 * Parses TLS Handshake NewSessionTicket messages.
 */
class NewSessionTicketParser {

    /**
     * 【主流程】读取 ticket_lifetime_hint（4 字节，单位秒）与 ticket（2 字节长度前缀）。
     */
    /**
     * Parses a single TLS Handshake NewSessionTicket message.
     *
     * @param {Stream} input - Stream, containing a raw NewSessionTicket message.
     * @returns {Object} Object representation of NewSessionTicket.
     */
    parse(input) {
        return {
            ticketLifetimeHint: this._readTicketLifetimeHint(input),
            ticket: this._readTicket(input),
        };
    }

    /**
     * 【字段】ticket_lifetime_hint（4 字节大端无符号数）：票据有效期，单位秒，
     * 输出时附上 "s" 后缀；剩余不足 4 字节则返回空串。
     */
    /**
     * Reads the ticket_lifetime_hint field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw NewSessionTicket message, with position before ticket_lifetime_hint field.
     * @returns {string} Lifetime hint, in seconds.
     */
    _readTicketLifetimeHint(input) {
        if (input.position + 4 > input.length) {
            input.moveTo(input.length);
            return "";
        }

        return input.readInt(4) + "s";
    }

    /**
     * 【字段】ticket：2 字节长度前缀 + 会话票据字节，hex 输出。
     */
    /**
     * Reads the ticket field fromt the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw NewSessionTicket message, with position before ticket length field.
     * @returns {string} Hex representation of ticket.
     */
    _readTicket(input) {
        return readSizePrefixedBytesAsHex(input, 2);
    }
}

/**
 * 【类】CertificateParser —— 解析 Certificate（服务器证书链，RFC 5246 §7.4.2）
 *
 * 结构：certificate_list<3 字节总长度>，其内是若干
 *       ASN.1Cert<3 字节长度 + DER 证书>。
 * 此处只按长度前缀切分证书并 hex 呈现；DER 内容本身可继续交给
 * 其它操作（如 Parse X.509）解析。
 */
/**
 * Parses TLS Handshake Certificate messages.
 */
class CertificateParser {

    /**
     * 【主流程】读取 certificate_list 字段（证书链）。
     */
    /**
     * Parses a single TLS Handshake Certificate message.
     *
     * @param {Stream} input - Stream, containing a raw Certificate message.
     * @returns {Object} Object representation of Certificate.
     */
    parse(input) {
        const output = {};

        output.certificateList = this._readCertificateList(input);

        return output;
    }

    /**
     * 【字段】certificate_list：3 字节总长度前缀，其后为若干证书，
     * 每张证书再以 3 字节长度前缀标注；剩余不足 3 字节则直接返回空对象。
     */
    /**
     * Reads the certificate_list field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw Certificate message, with position before certificate_list length field.
     * @returns {string[]} Array of strings, each containing a hex representation of a value within the certificate_list field.
     */
    _readCertificateList(input) {
        const output = {};

        if (input.position + 3 > input.length) {
            input.moveTo(input.length);
            return output;
        }

        output.length = input.readInt(3);
        if (!output.length) {
            return output;
        }

        const certificates = new Stream(input.getBytes(output.length));
        if (certificates.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (certificates.hasMore()) {
            const certificate = this._readCertificate(certificates);
            if (certificate) {
                output.values.push(certificate);
            }
        }

        return output;
    }

    /**
     * 【单张证书】3 字节长度前缀 + DER 证书字节，hex 输出。
     */
    /**
     * Reads a single certificate from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a list of certificicates, with position before the length field of the next certificate.
     * @returns {string} Hex representation of certificate.
     */
    _readCertificate(input) {
        return readSizePrefixedBytesAsHex(input, 3);
    }
}

/**
 * 【类】CertificateRequestParser —— 解析 CertificateRequest（服务器索取客户端证书，RFC 5246 §7.4.4）
 *
 * 结构：certificate_types<1..2^8-1>（1 字节长度前缀，元素 1 字节）|
 *       supported_signature_algorithms<2..2^16-2>（2 字节长度前缀，元素 2 字节）|
 *       certificate_authorities<0..2^16-1>（2 字节长度前缀，元素为 2 字节长度前缀的 DN）
 */
/**
 * Parses TLS Handshake CertificateRequest messages.
 */
class CertificateRequestParser {

    /**
     * 【主流程】依次读取 certificate_types、supported_signature_algorithms、
     * certificate_authorities；仅当 authorities 非空时才写入结果对象。
     */
    /**
     * Parses a single TLS Handshake CertificateRequest message.
     *
     * @param {Stream} input - Stream, containing a raw CertificateRequest message.
     * @return {Object} Object representation of CertificateRequest.
     */
    parse(input) {
        const output = {};

        output.certificateTypes = this._readCertificateTypes(input);
        output.supportedSignatureAlgorithms = this._readSupportedSignatureAlgorithms(input);

        const certificateAuthorities = this._readCertificateAuthorities(input);
        if (certificateAuthorities.length) {
            output.certificateAuthorities = certificateAuthorities;
        }

        return output;
    }

    /**
     * 【字段】certificate_types：1 字节长度前缀 + 若干 1 字节证书类型码
     * （如 1=rsa_sign 64=ecdsa_sign）。
     */
    /**
     * Reads the certificate_types field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateRequest message, with position before certificate_types length field.
     * @return {string[]} Array of strings, each containing a hex representation of a value within the certificate_types field.
     */
    _readCertificateTypes(input) {
        const output = {};

        output.length = input.readInt(1);
        if (!output.length) {
            return {};
        }

        const certificateTypes = new Stream(input.getBytes(output.length));
        if (certificateTypes.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (certificateTypes.hasMore()) {
            const certificateType = readBytesAsHex(certificateTypes, 1);
            if (certificateType) {
                output.values.push(certificateType);
            }
        }

        return output;
    }

    /**
     * 【字段】supported_signature_algorithms：2 字节长度前缀 + 若干 2 字节签名算法对
     * （TLS 1.2 为 hash + signature 组合，RFC 8446 统一为 SignatureScheme）。
     */
    /**
     * Reads the supported_signature_algorithms field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateRequest message, with position before supported_signature_algorithms length field.
     * @returns {string[]} Array of strings, each containing a hex representation of a value within the supported_signature_algorithms field.
     */
    _readSupportedSignatureAlgorithms(input) {
        const output = {};

        output.length = input.readInt(2);
        if (!output.length) {
            return {};
        }

        const signatureAlgorithms = new Stream(input.getBytes(output.length));
        if (signatureAlgorithms.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (signatureAlgorithms.hasMore()) {
            const signatureAlgorithm = readBytesAsHex(signatureAlgorithms, 2);
            if (signatureAlgorithm) {
                output.values.push(signatureAlgorithm);
            }
        }

        return output;
    }

    /**
     * 【字段】certificate_authorities：2 字节长度前缀，其内每个 DN（可分辨名称）
     * 再带 2 字节长度前缀。
     */
    /**
     * Reads the certificate_authorities field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateRequest message, with position before certificate_authorities length field.
     * @returns {string[]} Array of strings, each containing a hex representation of a value within the certificate_authorities field.
     */
    _readCertificateAuthorities(input) {
        const output = {};

        output.length = input.readInt(2);
        if (!output.length) {
            return {};
        }

        const certificateAuthorities = new Stream(input.getBytes(output.length));
        if (certificateAuthorities.length < output.length) {
            output.truncated = true;
        }

        output.values = [];

        while (certificateAuthorities.hasMore()) {
            const certificateAuthority = this._readCertificateAuthority(certificateAuthorities);
            if (certificateAuthority) {
                output.values.push(certificateAuthority);
            }
        }

        return output;
    }

    /**
     * 【单个 CA】2 字节长度前缀 + 可分辨名称（DN）字节，hex 输出。
     */
    /**
     * Reads a single certificate authority from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a list of raw certificate authorities, with position before the length field of the next certificate authority.
     * @returns {string} Hex representation of certificate authority.
     */
    _readCertificateAuthority(input) {
        return readSizePrefixedBytesAsHex(input, 2);
    }
}

/**
 * 【类】CertificateVerifyParser —— 解析 CertificateVerify（客户端证明持有私钥，RFC 5246 §7.4.8）
 *
 * 结构：algorithm{HashAlgorithm hash(1); SignatureAlgorithm signature(1)} |
 *       signature<0..2^16-1>（2 字节长度前缀）。
 * 注意：RFC 8446 已把 algorithm 改为 2 字节 SignatureScheme，
 * 本实现仍按 TLS 1.2 的 1 + 1 字节算法对读取。
 */
/**
 * Parses TLS Handshake CertificateVerify messages.
 */
class CertificateVerifyParser {

    /**
     * 【主流程】读取 algorithm.hash、algorithm.signature、signature 三个字段。
     */
    /**
     * Parses a single CertificateVerify Message.
     *
     * @param {Stream} input - Stream, containing a raw CertificateVerify message.
     * @returns {Object} Object representation of CertificateVerify.
     */
    parse(input) {
        return {
            algorithmHash: this._readAlgorithmHash(input),
            algorithmSignature: this._readAlgorithmSignature(input),
            signature: this._readSignature(input),
        };
    }

    /**
     * 【字段】algorithm.hash（1 字节）：摘要算法，如 4 = sha256。
     */
    /**
     * Reads the algorithm.hash field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateVerify message, with position before algorithm.hash field.
     * @return {string} Hex representation of hash algorithm.
     */
    _readAlgorithmHash(input) {
        return readBytesAsHex(input, 1);
    }

    /**
     * 【字段】algorithm.signature（1 字节）：签名算法，如 1 = rsa。
     */
    /**
     * Reads the algorithm.signature field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateVerify message, with position before algorithm.signature field.
     * @return {string} Hex representation of signature algorithm.
     */
    _readAlgorithmSignature(input) {
        return readBytesAsHex(input, 1);
    }

    /**
     * 【字段】signature：2 字节长度前缀 + 签名值字节，hex 输出。
     */
    /**
     * Reads the signature field from the following bytes in the provided Stream.
     *
     * @param {Stream} input - Stream, containing a raw CertificateVerify message, with position before signature field.
     * @return {string} Hex representation of signature.
     */
    _readSignature(input) {
        return readSizePrefixedBytesAsHex(input, 2);
    }
}

/**
 * 【工具函数】读取"长度前缀 + 内容"的变长字段并返回 hex 串
 *
 * 先按 sizePrefixLength（1/2/3 字节）读出长度；长度为 0 返回空串；
 * 否则再读 length 字节内容。TLS 中 session_id / ticket / certificate /
 * certificate_authority 等大量字段都是这种 TLV 形态，此处统一抽象，
 * 避免各解析器重复实现同一套读取逻辑。
 */
/**
 * Read the following size prefixed bytes from the provided Stream, and reuturn as a hex string.
 *
 * @param {Stream} input - Stream to read from.
 * @param {int} sizePrefixLength - Length of the size prefix field.
 * @returns {string} Hex representation of bytes read from Stream, empty string is returned if
 *                   field cannot be read in full.
 */
function readSizePrefixedBytesAsHex(input, sizePrefixLength) {
    const length = input.readInt(sizePrefixLength);
    if (!length) {
        return "";
    }

    return readBytesAsHex(input, length);
}

/**
 * 【工具函数】从流中读 n 个字节并返回带 "0x" 前缀的 hex 字符串
 *
 * 读不满 n 字节（流在末尾被截断）时返回空串而不是抛异常，
 * 保证畸形 / 截断报文也能尽力输出，与整个解析器的容错策略一致。
 */
/**
 * Read n bytes from the provided Stream, and return as a hex string.
 *
 * @param {Stream} input - Stream to read from.
 * @param {int} n - Number of bytes to read.
 * @returns {string} Hex representation of bytes read from Stream, or empty string if field cannot
 *                   be read in full.
 */
function readBytesAsHex(input, n) {
    const bytes = input.getBytes(n);
    if (!bytes || bytes.length !== n) {
        return "";
    }

    return "0x" + toHexFast(bytes);
}
