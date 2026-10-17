/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2021
 * @license Apache-2.0
 *
 * JA3 created by Salesforce
 *   John B. Althouse
 *   Jeff Atkinson
 *   Josh Atkins
 *
 * Algorithm released under the BSD-3-clause licence
 */

/**
 * ============================================================
 * 【模块】TLS 指纹（Crypto）— JA3 客户端指纹
 * 【操作】JA3 Fingerprint
 * 【功能】解析 TLS ClientHello，按五元组拼串取 MD5，用于标识 / 聚类 TLS 客户端
 * 【输入】string —— TLS ClientHello 应用层报文的 Hex / Base64 / Raw
 * 【输出】string —— MD5 摘要 / JA3 字符串 / 完整细节
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 按 Input format 把输入转成字节数组，包成 Stream 游标
 *   2. 校验 TLS 记录：首字节须 0x16（Handshake），核对记录长度，握手类型须 0x01（ClientHello）
 *   3. 依次跳过 Version(2)、Hello Version(2)、Random(32)，读 Session ID 长度并跳过
 *   4. 读密码套件段，parseJA3Segment 展开为 "-" 连接的口令套件列表
 *   5. 跳过压缩方法段
 *   6. 解析扩展段：0x0a 椭圆曲线、0x0b EC 点格式各自展开，其余扩展仅记录类型号
 *   7. 五元组逗号拼接得 JA3 字符串，再取 MD5 得摘要
 *   8. 按 Output format 返回摘要 / JA3 串 / 完整细节
 * ------------------------------------------------------------
 * 【关键算法】
 *   JA3 = MD5( helloVersion , cipherSuites , extensions , ellipticCurves , ellipticCurvePointFormats )
 *   五元组均为字符串，用英文逗号 "," 连接：
 *     - helloVersion              : ClientHello 版本号（十进制，如 771）
 *     - cipherSuites              : 密码套件 2 字节值（十进制），"-" 连接
 *     - extensions                : 扩展类型号（十进制），"-" 连接
 *     - ellipticCurves            : 扩展 0x0a 内的曲线值（十进制），"-" 连接
 *     - ellipticCurvePointFormats : 扩展 0x0b 内的点格式值（十进制），"-" 连接
 *   所有列表在展开时都剔除 GREASE 值（0x?a?a 形式）
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - GREASE_CIPHERSUITES 常量枚举全部 16 个 GREASE 值，规范要求指纹必须忽略它们
 *   - parseJA3Segment 是通用段解析器：元素宽度由 size 参数决定（套件 / 曲线 2 字节，点格式 1 字节）
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Utils from "../Utils.mjs";
import Stream from "../lib/Stream.mjs";
import {runHash} from "../lib/Hash.mjs";

/**
 * JA3 Fingerprint operation
 *
 * 继承 Operation 基类，run() 内以游标顺序解析 ClientHello 字节流。
 */
class JA3Fingerprint extends Operation {

    /**
     * JA3Fingerprint constructor
     *
     * 声明元信息与参数：
     *   name "JA3 Fingerprint"、module "Crypto"、inputType / outputType 均为 string
     *   args[0] "Input format"  —— Hex / Base64 / Raw
     *   args[1] "Output format" —— Hash digest（MD5 摘要）/ JA3 string（五元组串）/ Full details
     */
    constructor() {
        super();

        this.name = "JA3 Fingerprint";
        this.module = "Crypto";
        this.description = "Generates a JA3 fingerprint to help identify TLS clients based on hashing together values from the Client Hello.<br><br>Input: A hex stream of the TLS Client Hello packet application layer.";
        this.infoURL = "https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Input format",
                type: "option",
                value: ["Hex", "Base64", "Raw"]
            },
            {
                name: "Output format",
                type: "option",
                value: ["Hash digest", "JA3 string", "Full details"]
            }
        ];
    }

    /**
     * 【主流程】计算 JA3 客户端指纹
     *
     * args[0] = Input format，args[1] = Output format
     * 严格按 ClientHello 报文结构逐字节推进游标解析，最终五元组取 MD5
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [inputFormat, outputFormat] = args;

        // --- 步骤 1：输入格式归一化为字节数组，并包成可顺序读取的 Stream 游标 ---
        input = Utils.convertToByteArray(input, inputFormat);
        const s = new Stream(new Uint8Array(input));

        // --- 步骤 2：校验 TLS 记录头与握手类型（首字节 0x16，握手类型须为 ClientHello=0x01）---
        const handshake = s.readInt(1);
        if (handshake !== 0x16)
            throw new OperationError("Not handshake data.");

        // Version
        s.moveForwardsBy(2);

        // Length
        const length = s.readInt(2);
        if (s.length !== length + 5)
            throw new OperationError("Incorrect handshake length.");

        // Handshake type
        const handshakeType = s.readInt(1);
        if (handshakeType !== 1)
            throw new OperationError("Not a Client Hello.");

        // Handshake length
        const handshakeLength = s.readInt(3);
        if (s.length !== handshakeLength + 9)
            throw new OperationError("Not enough data in Client Hello.");

        // --- 步骤 3：跳过 Version / Hello Version / Random / Session ID，定位到密码套件段 ---
        // Hello version
        const helloVersion = s.readInt(2);

        // Random
        s.moveForwardsBy(32);

        // Session ID
        const sessionIDLength = s.readInt(1);
        s.moveForwardsBy(sessionIDLength);

        // --- 步骤 4–5：读密码套件段展开为 "-" 连接列表，随后跳过压缩方法段 ---
        // Cipher suites
        const cipherSuitesLength = s.readInt(2);
        const cipherSuites = s.getBytes(cipherSuitesLength);
        const cs = new Stream(cipherSuites);
        const cipherSegment = parseJA3Segment(cs, 2);

        // Compression Methods
        const compressionMethodsLength = s.readInt(1);
        s.moveForwardsBy(compressionMethodsLength);

        // --- 步骤 6：解析扩展段：0x0a 椭圆曲线、0x0b EC 点格式展开，其余仅记类型号（过滤 GREASE）---
        // Extensions
        const extensionsLength = s.readInt(2);
        const extensions = s.getBytes(extensionsLength);
        const es = new Stream(extensions);
        let ecsLen, ecs, ellipticCurves = "", ellipticCurvePointFormats = "";
        const exts = [];
        while (es.hasMore()) {
            const type = es.readInt(2);
            const length = es.readInt(2);
            switch (type) {
                case 0x0a: // Elliptic curves
                    ecsLen = es.readInt(2);
                    ecs = new Stream(es.getBytes(ecsLen));
                    ellipticCurves = parseJA3Segment(ecs, 2);
                    break;
                case 0x0b: // Elliptic curve point formats
                    ecsLen = es.readInt(1);
                    ecs = new Stream(es.getBytes(ecsLen));
                    ellipticCurvePointFormats = parseJA3Segment(ecs, 1);
                    break;
                default:
                    es.moveForwardsBy(length);
            }
            if (!GREASE_CIPHERSUITES.includes(type))
                exts.push(type);
        }

        // --- 步骤 7：五元组以逗号拼接为 JA3 字符串，再取 MD5 摘要 ---
        // Output
        const ja3 = [
            helloVersion.toString(),
            cipherSegment,
            exts.join("-"),
            ellipticCurves,
            ellipticCurvePointFormats
        ];
        const ja3Str = ja3.join(",");
        const ja3Hash = runHash("md5", Utils.strToArrayBuffer(ja3Str));

        switch (outputFormat) {
            case "JA3 string":
                return ja3Str;
            case "Full details":
                return `Hash digest:
${ja3Hash}

Full JA3 string:
${ja3Str}

TLS Version:
${helloVersion.toString()}
Cipher Suites:
${cipherSegment}
Extensions:
${exts.join("-")}
Elliptic Curves:
${ellipticCurves}
Elliptic Curve Point Formats:
${ellipticCurvePointFormats}`;
            case "Hash digest":
            default:
                return ja3Hash;
        }
    }

}

/**
 * Parses a JA3 segment, returning a "-" separated list
 *
 * 按 size 字节宽度依次读取元素，剔除 GREASE 值，返回以 "-" 连接的结果串；
 * 用于展开密码套件段、椭圆曲线段、EC 点格式段
 *
 * @param {Stream} stream
 * @returns {string}
 */
function parseJA3Segment(stream, size=2) {
    const segment = [];
    while (stream.hasMore()) {
        const element = stream.readInt(size);
        if (!GREASE_CIPHERSUITES.includes(element))
            segment.push(element);
    }
    return segment.join("-");
}

// GREASE 值全集（RFC 8701）：客户端故意放置的无意义占位值，JA3 指纹计算须忽略
const GREASE_CIPHERSUITES = [
    0x0a0a,
    0x1a1a,
    0x2a2a,
    0x3a3a,
    0x4a4a,
    0x5a5a,
    0x6a6a,
    0x7a7a,
    0x8a8a,
    0x9a9a,
    0xaaaa,
    0xbaba,
    0xcaca,
    0xdada,
    0xeaea,
    0xfafa
];

export default JA3Fingerprint;
