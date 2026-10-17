/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2021
 * @license Apache-2.0
 *
 * JA3S created by Salesforce
 *   John B. Althouse
 *   Jeff Atkinson
 *   Josh Atkins
 *
 * Algorithm released under the BSD-3-clause licence
 */

/**
 * ============================================================
 * 【模块】TLS 指纹（Crypto）— JA3S 服务端指纹
 * 【操作】JA3S Fingerprint
 * 【功能】解析 TLS ServerHello，按三元组拼串取 MD5，用于标识 / 聚类 TLS 服务端
 * 【输入】string —— TLS ServerHello 应用层报文的 Hex / Base64 / Raw
 * 【输出】string —— MD5 摘要 / JA3S 字符串 / 完整细节
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 按 Input format 转字节数组并包成 Stream 游标
 *   2. 校验 TLS 记录：首字节须 0x16（Handshake），核对记录长度，握手类型须 0x02（ServerHello）
 *   3. 依次跳过 Version(2)、Hello Version(2)、Random(32)，读 Session ID 长度并跳过
 *   4. 读取单个选定的 Cipher Suite（2 字节），跳过 Compression Method(1)
 *   5. 遍历扩展段，仅记录每个扩展的类型号（内容整体跳过）
 *   6. 三元组逗号拼接得 JA3S 字符串，再取 MD5 得摘要
 *   7. 按 Output format 返回摘要 / JA3S 串 / 完整细节
 * ------------------------------------------------------------
 * 【关键算法】
 *   JA3S = MD5( helloVersion , cipherSuite , extensions )
 *   三元组用英文逗号 "," 连接：
 *     - helloVersion : ServerHello 版本号（十进制）
 *     - cipherSuite  : 服务端选定的单个密码套件（十进制）
 *     - extensions   : 全部扩展类型号（十进制），"-" 连接
 *   与 JA3 不同，JA3S 侧不剔除 GREASE 值，全部扩展类型号都参与拼接
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - ServerHello 只协商一个密码套件，故 cipherSuite 是标量而非列表
 *   - 扩展段只读 type 与 length，随后 moveForwardsBy(length) 整体跳过，无需解析内容
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Utils from "../Utils.mjs";
import Stream from "../lib/Stream.mjs";
import {runHash} from "../lib/Hash.mjs";

/**
 * JA3S Fingerprint operation
 *
 * 继承 Operation 基类，run() 内以游标顺序解析 ServerHello 字节流。
 */
class JA3SFingerprint extends Operation {

    /**
     * JA3SFingerprint constructor
     *
     * 声明元信息与参数：
     *   name "JA3S Fingerprint"、module "Crypto"、inputType / outputType 均为 string
     *   args[0] "Input format"  —— Hex / Base64 / Raw
     *   args[1] "Output format" —— Hash digest（MD5 摘要）/ JA3S string（三元组串）/ Full details
     */
    constructor() {
        super();

        this.name = "JA3S Fingerprint";
        this.module = "Crypto";
        this.description = "Generates a JA3S fingerprint to help identify TLS servers based on hashing together values from the Server Hello.<br><br>Input: A hex stream of the TLS Server Hello record application layer.";
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
                value: ["Hash digest", "JA3S string", "Full details"]
            }
        ];
    }

    /**
     * 【主流程】计算 JA3S 服务端指纹
     *
     * args[0] = Input format，args[1] = Output format
     * 严格按 ServerHello 报文结构逐字节推进游标解析，最终三元组取 MD5
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

        // --- 步骤 2：校验 TLS 记录头与握手类型（首字节 0x16，握手类型须为 ServerHello=0x02）---
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
        if (handshakeType !== 2)
            throw new OperationError("Not a Server Hello.");

        // Handshake length
        const handshakeLength = s.readInt(3);
        if (s.length !== handshakeLength + 9)
            throw new OperationError("Not enough data in Server Hello.");

        // --- 步骤 3：跳过 Version / Hello Version / Random / Session ID，定位到密码套件字节 ---
        // Hello version
        const helloVersion = s.readInt(2);

        // Random
        s.moveForwardsBy(32);

        // Session ID
        const sessionIDLength = s.readInt(1);
        s.moveForwardsBy(sessionIDLength);

        // --- 步骤 4：读取单个选定的密码套件，随后跳过压缩方法字节 ---
        // Cipher suite
        const cipherSuite = s.readInt(2);

        // Compression Method
        s.moveForwardsBy(1);

        // --- 步骤 5：遍历扩展段，仅记录每个扩展的类型号（内容整体跳过，不过滤 GREASE）---
        // Extensions
        const extensionsLength = s.readInt(2);
        const extensions = s.getBytes(extensionsLength);
        const es = new Stream(extensions);
        const exts = [];
        while (es.hasMore()) {
            const type = es.readInt(2);
            const length = es.readInt(2);
            es.moveForwardsBy(length);
            exts.push(type);
        }

        // --- 步骤 6：三元组以逗号拼接为 JA3S 字符串，再取 MD5 摘要 ---
        // Output
        const ja3s = [
            helloVersion.toString(),
            cipherSuite,
            exts.join("-")
        ];
        const ja3sStr = ja3s.join(",");
        const ja3sHash = runHash("md5", Utils.strToArrayBuffer(ja3sStr));

        switch (outputFormat) {
            case "JA3S string":
                return ja3sStr;
            case "Full details":
                return `Hash digest:
${ja3sHash}

Full JA3S string:
${ja3sStr}

TLS Version:
${helloVersion.toString()}
Cipher Suite:
${cipherSuite}
Extensions:
${exts.join("-")}`;
            case "Hash digest":
            default:
                return ja3sHash;
        }
    }

}

export default JA3SFingerprint;
