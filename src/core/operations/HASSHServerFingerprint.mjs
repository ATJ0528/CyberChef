/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2021
 * @license Apache-2.0
 *
 * HASSH created by Salesforce
 *   Ben Reardon (@benreardon)
 *   Adel Karimi (@0x4d31)
 *   and the JA3 crew:
 *     John B. Althouse
 *     Jeff Atkinson
 *     Josh Atkins
 *
 * Algorithm released under the BSD-3-clause licence
*/

/**
 * ============================================================
 * 【模块】SSH 指纹（Crypto）— HASSH 服务端指纹
 * 【操作】HASSH Server Fingerprint
 * 【功能】解析服务端发来的 SSH_MSG_KEXINIT，拼接算法列表取 MD5，标识 SSH 服务端
 * 【输入】string —— SSH_MSG_KEXINIT（Server→Client）应用层报文的 Hex / Base64 / Raw
 * 【输出】string —— MD5 摘要 / HASSH 算法串 / 完整细节
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 转字节数组并包成 Stream 游标
 *   2. 读 4 字节包长度并核对，读 1 字节 padding length、1 字节 message code（须为 20 = SSH_MSG_KEXINIT）
 *   3. 跳过 16 字节 cookie
 *   4. 依次读取各算法名称列表（每段 4 字节长度 + 名称串）：
 *        kex / host key / enc C2S / enc S2C / mac C2S / mac S2C / comp C2S / comp S2C / lang C2S / lang S2C
 *   5. 跳过 1 字节 first_kex_packet_follows、4 字节 reserved、paddingLength 字节 padding
 *   6. 拼接 kexAlgos;encAlgosS2C;macAlgosS2C;compAlgosS2C 得 HASSH 串，取 MD5 得摘要
 *   7. 按 Output format 返回摘要 / 算法串 / 完整细节
 * ------------------------------------------------------------
 * 【关键算法】
 *   HASSH = MD5( kexAlgorithms ; encryptionAlgorithmsServerToClient ; macAlgorithmsServerToClient ; compressionAlgorithmsServerToClient )
 *   四个字段用英文分号 ";" 连接；每个字段本身是算法名列表的**原字符串**
 *   （列表内部由算法名以英文逗号分隔），因此拼接时不展开列表
 *   服务端指纹只取 Server→Client 方向的 enc / mac / comp 算法
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - Stream 游标 API：readInt(n) 读 n 字节大端整数，readString(len) 读成字符串，moveForwardsBy(n) 跳过
 *   - 客户端→服务端方向的算法段只在帧内占位，用 moveForwardsBy 跳过即可
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Utils from "../Utils.mjs";
import Stream from "../lib/Stream.mjs";
import {runHash} from "../lib/Hash.mjs";

/**
 * HASSH Server Fingerprint operation
 *
 * 继承 Operation 基类，run() 内以游标顺序解析 SSH_MSG_KEXINIT 字节流。
 */
class HASSHServerFingerprint extends Operation {

    /**
     * HASSHServerFingerprint constructor
     *
     * 声明元信息与参数：
     *   name "HASSH Server Fingerprint"、module "Crypto"、inputType / outputType 均为 string
     *   args[0] "Input format"  —— Hex / Base64 / Raw
     *   args[1] "Output format" —— Hash digest（MD5 摘要）/ HASSH algorithms string / Full details
     */
    constructor() {
        super();

        this.name = "HASSH Server Fingerprint";
        this.module = "Crypto";
        this.description = "Generates a HASSH fingerprint to help identify SSH servers based on hashing together values from the Server Key Exchange Init message.<br><br>Input: A hex stream of the SSH_MSG_KEXINIT packet application layer from Server to Client.";
        this.infoURL = "https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c";
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
                value: ["Hash digest", "HASSH algorithms string", "Full details"]
            }
        ];
    }

    /**
     * 【主流程】计算 HASSH 服务端指纹
     *
     * args[0] = Input format，args[1] = Output format
     * 逐个读取 SSH_MSG_KEXINIT 的算法名称列表，取服务端方向字段拼接后取 MD5
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [inputFormat, outputFormat] = args;

        // --- 步骤 1：转字节数组、包 Stream 游标，并读 4 字节包长度校验 ---
        input = Utils.convertToByteArray(input, inputFormat);
        const s = new Stream(new Uint8Array(input));

        // Length
        const length = s.readInt(4);
        if (s.length !== length + 4)
            throw new OperationError("Incorrect packet length.");

        // --- 步骤 2：读 padding length 与 message code（须为 20 = SSH_MSG_KEXINIT）---
        // Padding length
        const paddingLength = s.readInt(1);

        // Message code
        const messageCode = s.readInt(1);
        if (messageCode !== 20)
            throw new OperationError("Not a Key Exchange Init.");

        // --- 步骤 3：跳过 16 字节 cookie ---
        // Cookie
        s.moveForwardsBy(16);

        // --- 步骤 4：依次读取各算法名称列表（kex / host key / enc / mac / comp / lang，各含 C2S 与 S2C）---
        // KEX Algorithms
        const kexAlgosLength = s.readInt(4);
        const kexAlgos = s.readString(kexAlgosLength);

        // Server Host Key Algorithms
        const serverHostKeyAlgosLength = s.readInt(4);
        s.moveForwardsBy(serverHostKeyAlgosLength);

        // Encryption Algorithms Client to Server
        const encAlgosC2SLength = s.readInt(4);
        s.moveForwardsBy(encAlgosC2SLength);

        // Encryption Algorithms Server to Client
        const encAlgosS2CLength = s.readInt(4);
        const encAlgosS2C = s.readString(encAlgosS2CLength);

        // MAC Algorithms Client to Server
        const macAlgosC2SLength = s.readInt(4);
        s.moveForwardsBy(macAlgosC2SLength);

        // MAC Algorithms Server to Client
        const macAlgosS2CLength = s.readInt(4);
        const macAlgosS2C = s.readString(macAlgosS2CLength);

        // Compression Algorithms Client to Server
        const compAlgosC2SLength = s.readInt(4);
        s.moveForwardsBy(compAlgosC2SLength);

        // Compression Algorithms Server to Client
        const compAlgosS2CLength = s.readInt(4);
        const compAlgosS2C = s.readString(compAlgosS2CLength);

        // Languages Client to Server
        const langsC2SLength = s.readInt(4);
        s.moveForwardsBy(langsC2SLength);

        // Languages Server to Client
        const langsS2CLength = s.readInt(4);
        s.moveForwardsBy(langsS2CLength);

        // --- 步骤 5：跳过 first_kex_packet_follows、reserved 与填充字节 ---
        // First KEX packet follows
        s.moveForwardsBy(1);

        // Reserved
        s.moveForwardsBy(4);

        // Padding string
        s.moveForwardsBy(paddingLength);

        // --- 步骤 6：按 kex;encS2C;macS2C;compS2C 拼接为 HASSH 串，再取 MD5 摘要 ---
        // Output
        const hassh = [
            kexAlgos,
            encAlgosS2C,
            macAlgosS2C,
            compAlgosS2C
        ];
        const hasshStr = hassh.join(";");
        const hasshHash = runHash("md5", Utils.strToArrayBuffer(hasshStr));

        switch (outputFormat) {
            case "HASSH algorithms string":
                return hasshStr;
            case "Full details":
                return `Hash digest:
${hasshHash}

Full HASSH algorithms string:
${hasshStr}

Key Exchange Algorithms:
${kexAlgos}
Encryption Algorithms Server to Client:
${encAlgosS2C}
MAC Algorithms Server to Client:
${macAlgosS2C}
Compression Algorithms Server to Client:
${compAlgosS2C}`;
            case "Hash digest":
            default:
                return hasshHash;
        }
    }

}

export default HASSHServerFingerprint;
