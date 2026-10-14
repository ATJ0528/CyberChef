/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】TLS 指纹（Crypto）— JA4S 服务端指纹
 * 【操作】JA4Server Fingerprint
 * 【功能】解析 TLS / QUIC ServerHello，计算 JA4S 服务端指纹
 * 【输入】string —— TLS 或 QUIC ServerHello 应用层报文的 Hex / Base64 / Raw
 * 【输出】string —— JA4S / JA4S_r / 两者
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 按 Input format 把输入转成字节数组
 *   2. 调用 lib/JA4.mjs 的 toJA4S() 得到 {JA4S, JA4S_r}
 *   3. 按 Output format 返回 JA4S、JA4S_r 或两者
 * ------------------------------------------------------------
 * 【关键算法】（实现见 src/core/lib/JA4.mjs）
 *   JA4S = "a 段_cipher_扩展哈希"，各段用下划线 "_" 分隔：
 *     a 段 = 协议 + 版本 + 扩展数 + ALPN
 *        · 协议   : "t"（TCP）或 "q"（QUIC，当前仅实现 t）
 *        · 版本   : supported_versions 扩展最高值映射为 13/12/11/10/s3/s2/s1/00
 *        · 扩展数 : 扩展总数，2 位补零
 *        · ALPN   : 选定 ALPN 首值首末字符，无则 "00"
 *     cipher      : 服务端选定的密码套件十六进制（4 位）
 *     扩展哈希     : 扩展类型 4 位十六进制列表（逗号连接）的 SHA256 前 12 位
 *   JA4S_r 用扩展原始列表串替代哈希（对应 JA4 的 raw 变体）
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 与 JA4 客户端不同，JA4S 的 a 段不含密码套件数（服务端只选一个套件）而含扩展数
 *   - 算法封装在 lib/JA4.mjs，本操作仅做输入转换与输出选择
 * ============================================================
 */

import Operation from "../Operation.mjs";
import Utils from "../Utils.mjs";
import {toJA4S} from "../lib/JA4.mjs";

/**
 * JA4Server Fingerprint operation
 *
 * 继承 Operation 基类，真正算法委托给 lib/JA4.mjs 的 toJA4S()。
 */
class JA4ServerFingerprint extends Operation {

    /**
     * JA4ServerFingerprint constructor
     *
     * 声明元信息与参数：
     *   name "JA4Server Fingerprint"、module "Crypto"、inputType / outputType 均为 string
     *   args[0] "Input format"  —— Hex / Base64 / Raw
     *   args[1] "Output format" —— JA4S / JA4S Raw / Both
     */
    constructor() {
        super();

        this.name = "JA4Server Fingerprint";
        this.module = "Crypto";
        this.description = "Generates a JA4Server Fingerprint (JA4S) to help identify TLS servers or sessions based on hashing together values from the Server Hello.<br><br>Input: A hex stream of the TLS or QUIC Server Hello packet application layer.";
        this.infoURL = "https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637";
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
                value: ["JA4S", "JA4S Raw", "Both"]
            }
        ];
    }

    /**
     * 【主流程】计算 JA4S 服务端指纹
     *
     * args[0] = Input format，args[1] = Output format
     * 核心算法封装在 lib/JA4.mjs 的 toJA4S()，本函数只做输入转换与输出选择
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [inputFormat, outputFormat] = args;
        // --- 步骤 1：输入格式归一化为字节数组 ---
        input = Utils.convertToByteArray(input, inputFormat);
        // --- 步骤 2：调用 toJA4S() 得到 JA4S 与 JA4S_r 两种变体 ---
        const ja4s = toJA4S(new Uint8Array(input));

        // --- 步骤 3：按 Output format 选取其中一个或两者 ---
        // Output
        switch (outputFormat) {
            case "JA4S":
                return ja4s.JA4S;
            case "JA4S Raw":
                return ja4s.JA4S_r;
            case "Both":
            default:
                return `JA4S:   ${ja4s.JA4S}\nJA4S_r: ${ja4s.JA4S_r}`;
        }
    }

}

export default JA4ServerFingerprint;
