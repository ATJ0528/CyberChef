/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】TLS 指纹（Crypto）— JA4 客户端指纹
 * 【操作】JA4 Fingerprint
 * 【功能】解析 TLS / QUIC ClientHello，计算 JA4 系列指纹（JA4 / JA4_o / JA4_r / JA4_ro）
 * 【输入】string —— TLS 或 QUIC ClientHello 应用层报文的 Hex / Base64 / Raw
 * 【输出】string —— 指定的一种指纹或四种全部
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 按 Input format 把输入转成字节数组
 *   2. 调用 lib/JA4.mjs 的 toJA4() 得到 {JA4, JA4_o, JA4_r, JA4_ro} 四个串
 *   3. 按 Output format 返回其中一个，选 "All" 时四行全部返回
 * ------------------------------------------------------------
 * 【关键算法】（实现见 src/core/lib/JA4.mjs）
 *   JA4 = "a 段_b 段_c 段"，三段用下划线 "_" 分隔：
 *     a 段（字母数字编码）= 协议 + 版本 + SNI + 密码套件数 + 扩展数 + ALPN
 *        · 协议   : "t"（TCP）或 "q"（QUIC，当前仅实现 t）
 *        · 版本   : supported_versions 扩展里的最高版本映射为 13/12/11/10/s3/s2/s1/00
 *        · SNI    : 存在 server_name 扩展为 "d"（域名），否则 "i"（IP）
 *        · 套件数 : 非 GREASE 密码套件数量，2 位补零，>99 记 "99"
 *        · 扩展数 : 非 GREASE 扩展数量，2 位补零
 *        · ALPN   : ALPN 首值首末字符（均为字母数字则取字符，否则取首字节首位 + 末字节末位），无扩展为 "00"
 *     b 段 = 密码套件 4 位十六进制列表（小写、逗号连接、忽略 GREASE）排序后的 SHA256 前 12 位
 *     c 段 = 扩展类型 4 位十六进制列表（排序、剔除 SNI 0000 与 ALPN 0010）+"_"+签名算法列表
 *            两部分的 SHA256 前 12 位
 *   变体：_o 用原始顺序（不排序）；_r 输出未哈希的原始列表串；_ro 两者结合
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 算法全部封装在 lib/JA4.mjs，本操作只是薄封装，便于复用与单测
 *   - c 段剔除 SNI 与 ALPN，使同一客户端去往域名 / IP 或切换 ALPN 时 b、c 段保持一致
 * ============================================================
 */

import Operation from "../Operation.mjs";
import Utils from "../Utils.mjs";
import {toJA4} from "../lib/JA4.mjs";

/**
 * JA4 Fingerprint operation
 *
 * 继承 Operation 基类，真正算法委托给 lib/JA4.mjs 的 toJA4()。
 */
class JA4Fingerprint extends Operation {

    /**
     * JA4Fingerprint constructor
     *
     * 声明元信息与参数：
     *   name "JA4 Fingerprint"、module "Crypto"、inputType / outputType 均为 string
     *   args[0] "Input format"  —— Hex / Base64 / Raw
     *   args[1] "Output format" —— JA4 / JA4 Original Rendering / JA4 Raw / JA4 Raw Original Rendering / All
     */
    constructor() {
        super();

        this.name = "JA4 Fingerprint";
        this.module = "Crypto";
        this.description = "Generates a JA4 fingerprint to help identify TLS clients based on hashing together values from the Client Hello.<br><br>Input: A hex stream of the TLS or QUIC Client Hello packet application layer.";
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
                value: ["JA4", "JA4 Original Rendering", "JA4 Raw", "JA4 Raw Original Rendering", "All"]
            }
        ];
    }

    /**
     * 【主流程】计算 JA4 客户端指纹
     *
     * args[0] = Input format，args[1] = Output format
     * 核心算法封装在 lib/JA4.mjs 的 toJA4()，本函数只做输入转换与输出选择
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [inputFormat, outputFormat] = args;
        // --- 步骤 1：输入格式归一化为字节数组 ---
        input = Utils.convertToByteArray(input, inputFormat);
        // --- 步骤 2：调用 toJA4() 得到 JA4 / JA4_o / JA4_r / JA4_ro 四种变体 ---
        const ja4 = toJA4(new Uint8Array(input));

        // --- 步骤 3：按 Output format 选取其一，选 "All" 时输出全部四种 ---
        // Output
        switch (outputFormat) {
            case "JA4":
                return ja4.JA4;
            case "JA4 Original Rendering":
                return ja4.JA4_o;
            case "JA4 Raw":
                return ja4.JA4_r;
            case "JA4 Raw Original Rendering":
                return ja4.JA4_ro;
            case "All":
            default:
                return `JA4:    ${ja4.JA4}
JA4_o:  ${ja4.JA4_o}
JA4_r:  ${ja4.JA4_r}
JA4_ro: ${ja4.JA4_ro}`;
        }
    }

}

export default JA4Fingerprint;
