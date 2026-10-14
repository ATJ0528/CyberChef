/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】URL 与域名处理（URL）— 百分号编码
 * 【操作】URL Encode
 * 【功能】把字节按 RFC 3986 百分号编码（percent-encoding）转义，
 *        不安全的字符编码成 %XX
 * 【输入】byteArray —— 待编码字节（框架先把 Dish 内容解析为字节数组）
 * 【输出】string —— 编码后的字符串
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 读参数 encodeAll（是否编码全部特殊字符）
 *   2. 调用 encodeBytes() 逐字节判断"原样保留"还是"转 %XX"
 *   3. 返回结果
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 白名单正则 safeChars 决定哪些字符原样保留：
 *       encodeAll = false →
 *         /^[A-Za-z0-9:/?#[\]@!$&'()*+,;=%]$/
 *         即 unreserved（字母数字）+ URI 保留字（gen-delims ":/?#[]@" 与
 *         sub-delims "!$&'()*+,;="）+ "%"；仅空格、非 ASCII、控制符等被编码
 *       encodeAll = true  →
 *         /^[A-Za-z0-9]$/
 *         只保留字母数字，其余（含 :/?# 等保留字）全部编码
 *   - 编码规则：不安全字节写成
 *       "%" + byte.toString(16).toUpperCase().padStart(2, "0")
 *     即先转十六进制（小写）、再转大写、左侧补零到两位
 *     （如 0x3D → "3D"，0x0A → "0A"）
 *   - 逐字节而非逐字符：输入是 byteArray，天然按 UTF-8 字节流处理，
 *     一个多字节字符（如中文）会拆成多个字节、各自编码成多个 %XX，
 *     完全符合 RFC 3986 的 UTF-8 百分号编码约定
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 保留字为何不编码：":/?#" 分隔 URI 各分量、"[]@" 用于 IPv6 与 userinfo、
 *     "!$&'()*+,;=" 是 sub-delims；默认保留它们可保持 URL 结构可用
 *   - "%" 本身在白名单内，避免对已编码内容二次编码时把 "%" 变成 "%25"
 *     （仅在 encodeAll = false 时成立）
 *   - 注意实现输出为大写十六进制，而 description 示例写作小写 "%3d"；
 *     且 "=" 在默认模式下属保留字不会被编码，仅 encodeAll = true 时才编码
 * ============================================================
 */

import Operation from "../Operation.mjs";

/**
 * URL Encode operation
 *
 * 继承自 Operation，只需实现 run()。
 * 类内另有公开方法 encodeBytes() 承担实际的逐字节编码逻辑。
 */
class URLEncode extends Operation {

    /**
     * URLEncode constructor
     *
     * 声明元信息与 1 个参数：
     *   [0] Encode all special chars (boolean，默认 false)
     *       false → 仅编码空格/非 ASCII/控制符等，保留 URI 保留字
     *       true  → 除字母数字外全部编码，得到最保守的编码结果
     * inputType = "byteArray" → 框架先按字节数组传入
     * outputType = "string"   → 返回文本
     */
    constructor() {
        super();

        this.name = "URL Encode";
        this.module = "URL";
        this.description = "Encodes problematic characters into percent-encoding, a format supported by URIs/URLs.<br><br>e.g. <code>=</code> becomes <code>%3d</code>";
        this.infoURL = "https://wikipedia.org/wiki/Percent-encoding";
        this.inputType = "byteArray";
        this.outputType = "string";
        this.args = [
            {
                "name": "Encode all special chars",
                "type": "boolean",
                "value": false
            }
        ];
    }

    /**
     * 【主流程】读取参数并转交 encodeBytes 编码
     *
     * @param {byteArray} input - 待编码字节数组
     * @param {Object[]} args - [Encode all special chars]
     * @returns {string}
     */
    run(input, args) {
        const encodeAll = args[0];
        return this.encodeBytes(input, encodeAll);
    }

    /**
     * Encode bytes in URL using percent encoding.
     *
     * 私有编码核心：逐字节判断是否属于安全字符。
     * 输入：字节数组 + 是否全编码开关；输出：编码后的字符串。
     * 算法：先用 safeChars 白名单正则定界（见文件头【关键算法】），
     *       再对每个字节走 safeChars.test → 命中则原样、否则转 %XX，
     *       逐字节累加成输出。
     *
     * @param {byteArray} bytes
     * @param {boolean} encodeAll
     * @returns {string}
     */
    encodeBytes(bytes, encodeAll) {
        // 白名单：命中此正则的字符原样保留，其余转 %XX
        const safeChars = encodeAll ?
            /^[A-Za-z0-9]$/ :
            /^[A-Za-z0-9:/?#[\]@!$&'()*+,;=%]$/;

        let output = "";

        // 逐字节处理：安全字符原样输出，否则输出 "%"+大写两位十六进制
        for (const byte of bytes) {
            const char = String.fromCharCode(byte);

            output += safeChars.test(char) ?
                char :
                "%" + byte.toString(16).toUpperCase().padStart(2, "0");
        }

        return output;
    }

}


export default URLEncode;
