/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】URL 与域名处理（URL）— 百分号解码
 * 【操作】URL Decode
 * 【功能】把 %XX 形式的百分号编码还原为原始字符，
 *        是 URL Encode 的逆操作（如 %3D → "="）
 * 【输入】string —— 含 %XX 编码的字符串
 * 【输出】string —— 解码后的字符串
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 读参数 plusIsSpace
 *   2. 若 plusIsSpace 为真，先把所有 "+" 替换成 "%20"，
 *      把 form-urlencoded 的空格约定统一成百分号形式
 *   3. 优先调用 decodeURIComponent() 解码；一旦抛异常
 *      （例如遇到孤立的 "%" 或非法序列），回退到 unescape()
 *   4. 返回解码结果
 * ------------------------------------------------------------
 * 【关键算法】
 *   - decodeURIComponent：按 UTF-8 语义把连续的 %XX 还原成字符，
 *     多字节序列自动合并，是标准的严格解码器，遇非法序列会抛异常
 *   - 回退 unescape：老式 API，容错性强、不抛异常，但按 Latin-1 逐字节
 *     还原，遇到 UTF-8 多字节序列可能显示为乱码 —— 仅作最后兜底
 *   - checks：声明自动检测规则——输入中若出现 ≥4 处 %XX 编码，
 *     框架提示"可套用本操作"（pattern ".*(?:%[\da-f]{2}.*){4}"，flags "i"）
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - plusIsSpace 默认 true：URL 查询串中 "+" 依约定表示空格；
 *     但 URL 路径里 "+" 是字面加号，此时应关闭该开关以免被误改
 *   - try/catch 兜底体现"容错优先"：宁可部分内容乱码，
 *     也要让整段输入尽量解出，而不是让操作整体失败
 *   - 替换 "+" 为 "%20" 而非直接替换成空格，是为了复用统一的百分号解码路径
 * ============================================================
 */

import Operation from "../Operation.mjs";

/**
 * URL Decode operation
 *
 * 继承自 Operation，只需实现 run()。逻辑较短，
 * 依赖标准库 decodeURIComponent 并配合 unescape 兜底。
 */
class URLDecode extends Operation {

    /**
     * URLDecode constructor
     *
     * 声明元信息与 1 个参数：
     *   [0] Treat "+" as space (boolean，默认 true)
     *       true  → 解码前把 "+" 视作空格
     *       false → 保留 "+" 原样
     * checks 为自动检测规则：输入含多处 %XX 时提示可用本操作。
     */
    constructor() {
        super();

        this.name = "URL Decode";
        this.module = "URL";
        this.description = "Converts URI/URL percent-encoded characters back to their raw values.<br><br>e.g. <code>%3d</code> becomes <code>=</code>";
        this.infoURL = "https://wikipedia.org/wiki/Percent-encoding";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                "name": "Treat \"+\" as space",
                "type": "boolean",
                "value": true
            },
        ];
        this.checks = [
            {
                pattern: ".*(?:%[\\da-f]{2}.*){4}",
                flags: "i",
                args: []
            },
        ];
    }

    /**
     * 【主流程】把百分号编码还原为原始字符
     *
     * 分 3 步：① 按开关把 "+" 归一化为 "%20" ② decodeURIComponent 解码
     * ③ 解码失败时用 unescape 兜底。输入输出均为字符串。
     *
     * @param {string} input - 含 %XX 的字符串
     * @param {Object[]} args - [Treat "+" as space]
     * @returns {string}
     */
    run(input, args) {
        // --- 步骤 1：把 "+" 统一成 "%20"（form-urlencoded 空格约定）---
        const plusIsSpace = args[0];
        const data = plusIsSpace ? input.replace(/\+/g, "%20") : input;
        // --- 步骤 2/3：严格解码优先，失败则回退到宽松的 unescape ---
        try {
            return decodeURIComponent(data);
        } catch (err) {
            return unescape(data);
        }
    }

}

export default URLDecode;
