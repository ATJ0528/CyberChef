/**
 * @author arnydo [arnydo@protonmail.com]
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2018
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】URL 与域名处理（Default）— URL 去毒化
 * 【操作】Defang URL
 * 【功能】把可点击的 URL/域名改写成"失效"形式（http→hxxp、.→[.]、
 *         ://→[://]），使链接无法被误点，用于安全报告中安全展示恶意 IOC
 * 【输入】string —— 任意包含 URL/域名的文本
 * 【输出】string —— 去毒化后的文本
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 取出 4 个参数：dots / http / slashes / process
 *   2. 按 process 决定替换范围：
 *        "Valid domains and full URLs" → 先用 URL_REGEX 匹配完整 URL 去毒，
 *                                        再用 DOMAIN_REGEX 匹配裸域名去毒
 *        "Only full URLs"             → 只用 URL_REGEX 匹配完整 URL
 *        "Everything"                 → 不匹配，整段文本整体去毒
 *   3. 每个命中的片段交给私有函数 defangURL() 按三个开关逐项替换
 *   4. 返回处理后的文本
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 正则替换 + 回调：input.replace(regex, x => defangURL(x, ...))，
 *     只替换"匹配到的 URL/域名片段"，正文其余部分原样保留
 *   - URL_REGEX / DOMAIN_REGEX 直接复用 lib/Extract.mjs 中
 *     "Extract URLs" 所用的同一套正则，保证识别口径一致
 *   - Defang 可逆替换规则表（见 defangURL 内，逐一对应 Fang URL 的逆替换）：
 *       开关 dots    : /\./g      ".",  →  "[.]"
 *       开关 http    : /http/gi   "http"（不分大小写）→ "hxxp"（恒为小写）
 *       开关 slashes : /:\/\//g   "://"  →  "[://]"
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 三个开关彼此独立、可任意组合；关闭则跳过对应替换
 *   - 替换顺序 dots → http → slashes 互不干扰：先把 "." 变成 "[.]"，
 *     而 "://" 中不含 "."，因此不会破坏后续 :// 的匹配
 *   - process = "Everything" 对整段文本替换，正文中恰含 "http" 的普通词
 *     （如 "http 协议"）也会被一并改写，需按场景选择
 * ============================================================
 */

import Operation from "../Operation.mjs";
import {URL_REGEX, DOMAIN_REGEX} from "../lib/Extract.mjs";

/**
 * DefangURL operation
 *
 * 继承自 Operation，只需实现 run()。
 * 模块级再定义一个私有辅助函数 defangURL() 完成单条 URL 的替换。
 */
class DefangURL extends Operation {

    /**
     * DefangURL constructor
     *
     * 声明元信息与 4 个参数：
     *   [0] Escape dots    (boolean) —— 是否把 "." 替换为 "[.]"
     *   [1] Escape http    (boolean) —— 是否把 "http" 替换为 "hxxp"
     *   [2] Escape ://     (boolean) —— 是否把 "://" 替换为 "[://]"
     *   [3] Process        (option)  —— 替换范围：
     *        ["Valid domains and full URLs", "Only full URLs", "Everything"]
     */
    constructor() {
        super();

        this.name = "Defang URL";
        this.module = "Default";
        this.description = "Takes a Universal Resource Locator (URL) and 'Defangs' it; meaning the URL becomes invalid, neutralising the risk of accidentally clicking on a malicious link.<br><br>This is often used when dealing with malicious links or IOCs.<br><br>Works well when combined with the 'Extract URLs' operation.";
        this.infoURL = "https://isc.sans.edu/forums/diary/Defang+all+the+things/22744/";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Escape dots",
                type: "boolean",
                value: true
            },
            {
                name: "Escape http",
                type: "boolean",
                value: true
            },
            {
                name: "Escape ://",
                type: "boolean",
                value: true
            },
            {
                name: "Process",
                type: "option",
                value: ["Valid domains and full URLs", "Only full URLs", "Everything"]
            }
        ];
    }

    /**
     * 【主流程】按 process 选择范围，对 URL/域名去毒
     *
     * 参数来自界面 4 个控件（解构为 [dots, http, slashes, process]），
     * 返回值是替换后的整段文本。
     *
     * @param {string} input - 含 URL/域名的原始文本
     * @param {Object[]} args - [Escape dots, Escape http, Escape ://, Process]
     * @returns {string}
     */
    run(input, args) {
        // --- 步骤 1：解构 4 个参数 ---
        const [dots, http, slashes, process] = args;

        // --- 步骤 2：按 process 选择匹配范围，逐命中片段调用 defangURL ---
        switch (process) {
            case "Valid domains and full URLs":
                input = input.replace(URL_REGEX, x => {
                    return defangURL(x, dots, http, slashes);
                });
                input = input.replace(DOMAIN_REGEX, x => {
                    return defangURL(x, dots, http, slashes);
                });
                break;
            case "Only full URLs":
                input = input.replace(URL_REGEX, x => {
                    return defangURL(x, dots, http, slashes);
                });
                break;
            case "Everything":
                input = defangURL(input, dots, http, slashes);
                break;
        }

        return input;
    }

}


/**
 * Defangs a given URL
 *
 * 私有辅助函数：对单条 URL/域名片段做去毒替换。
 * 输入：一段 URL 文本 + 三个布尔开关；输出：改写后的字符串。
 * 算法：三个互相独立、互不干扰的全局正则替换，按 dots → http → slashes
 *       顺序执行，每项仅在其开关为 true 时生效。
 *
 * @param {string} url
 * @param {boolean} dots
 * @param {boolean} http
 * @param {boolean} slashes
 * @returns {string}
 */
function defangURL(url, dots, http, slashes) {
    if (dots) url = url.replace(/\./g, "[.]");
    if (http) url = url.replace(/http/gi, "hxxp");
    if (slashes) url = url.replace(/:\/\//g, "[://]");

    return url;
}

export default DefangURL;
