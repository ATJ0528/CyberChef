/**
 * @author arnydo [github@arnydo.com]
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】URL 与域名处理（Default）— URL 还原（去毒化逆操作）
 * 【操作】Fang URL
 * 【功能】把去毒化（Defang）后的 URL 还原成可用形式，
 *        是 Defang URL 的逆操作
 * 【输入】string —— 含已去毒 URL 的文本（如 "hxxp://example[.]com"）
 * 【输出】string —— 还原后的文本（如 "http://example.com"）
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 取出 3 个开关：dots / http / slashes
 *   2. 调用私有函数 fangURL() 执行逆替换
 *   3. 返回还原后的文本
 * ------------------------------------------------------------
 * 【关键算法】
 *   - Fang 可逆替换规则表（见 fangURL 内），恰为 Defang 的逆向：
 *       开关 dots    : /\[\.\]/g    "[.]"   →  "."
 *       开关 http    : /hxxp/g      "hxxp"  →  "http"
 *       开关 slashes : /\[:\/\/\]/g "[://]" →  "://"
 *   - 与 DefangURL 的替换一一对应，因此 Defang → Fang 可往返还原
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 注意大小写口径不一致：Defang 侧 http 用 /gi 不区分大小写，
 *     而 Fang 侧 hxxp 用 /g 区分大小写，故原文中的 "HXXP" 无法被本操作还原
 *   - 文件末尾 fangURL 的 JSDoc 首行仍写着 "Defangs a given URL"，
 *     那是从 DefangURL 复制模板时遗留的历史注释，实际功能为"还原"
 * ============================================================
 */

import Operation from "../Operation.mjs";

/**
 * FangURL operation
 *
 * 继承自 Operation，只需实现 run()。
 * 模块级另有私有辅助函数 fangURL() 完成单条 URL 的逆替换。
 */
class FangURL extends Operation {

    /**
     * FangURL constructor
     *
     * 声明元信息与 3 个参数：
     *   [0] Restore [.]   (boolean) —— 是否把 "[.]" 还原为 "."
     *   [1] Restore hxxp  (boolean) —— 是否把 "hxxp" 还原为 "http"
     *   [2] Restore ://   (boolean) —— 是否把 "[://]" 还原为 "://"
     */
    constructor() {
        super();

        this.name = "Fang URL";
        this.module = "Default";
        this.description = "Takes a 'Defanged' Universal Resource Locator (URL) and 'Fangs' it. Meaning, it removes the alterations (defanged) that render it useless so that it can be used again.";
        this.infoURL = "https://isc.sans.edu/forums/diary/Defang+all+the+things/22744/";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Restore [.]",
                type: "boolean",
                value: true
            },
            {
                name: "Restore hxxp",
                type: "boolean",
                value: true
            },
            {
                name: "Restore ://",
                type: "boolean",
                value: true
            }
        ];
    }

    /**
     * 【主流程】对整段文本执行去毒化的逆替换
     *
     * 参数来自界面 3 个开关（解构为 [dots, http, slashes]），
     * 输入输出均为字符串。
     *
     * @param {string} input - 含已去毒 URL 的文本
     * @param {Object[]} args - [Restore [.], Restore hxxp, Restore ://]
     * @returns {string}
     */
    run(input, args) {
        // --- 步骤 1：解构 3 个还原开关 ---
        const [dots, http, slashes] = args;

        // --- 步骤 2：调用 fangURL 完成逆替换 ---
        input = fangURL(input, dots, http, slashes);

        return input;
    }

}


/**
 * Defangs a given URL
 *
 * 私有辅助函数：对单条已去毒 URL 做逆替换（"Fang"）。
 * 输入：一段 URL 文本 + 三个布尔开关；输出：还原后的字符串。
 * 算法：三个互相独立的全局正则替换，按 dots → http → slashes 顺序执行，
 *       每项仅在其开关为 true 时生效，整体为 DefangURL.defangURL 的逆向。
 *
 * @param {string} url
 * @param {boolean} dots
 * @param {boolean} http
 * @param {boolean} slashes
 * @returns {string}
 */
function fangURL(url, dots, http, slashes) {
    if (dots) url = url.replace(/\[\.\]/g, ".");
    if (http) url = url.replace(/hxxp/g, "http");
    if (slashes) url = url.replace(/\[:\/\/\]/g, "://");

    return url;
}

export default FangURL;
