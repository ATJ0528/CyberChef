/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】User-Agent 解析（UserAgent）
 * 【操作】Parse User Agent
 * 【功能】解析 User-Agent 字符串，识别浏览器、设备、引擎、操作系统与 CPU 架构
 * 【输入】string —— 一条 User-Agent 文本
 * 【输出】string —— 分行整理好的可读信息
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 把输入交给第三方库 ua-parser-js 的 UAParser() 解析
 *   2. 从返回对象中取出 browser / device / engine / os / cpu 各字段
 *   3. 缺失字段统一用 "unknown" 兜底，拼成多行文本返回
 * ------------------------------------------------------------
 * 【关键算法】基于正则特征的 UA 匹配
 *   - ua-parser-js 内部维护一组"特征（regex + 名称/版本）"规则，逐条对 UA
 *     字符串做正则匹配：命中哪条规则，就判定为对应的浏览器/系统/设备
 *   - 例如 UA 含 "Firefox/" 判为 Firefox；含 "Chrome/" 且不含 "Edg" 判为 Chrome；
 *     含 "Windows NT 10.0" 判为 Windows 10；含 "iPhone" 判为 iOS 设备
 *   - 版本号通常由规则里的捕获组从字符串中提取（如 /Chrome\/(\d+)/）
 *   - 本操作自身不含匹配逻辑，只负责调用库并整理输出
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - checks 里定义的特征规则供框架的"自动识别（Magic）"使用：当输入看起来像
 *     一条 User-Agent（以 "User-Agent:" 或 "Mozilla/" 开头）时，才推荐本操作
 *   - 所有取值都用 `|| "unknown"` 兜底，避免输出里出现 undefined
 * ============================================================
 */

import Operation from "../Operation.mjs";
import { UAParser } from "ua-parser-js";

/**
 * Parse User Agent operation
 *
 * 继承自 Operation；解析工作全部委托给第三方库 ua-parser-js，
 * 本类只负责组织输入输出与结果格式化。
 */
class ParseUserAgent extends Operation {

    /**
     * ParseUserAgent constructor
     *
     * 声明元信息与"自动识别"规则：
     *   inputType / outputType 均为 "string"
     *   args = []，无用户可调参数
     *   checks —— 框架的 Magic 检测：输入匹配到该正则（以 "User-Agent:" 或
     *     "Mozilla/" 开头的一整行）时，才在自动识别中推荐本操作
     */
    constructor() {
        super();

        this.name = "Parse User Agent";
        this.module = "UserAgent";
        this.description = "Attempts to identify and categorise information contained in a user-agent string.";
        this.infoURL = "https://wikipedia.org/wiki/User_agent";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [];
        this.checks = [
            {
                pattern:  "^(User-Agent:|Mozilla\\/)[^\\n\\r]+\\s*$",
                flags:  "i",
                args:   []
            }
        ];
    }

    /**
     * 【主流程】解析并格式化 User-Agent
     *
     * 调用 UAParser(input) 得到结构化结果，再按 Browser / Device / Engine /
     * OS / CPU 五组字段拼成多行文本；每个字段缺失时回退为 "unknown"。
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const ua = UAParser(input);
        return `Browser
    Name: ${ua.browser.name || "unknown"}
    Version: ${ua.browser.version || "unknown"}
Device
    Model: ${ua.device.model || "unknown"}
    Type: ${ua.device.type || "unknown"}
    Vendor: ${ua.device.vendor || "unknown"}
Engine
    Name: ${ua.engine.name || "unknown"}
    Version: ${ua.engine.version || "unknown"}
OS
    Name: ${ua.os.name || "unknown"}
    Version: ${ua.os.version || "unknown"}
CPU
    Architecture: ${ua.cpu.architecture || "unknown"}`;
    }

}

export default ParseUserAgent;
