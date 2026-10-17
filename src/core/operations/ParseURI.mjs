/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】URL 与域名处理（URL）— URI 分量解析
 * 【操作】Parse URI
 * 【功能】把复杂 URI/URL 字符串按 RFC 3986 拆解成 protocol / auth /
 *        hostname / port / pathname / query / hash 等分量，逐行对齐输出
 * 【输入】string —— 一个完整或部分 URI，如
 *        "https://user:pass@example.com:8080/path?a=1&a=2#frag"
 * 【输出】string —— 分量名与值对齐排列的多行文本（缺失分量不出现）
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 调用 Node 内置 url.parse(input, false) 做一次整体切分；
 *      第二个参数传 false —— 不把 query 解析成对象，保留原始查询串
 *   2. 依次判断 protocol/auth/hostname/port/pathname 是否存在，
 *      存在才输出对应行
 *   3. 有 query 时用 URLSearchParams 逐对解析，同名键合并为数组
 *   4. 取最长的键名宽度作对齐基准，用 padEnd 补空格美化
 *   5. 最后输出 hash 分量
 * ------------------------------------------------------------
 * 【关键算法】
 *   - URI 分量切分（RFC 3986 通用语法）：
 *       scheme "://" [userinfo "@"] host [":" port] path ["?" query] ["#" fragment]
 *     url.parse() 一次性按此规则切出各分量；它是 Node 遗留 API，
 *     对畸形输入较宽容，不会抛异常，只是一个分量都可能为空
 *   - 同名参数合并：`new URLSearchParams(uri.query)` 产出"键→值"迭代表；
 *     遇到已存在的键时，首个值先升级为数组再 push，
 *     从而 a=1&a=2 归并为 a:[1, 2]
 *   - 对齐美化：先遍历所有键求最大长度 padding，再 padEnd(padding, " ")，
 *     使各行的 "键 = 值" 纵向对齐
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 每个分量都先做真值判断再拼接，缺失分量的行完全不会出现，
 *     输出紧凑、无空占位
 *   - queryObj 用 Object.create(null) 创建，没有原型链，
 *     避免键名为 "constructor""toString" 等原型属性时被 hasOwnProperty 误判
 *   - `if (queryObj[key].length)` 是唯一的值存在性判断：
 *     空字符串长度为 0，此时只换行、不打印 "= 值"
 * ============================================================
 */

import Operation from "../Operation.mjs";
import url from "url";

/**
 * Parse URI operation
 *
 * 继承自 Operation 基类，只需实现 run()。本操作无参数（args = []），
 * 构造函数中声明的元信息决定它在 UI 中的名称、描述与输入输出类型。
 */
class ParseURI extends Operation {

    /**
     * ParseURI constructor
     *
     * 声明操作元信息：
     *   name        = "Parse URI"   界面显示名
     *   module      = "URL"         所属分类
     *   description = ...           帮助文本
     *   infoURL     = ...           RFC/Wikipedia 参考链接
     * inputType  = "string"  → 框架把 Dish 内容按字符串交给 run()
     * outputType = "string"  → run() 返回值直接作为字符串结果呈现
     * args       = []        → 本操作无需任何用户参数
     */
    constructor() {
        super();

        this.name = "Parse URI";
        this.module = "URL";
        this.description = "Pretty prints complicated Uniform Resource Identifier (URI) strings for ease of reading. Particularly useful for Uniform Resource Locators (URLs) with a lot of arguments.";
        this.infoURL = "https://wikipedia.org/wiki/Uniform_Resource_Identifier";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [];
    }

    /**
     * 【主流程】解析 URI 并格式化输出
     *
     * 分 3 步：① url.parse 切分 ② 逐分量条件输出 ③ query 对齐美化。
     * 返回可直接显示的多行字符串；若输入不成其为 URI，各分量为空，
     * 则返回空串而不报错。
     *
     * @param {string} input - 待解析的 URI/URL 字符串
     * @param {Object[]} args - 无参数，恒为空数组
     * @returns {string}
     */
    run(input, args) {
        // --- 步骤 1：按 RFC 3986 整体切分 URI（第二参 false = query 不解析，保留原始串）---
        const uri = url.parse(input, false);

        let output = "";

        // --- 步骤 2：逐分量判断存在即输出（缺失分量不出行）---
        if (uri.protocol) output += "Protocol:\t" + uri.protocol + "\n";
        if (uri.auth) output += "Auth:\t\t" + uri.auth + "\n";
        if (uri.hostname) output += "Hostname:\t" + uri.hostname + "\n";
        if (uri.port) output += "Port:\t\t" + uri.port + "\n";
        if (uri.pathname) output += "Path name:\t" + uri.pathname + "\n";
        // --- 步骤 3：query 同名键合并为数组，并按最长键名对齐输出 ---
        if (uri.query) {
            const queryObj = Object.create(null);
            for (const [key, value] of new URLSearchParams(uri.query)) {
                if (Object.prototype.hasOwnProperty.call(queryObj, key)) {
                    if (Array.isArray(queryObj[key])) {
                        queryObj[key].push(value);
                    } else {
                        queryObj[key] = [queryObj[key], value];
                    }
                } else {
                    queryObj[key] = value;
                }
            }

            const keys = Object.keys(queryObj);
            let padding = 0;

            keys.forEach(k => {
                padding = (k.length > padding) ? k.length : padding;
            });

            output += "Arguments:\n";
            for (const key in queryObj) {
                output += "\t" + key.padEnd(padding, " ");
                if (queryObj[key].length) {
                    output += " = " + queryObj[key] + "\n";
                } else {
                    output += "\n";
                }
            }
        }
        if (uri.hash) output += "Hash:\t\t" + uri.hash + "\n";

        return output;
    }

}

export default ParseURI;
