/**
 * @author h345983745
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】URL 与域名处理（Default）— IP 地址去毒化
 * 【操作】Defang IP Addresses
 * 【功能】把 IPv4/IPv6 地址改写成不可直接使用的形式
 *         （"." → "[.]"、"每段 :" → "[:]"），避免误用为真实地址
 * 【输入】string —— 含 IP 地址的文本
 * 【输出】string —— 去毒化后的文本
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 整体扫描 IPv4：用 IPV4_REGEX 匹配所有地址，对每个命中片段
 *      把其中每个 "." 替换成 "[.]"
 *   2. 整体扫描 IPv6：用 IPV6_REGEX 匹配所有地址，对每个命中片段
 *      把其中每个 ":" 替换成 "[:]"
 *   3. 返回替换后的文本
 * ------------------------------------------------------------
 * 【关键算法】← 两个正则的捕获组逐一说明
 *   - IPV4_REGEX（全局，g）：
 *       (?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}  前 3 个 0-255 的数 + "."
 *         ├ \d             →  0-9            （个位）
 *         ├ [01]?\d\d      →  可带前导零的 2-3 位
 *         ├ 2[0-4]\d       →  200-249
 *         └ 25[0-5]        →  250-255
 *       (?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)           第 4 个 0-255 的数
 *       (?:\/\d{1,2})?                              可选 CIDR 前缀（/0../32）
 *     分段枚举保证每段都不超过 255；[01]?\d\d 允许前导零写法
 *   - IPV6_REGEX（全局，g）：
 *     支持 8 组冒号分隔的完整写法，也支持 "::" 压缩写法，
 *     并能连带匹配内嵌的 IPv4 尾巴（如 ::ffff:192.168.0.1）。
 *     关键约束：
 *       (?=.*::)     先行断言——必须含 "::"
 *       (?!.*::.+::) 负向断言—— "::" 至多出现一次
 *       \2 \3        反向引用复用前面已捕获的分组来约束后续段
 *   - checks：声明自动检测规则——当整段输入恰好是一个完整 IPv4/IPv6
 *     （首个 pattern）时，框架会提示"可套用本操作"，
 *     其 output.pattern 即去毒后应呈现的形态（"." → "[.]"、":" → "[:]"）
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 两个 replace 的回调只在"匹配到的 IP 片段内部"替换字符，
 *     因此正文中孤立的 "." 或 ":" 不会被误伤
 *   - 处理顺序为"先 IPv4 后 IPv6"；IPv4 替换引入的 "[" "]" 不含 ":",
 *     不会被随后的 IPV6_REGEX 再次命中，二者互不干扰
 * ============================================================
 */

import Operation from "../Operation.mjs";


/**
 * Defang IP Addresses operation
 *
 * 继承自 Operation，只需实现 run()。
 * 文件底部定义了模块级的 IPV4_REGEX / IPV6_REGEX 两个识别用正则常量。
 */
class DefangIPAddresses extends Operation {

    /**
     * DefangIPAddresses constructor
     *
     * 声明元信息；本操作无用户参数（args = []）。
     * checks 为"自动检测"提示规则：框架在输入匹配 checks[i].pattern 时，
     * 会建议用户套用本操作，并给出预期输出的 output.pattern：
     *   pattern        → 匹配"普通 IPv4（含可选 CIDR）"或"完整 8 组 IPv6"
     *   output.pattern → 匹配同一地址去毒后的形态（"[.]""[:]" 版本）
     */
    constructor() {
        super();

        this.name = "Defang IP Addresses";
        this.module = "Default";
        this.description = "Takes a IPv4 or IPv6 address and 'Defangs' it, meaning the IP becomes invalid, removing the risk of accidentally utilising it as an IP address.";
        this.infoURL = "https://isc.sans.edu/forums/diary/Defang+all+the+things/22744/";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [];
        this.checks = [
            {
                pattern: "^\\s*(([0-9]{1,3}\\.){3}[0-9]{1,3}|([0-9a-f]{4}:){7}[0-9a-f]{4})\\s*$",
                flags: "i",
                args: [],
                output: {
                    pattern: "^\\s*(([0-9]{1,3}\\[\\.\\]){3}[0-9]{1,3}|([0-9a-f]{4}\\[\\:\\]){7}[0-9a-f]{4})\\s*$",
                    flags: "i"
                }
            }
        ];
    }

    /**
     * 【主流程】对文本中的 IPv4 与 IPv6 地址分别去毒
     *
     * 分 2 步：① 替换所有 IPv4 片段内的 "." ② 替换所有 IPv6 片段内的 ":"。
     * 无参数，输入输出均为字符串。
     *
     * @param {string} input - 含 IP 地址的文本
     * @param {Object[]} args - 无参数，恒为空数组
     * @returns {string}
     */
    run(input, args) {
        // --- 步骤 1：IPv4 去毒——对每个匹配到的地址，把内部的 "." 换成 "[.]" ---
        input = input.replace(IPV4_REGEX, x => {
            return x.replace(/\./g, "[.]");
        });

        // --- 步骤 2：IPv6 去毒——对每个匹配到的地址，把内部的 ":" 换成 "[:]" ---
        input = input.replace(IPV6_REGEX, x => {
            return x.replace(/:/g, "[:]");
        });

        return input;
    }
}

export default DefangIPAddresses;


/**
 * IPV4 regular expression
 *
 * 匹配形如 a.b.c.d 的 IPv4（每段 0-255），可选带 /n 的 CIDR 前缀；
 * 分组含义见文件头【关键算法】。末尾 "g" 表示全局匹配，找出文本中所有地址。
 */
const IPV4_REGEX = new RegExp("(?:(?:\\d|[01]?\\d\\d|2[0-4]\\d|25[0-5])\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d|\\d)(?:\\/\\d{1,2})?", "g");


/**
 * IPV6 regular expression
 *
 * 匹配 IPv6 地址：既支持 8 组完整写法，也支持含 "::" 的压缩写法，
 * 并可连带匹配内嵌的 IPv4 尾巴；用先行/反向引用保证 "::" 至多出现一次。
 * 分组含义见文件头【关键算法】。"g" 表示全局匹配。
 */
const IPV6_REGEX = new RegExp("((?=.*::)(?!.*::.+::)(::)?([\\dA-Fa-f]{1,4}:(:|\\b)|){5}|([\\dA-Fa-f]{1,4}:){6})((([\\dA-Fa-f]{1,4}((?!\\3)::|:\\b|(?![\\dA-Fa-f])))|(?!\\2\\3)){2}|(((2[0-4]|1\\d|[1-9])?\\d|25[0-5])\\.?\\b){4})", "g");
