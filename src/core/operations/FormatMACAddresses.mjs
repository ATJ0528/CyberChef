/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— MAC 地址格式化
 * 【操作】Format MAC addresses
 * 【功能】把 MAC 地址归一化后展示为多种常见写法（无分隔 / 冒号 / 破折号 / Cisco / EUI-64 接口标识）
 * 【输入】string —— 以逗号、空格、换行分隔的 MAC 地址列表
 * 【输出】string —— 每个 MAC 的各格式变体（每行一个），不同 MAC 之间以空行分隔
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 空输入直接返回空串
 *   2. 解构参数（1 个大小写选项 + 5 个格式开关），把输入统一小写并按 [,\s\r\n]+ 拆成列表
 *   3. 逐个 MAC：去掉 [:. -] 分隔符，得到 12 位纯十六进制 cleanMac
 *   4. 基于 cleanMac 生成各分隔变体：无分隔、冒号、破折号、Cisco（每 4 位一点）
 *   5. 生成 IPv6 接口标识（EUI-64）：第 6 位后插入 fffe，每 4 位加冒号，翻转首字节 U/L 位
 *   6. 按 "Output case" 选择大小写，把勾选中的变体 push 进输出表
 *   7. 每个 MAC 结束补一个空串作分组分隔，最终以 \n 连接返回
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 用带正向前瞻的正则批量插入分隔符：
 *       `cleanMac.replace(/(.{2}(?=.))/g, "$1-")` —— 每 2 个字符后加 "-"；
 *       `(?=.)` 前瞻保证末尾之后不再补分隔符（因为最后两位后已无字符）
 *       同理 Cisco 用 `/(.{4}(?=.))/g` 每 4 位加 "."
 *   - EUI-64 生成：`slice(0,6) + "fffe" + slice(6)` 在中间字节处插入 fffe，
 *     随后按 4 位分组加冒号；最后 `parseInt(首字节,16) ^ 2` 翻转 U/L 位
 *   - 一次 cleanMac 反复复用，生成全部变体，避免重复解析
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 源码明示「无有效性检查」：本操作只做格式转换，不做 MAC 合法性校验
 *   - 5 个布尔开关相互独立，用户可任选要输出哪些格式；"Both" 大小写时同时推入两种
 * ============================================================
 */

import Operation from "../Operation.mjs";

/**
 * 【类】FormatMACAddresses —— MAC 地址多格式展示操作
 * 继承 Operation 基类，只实现 run()；输入是混合分隔符的地址列表，输出为各格式变体。
 */
/**
 * Format MAC addresses operation
 */
class FormatMACAddresses extends Operation {

    /**
     * 【构造函数】声明元信息与六个参数
     * name = "Format MAC addresses"，module = "Default"，inputType/outputType 均为 "string"。
     * args[0] Output case      —— 选项：Both / Upper only / Lower only，控制输出大小写
     * args[1] No delimiter     —— 布尔，是否输出无分隔形式，默认 true
     * args[2] Dash delimiter   —— 布尔，是否输出破折号分隔形式，默认 true
     * args[3] Colon delimiter  —— 布尔，是否输出冒号分隔形式，默认 true
     * args[4] Cisco style      —— 布尔，是否输出 Cisco 点分形式（xxxx.xxxx.xxxx），默认 false
     * args[5] IPv6 interface ID —— 布尔，是否输出 EUI-64 接口标识形式，默认 false
     */
    /**
     * FormatMACAddresses constructor
     */
    constructor() {
        super();

        this.name = "Format MAC addresses";
        this.module = "Default";
        this.description = "Displays given MAC addresses in multiple different formats.<br><br>Expects addresses in a list separated by newlines, spaces or commas.<br><br>WARNING: There are no validity checks.";
        this.infoURL = "https://wikipedia.org/wiki/MAC_address#Notational_conventions";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                "name": "Output case",
                "type": "option",
                "value": ["Both", "Upper only", "Lower only"]
            },
            {
                "name": "No delimiter",
                "type": "boolean",
                "value": true
            },
            {
                "name": "Dash delimiter",
                "type": "boolean",
                "value": true
            },
            {
                "name": "Colon delimiter",
                "type": "boolean",
                "value": true
            },
            {
                "name": "Cisco style",
                "type": "boolean",
                "value": false
            },
            {
                "name": "IPv6 interface ID",
                "type": "boolean",
                "value": false
            }
        ];
    }

    /**
     * 【主流程】把 MAC 地址列表展开为多种格式变体
     * 参数 args 见构造函数；返回以 \n 连接的变体文本，组间留空行。
     */
    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        // 空输入直接返回空串，避免后续 split 产生空元素
        if (!input) return "";

        const [
                outputCase,
                noDelim,
                dashDelim,
                colonDelim,
                ciscoStyle,
                ipv6IntID
            ] = args,
            outputList = [],
            macs = input.toLowerCase().split(/[,\s\r\n]+/);

        // --- 逐个 MAC 生成各格式变体 ---
        macs.forEach(function(mac) {
            // 归一化：去掉所有分隔符，得到 12 位纯十六进制串
            const cleanMac = mac.replace(/[:.-]+/g, ""),
                macHyphen = cleanMac.replace(/(.{2}(?=.))/g, "$1-"),
                macColon = cleanMac.replace(/(.{2}(?=.))/g, "$1:"),
                macCisco = cleanMac.replace(/(.{4}(?=.))/g, "$1.");
            // --- 生成 EUI-64 接口标识：第 6 位后插入 fffe，每 4 位加冒号，并翻转首字节 U/L 位 ---
            let macIPv6 = cleanMac.slice(0, 6) + "fffe" + cleanMac.slice(6);

            macIPv6 = macIPv6.replace(/(.{4}(?=.))/g, "$1:");
            let bite = parseInt(macIPv6.slice(0, 2), 16) ^ 2;
            bite = bite.toString(16).padStart(2, "0");
            macIPv6 = bite + macIPv6.slice(2);

            // --- 按 Output case 选大小写，逐个 push 勾选中的输出变体 ---
            if (outputCase === "Lower only") {
                if (noDelim) outputList.push(cleanMac);
                if (dashDelim) outputList.push(macHyphen);
                if (colonDelim) outputList.push(macColon);
                if (ciscoStyle) outputList.push(macCisco);
                if (ipv6IntID) outputList.push(macIPv6);
            } else if (outputCase === "Upper only") {
                if (noDelim) outputList.push(cleanMac.toUpperCase());
                if (dashDelim) outputList.push(macHyphen.toUpperCase());
                if (colonDelim) outputList.push(macColon.toUpperCase());
                if (ciscoStyle) outputList.push(macCisco.toUpperCase());
                if (ipv6IntID) outputList.push(macIPv6.toUpperCase());
            } else {
                if (noDelim) outputList.push(cleanMac, cleanMac.toUpperCase());
                if (dashDelim) outputList.push(macHyphen, macHyphen.toUpperCase());
                if (colonDelim) outputList.push(macColon, macColon.toUpperCase());
                if (ciscoStyle) outputList.push(macCisco, macCisco.toUpperCase());
                if (ipv6IntID) outputList.push(macIPv6, macIPv6.toUpperCase());
            }

            outputList.push(
                "" // Empty line to delimit groups
            );
        });

        // Return the data as a string
        return outputList.join("\n");
    }

}

export default FormatMACAddresses;
