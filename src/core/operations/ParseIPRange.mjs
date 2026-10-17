/**
 * @author n1474335 [n1474335@gmail.com]
 * @author Klaxon [klaxon@veyr.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— IP 范围解析
 * 【操作】Parse IP range
 * 【功能】识别输入是 CIDR 网段、连字符范围还是 IP/CIDR 列表，给出网段信息并（对 IPv4）枚举全部地址
 * 【输入】string —— 三种形态之一：如 "10.0.0.0/24"、"10.0.0.0 - 10.0.1.0"、多行 IP/CIDR 列表
 * 【输出】string —— 网络信息与（可选）枚举出的地址列表
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 解构三个布尔参数：是否包含网络信息、是否枚举地址、是否允许大范围查询
 *   2. 六条正则分别描述 IPv4 的 CIDR / 连字符 / 列表，以及 IPv6 的对应三种
 *   3. 依次尝试匹配，命中即调用 lib/IP.mjs 中对应的处理函数：
 *        ipv4CidrRange / ipv4HyphenatedRange / ipv4ListedRange
 *        ipv6CidrRange / ipv6HyphenatedRange / ipv6ListedRange
 *   4. 六种都不匹配则抛 OperationError 提示正确输入格式
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 用正则的「捕获组」顺带完成地址与掩码的拆分，处理函数直接消费 match 数组，无需二次解析
 *   - ipv4ListRegex 用 `((IPv4或CIDR)(\n|$)(\n*))+` 匹配「一行一个、行尾可有空行」的多行列表
 *   - IPv6 正则为处理 :: 压缩而使用了大量前瞻与反向引用：
 *       `(?=.*::)` 要求串中存在 ::；`(?!.*::.+::)` 禁止出现两个 ::（防止 "1::2::3" 这类非法写法）；
 *       `\3`、`\4`、`\16`、`\17` 等反向引用把同一子模式复用，保证首尾地址写法自洽
 *   - IPv6 仅做网络信息，不枚举（地址空间过大，枚举无意义）
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 惯用法 `if ((match = regex.exec(input)))`：把匹配与赋值合并，命中即携带 match 进入分支
 *   - run() 本身保持「薄」——真正的地址运算全部下沉到 lib/IP.mjs，操作类只负责分发
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import {ipv4CidrRange, ipv4HyphenatedRange, ipv4ListedRange, ipv6CidrRange, ipv6HyphenatedRange, ipv6ListedRange} from "../lib/IP.mjs";

/**
 * 【类】ParseIPRange —— IP 范围/CIDR/列表解析操作
 * 继承 Operation 基类，只实现 run()；核心运算委托给 lib/IP.mjs。
 */
/**
 * Parse IP range operation
 */
class ParseIPRange extends Operation {

    /**
     * 【构造函数】声明元信息与三个布尔参数
     * name = "Parse IP range"，module = "Default"，inputType/outputType 均为 "string"。
     * args[0] Include network info   —— true 时输出网络地址、广播地址、掩码等网段信息
     * args[1] Enumerate IP addresses —— true 时逐个列出范围内的地址（IPv6 不枚举）
     * args[2] Allow large queries    —— true 时允许枚举超大网段（否则加保护，防卡死）
     */
    /**
     * ParseIPRange constructor
     */
    constructor() {
        super();

        this.name = "Parse IP range";
        this.module = "Default";
        this.description = "Given a CIDR range (e.g. <code>10.0.0.0/24</code>), hyphenated range (e.g. <code>10.0.0.0 - 10.0.1.0</code>), or a list of IPs and/or CIDR ranges (separated by a new line), this operation provides network information and enumerates all IP addresses in the range.<br><br>IPv6 is supported but will not be enumerated.";
        this.infoURL = "https://wikipedia.org/wiki/Subnetwork";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                "name": "Include network info",
                "type": "boolean",
                "value": true
            },
            {
                "name": "Enumerate IP addresses",
                "type": "boolean",
                "value": true
            },
            {
                "name": "Allow large queries",
                "type": "boolean",
                "value": false
            }
        ];
    }

    /**
     * 【主流程】识别输入形态并分派到对应的范围处理函数
     * 参数 args 见构造函数；返回处理函数产出的文本；输入无法识别时抛 OperationError。
     */
    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [
            includeNetworkInfo,
            enumerateAddresses,
            allowLargeList
        ] = args;

        // --- 步骤 2：按输入形态逐条匹配并分派（注意顺序：先具体后宽泛）---
        // Check what type of input we are looking at
        const ipv4CidrRegex = /^\s*((?:\d{1,3}\.){3}\d{1,3})\/(\d\d?)\s*$/,
            ipv4RangeRegex = /^\s*((?:\d{1,3}\.){3}\d{1,3})\s*-\s*((?:\d{1,3}\.){3}\d{1,3})\s*$/,
            ipv4ListRegex = /^\s*(((?:\d{1,3}\.){3}\d{1,3})(\/(\d\d?))?(\n|$)(\n*))+\s*$/,
            ipv6CidrRegex = /^\s*(((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\4)::|:\b|(?![\dA-F])))|(?!\3\4)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4}))\/(\d\d?\d?)\s*$/i,
            ipv6RangeRegex = /^\s*(((?=.*::)(?!.*::[^-]+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\4)::|:\b|(?![\dA-F])))|(?!\3\4)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4}))\s*-\s*(((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\17)::|:\b|(?![\dA-F])))|(?!\16\17)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4}))\s*$/i,
            ipv6ListRegex = /^\s*((((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\4)::|:\b|(?![\dA-F])))|(?!\3\4)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4}))(\/(\d\d?\d?))?(\n|$)(\n*))+\s*$/i;
        let match;

        if ((match = ipv4CidrRegex.exec(input))) {
            return ipv4CidrRange(match, includeNetworkInfo, enumerateAddresses, allowLargeList);
        } else if ((match = ipv4RangeRegex.exec(input))) {
            return ipv4HyphenatedRange(match, includeNetworkInfo, enumerateAddresses, allowLargeList);
        } else if ((match = ipv4ListRegex.exec(input))) {
            return ipv4ListedRange(match, includeNetworkInfo, enumerateAddresses, allowLargeList);
        } else if ((match = ipv6CidrRegex.exec(input))) {
            return ipv6CidrRange(match, includeNetworkInfo);
        } else if ((match = ipv6RangeRegex.exec(input))) {
            return ipv6HyphenatedRange(match, includeNetworkInfo);
        } else if ((match = ipv6ListRegex.exec(input))) {
            return ipv6ListedRange(match, includeNetworkInfo);
        } else {
            throw new OperationError("Invalid input.\n\nEnter either a CIDR range (e.g. 10.0.0.0/24) or a hyphenated range (e.g. 10.0.0.0 - 10.0.1.0). IPv6 also supported.");
        }
    }

}


export default ParseIPRange;
