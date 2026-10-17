/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— IP 地址聚合
 * 【操作】Group IP addresses
 * 【功能】把一列散落的 IPv4 / IPv6 地址按给定 CIDR 前缀聚合，归入各自的子网并输出
 * 【输入】string —— 用参数 "Delimiter" 指定的分隔符切分的 IP 列表（IPv4、IPv6 可混用）
 * 【输出】string —— 每个子网一行（网络地址/CIDR），其下缩进列出属于它的成员地址
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 取分隔符、CIDR 前缀长度、是否只显示子网三个参数
 *   2. 由 CIDR 计算 ipv4Mask（32 位网络掩码）与 ipv6Mask（128 位，逐 hextet 的掩码数组）
 *   3. 校验 CIDR 是否落在 0..127
 *   4. 遍历每个 IP：
 *        IPv4 → IPV4_REGEX 匹配 → strToIpv4 得整数 → `ip & ipv4Mask` 得网络号 → 存入 ipv4Networks 字典
 *        IPv6 → IPV6_REGEX 匹配 → strToIpv6 得 8 hextet 数组 → 逐 hextet 与 ipv6Mask 相与
 *               → ipv6ToStr(压缩) 作键 → 存入 ipv6Networks 字典
 *   5. 输出每个 IPv4 子网及成员（仅当 !onlySubnets）
 *   6. 输出每个 IPv6 子网及成员（仅当 !onlySubnets）
 *   7. 返回拼接好的文本
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 网络掩码计算：`cidr < 32 ? ~(0xFFFFFFFF >>> cidr) : 0xFFFFFFFF`
 *       先把 0xFFFFFFFF 逻辑右移 cidr 位得到「低位全 1」，再按位取反得到「高位全 1」的掩码；
 *       cidr==32（/32）单独处理，避免移位计数达到 32 时 JS 只取模 32 导致的异常
 *   - 分组键 = 网络地址本身：IPv4 直接 `ip & ipv4Mask`；IPv6 对 8 个 hextet 逐个 `& ipv6Mask[j]`
 *   - 用普通对象 {网络地址: [成员…]} 充当字典完成聚合
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 复用 lib/Delim.mjs 的 IP_DELIM_OPTIONS 作为分隔符下拉选项
 *   - 源码中保留了一处 TODO：IPv6 成员列表尚未排序（IPv4 已排序），注释即文档
 * ============================================================
 */

import Operation from "../Operation.mjs";
import Utils from "../Utils.mjs";
import OperationError from "../errors/OperationError.mjs";
import {IP_DELIM_OPTIONS} from "../lib/Delim.mjs";
import {ipv6ToStr, genIpv6Mask, IPV4_REGEX, strToIpv6,  ipv4ToStr, IPV6_REGEX, strToIpv4} from "../lib/IP.mjs";

/**
 * 【类】GroupIPAddresses —— IP 地址按子网聚合操作
 * 继承 Operation 基类，只实现 run()；IPv4 与 IPv6 用同一套流程分别聚合。
 */
/**
 * Group IP addresses operation
 */
class GroupIPAddresses extends Operation {

    /**
     * 【构造函数】声明元信息与三个参数
     * name = "Group IP addresses"，module = "Default"，inputType/outputType 均为 "string"。
     * args[0] Delimiter         —— 选项，取自 IP_DELIM_OPTIONS（逗号/换行/空格等）
     * args[1] Subnet (CIDR)     —— 数字，前缀长度，默认 24，IPv4 取 0..32、IPv6 取 0..128
     * args[2] Only show the subnets —— 布尔，true 时只列子网不列成员，默认 false
     */
    /**
     * GroupIPAddresses constructor
     */
    constructor() {
        super();

        this.name = "Group IP addresses";
        this.module = "Default";
        this.description = "Groups a list of IP addresses into subnets. Supports both IPv4 and IPv6 addresses.";
        this.infoURL = "https://wikipedia.org/wiki/Subnetwork";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                "name": "Delimiter",
                "type": "option",
                "value": IP_DELIM_OPTIONS
            },
            {
                "name": "Subnet (CIDR)",
                "type": "number",
                "value": 24
            },
            {
                "name": "Only show the subnets",
                "type": "boolean",
                "value": false,
            }
        ];
    }

    /**
     * 【主流程】按 CIDR 把 IP 列表聚合到各子网
     * 返回值为多行文本；当 CIDR 超出 0..127 时抛 OperationError。
     */
    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        // 由 CIDR 前缀长度推导网络掩码：IPv4 为 32 位整数，IPv6 为 8 个 hextet 的掩码数组
        const delim = Utils.charRep(args[0]),
            cidr = args[1],
            onlySubnets = args[2],
            ipv4Mask = cidr < 32 ? ~(0xFFFFFFFF >>> cidr) : 0xFFFFFFFF,
            ipv6Mask = genIpv6Mask(cidr),
            ips = input.split(delim),
            ipv4Networks = {},
            ipv6Networks = {};
        let match = null,
            output = "",
            ip = null,
            network = null,
            networkStr = "",
            i;

        // --- 步骤 3：CIDR 合法性校验（IPv4 要求 0..32，IPv6 要求 0..128，这里统一放到 127 判定）---
        if (cidr < 0 || cidr > 127) {
            throw new OperationError("CIDR must be less than 32 for IPv4 or 128 for IPv6");
        }

        // --- 步骤 4：解析每个 IP，求其网络地址并归入对应子网字典 ---
        // Parse all IPs and add to network dictionary
        for (i = 0; i < ips.length; i++) {
            if ((match = IPV4_REGEX.exec(ips[i]))) {
                ip = strToIpv4(match[1]) >>> 0;
                network = ip & ipv4Mask;

                if (network in ipv4Networks) {
                    ipv4Networks[network].push(ip);
                } else {
                    ipv4Networks[network] = [ip];
                }
            } else if ((match = IPV6_REGEX.exec(ips[i]))) {
                ip = strToIpv6(match[1]);
                network = [];
                networkStr = "";

                for (let j = 0; j < 8; j++) {
                    network.push(ip[j] & ipv6Mask[j]);
                }

                networkStr = ipv6ToStr(network, true);

                if (networkStr in ipv6Networks) {
                    ipv6Networks[networkStr].push(ip);
                } else {
                    ipv6Networks[networkStr] = [ip];
                }
            }
        }

        // --- 步骤 5：输出每个 IPv4 子网及其成员（IPv4 成员已排序）---
        // Sort IPv4 network dictionaries and print
        for (network in ipv4Networks) {
            ipv4Networks[network] = ipv4Networks[network].sort();

            output += ipv4ToStr(network) + "/" + cidr + "\n";

            if (!onlySubnets) {
                for (i = 0; i < ipv4Networks[network].length; i++) {
                    output += "  " + ipv4ToStr(ipv4Networks[network][i]) + "\n";
                }
                output += "\n";
            }
        }

        // --- 步骤 6：输出每个 IPv6 子网及其成员 ---
        // Sort IPv6 network dictionaries and print
        for (networkStr in ipv6Networks) {
            // ipv6Networks[networkStr] = ipv6Networks[networkStr].sort();  TODO

            output += networkStr + "/" + cidr + "\n";

            if (!onlySubnets) {
                for (i = 0; i < ipv6Networks[networkStr].length; i++) {
                    output += "  " + ipv6ToStr(ipv6Networks[networkStr][i], true) + "\n";
                }
                output += "\n";
            }
        }

        return output;
    }

}

export default GroupIPAddresses;
