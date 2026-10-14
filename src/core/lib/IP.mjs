/**
 * IP resources.
 *
 * @author picapi
 * @author n1474335 [n1474335@gmail.com]
 * @author Klaxon [klaxon@veyr.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 共享算法库
 * 【文件】src/core/lib/IP.mjs
 * 【职责】提供 IPv4/IPv6 地址的「字符串 ↔ 数值」双向转换、CIDR / 连字符网段解析、
 *         网段内地址枚举、IPv6 掩码生成、地址排序比较器，以及 IPv4/IPv6 校验正则
 *         和 IANA 协议号查找表；是网络类操作共用的底层工具集，不含任何 Operation 类。
 * 【被谁使用】（grep 查证）
 *   - src/core/operations/ParseIPv4Header.mjs  ← ipv4ToStr, protocolLookup
 *   - src/core/operations/ParseIPRange.mjs     ← ipv4CidrRange, ipv4HyphenatedRange,
 *                                                 ipv4ListedRange, ipv6CidrRange,
 *                                                 ipv6HyphenatedRange, ipv6ListedRange
 *   - src/core/operations/ParseIPv6Address.mjs ← strToIpv6, ipv6ToStr, ipv4ToStr, IPV6_REGEX
 *   - src/core/operations/GroupIPAddresses.mjs ← ipv6ToStr, genIpv6Mask, IPV4_REGEX,
 *                                                 strToIpv6, ipv4ToStr, IPV6_REGEX, strToIpv4
 * ------------------------------------------------------------
 * 【导出接口】
 *   - ipv4CidrRange(cidr, includeNetworkInfo, enumerateAddresses, allowLargeList) → string
 *       : 解析 IPv4 CIDR（如 192.168.0.0/24），输出网络/掩码/范围概要，可选枚举地址
 *   - ipv6CidrRange(cidr, includeNetworkInfo) → string
 *       : 解析 IPv6 CIDR（如 ff00::/48），输出概要
 *   - ipv4HyphenatedRange(range, includeNetworkInfo, enumerateAddresses, allowLargeList) → string
 *       : 解析 IPv4 连字符区间（如 192.168.0.0 - 192.168.0.255），反推最小子网
 *   - ipv6HyphenatedRange(range, includeNetworkInfo) → string
 *       : 解析 IPv6 连字符区间（如 ff00:: - ffff::）
 *   - ipv4ListedRange(match, includeNetworkInfo, enumerateAddresses, allowLargeList) → string
 *       : 解析换行分隔的 IPv4 列表（可含 CIDR），归并为区间
 *   - ipv6ListedRange(match, includeNetworkInfo) → string
 *       : 解析换行分隔的 IPv6 列表（可含 CIDR），归并为区间
 *   - strToIpv4(ipStr) → number            : IPv4 点分十进制 → 32 位整数
 *   - ipv4ToStr(ipInt) → string            : 32 位整数 → IPv4 点分十进制
 *   - strToIpv6(ipStr) → number[]          : IPv6 字符串（支持 :: 压缩）→ 8 段 16 位整数
 *   - ipv6ToStr(ipv6, compact) → string    : 8 段 16 位整数 → IPv6 字符串（compact 时压缩）
 *   - generateIpv4Range(ip, endIp) → string[] : 枚举 [ip, endIp] 内全部 IPv4 字符串
 *   - genIpv6Mask(cidr) → number[]         : 由 CIDR 生成 IPv6 的 8 段 16 位掩码
 *   - ipv4Compare(a, b) → number           : IPv4 排序比较器
 *   - ipv6Compare(a, b) → number           : IPv6 排序比较器
 *   - IPV4_REGEX : 匹配单个 IPv4 地址的正则
 *   - IPV6_REGEX : 匹配单个 IPv6 地址的正则（含压缩与内嵌 IPv4 形态）
 *   - protocolLookup : 协议号(0-255) → {keyword, protocol} 查找表
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 位运算转换：strToIpv4/ipv4ToStr 用「移位 + &255 掩码」在 4 个字节与一个
 *     32 位整数间互转，最高位字节在左（大端）
 *   - CIDR 掩码：`~(0xFFFFFFFF >>> cidrRange)` 生成高 cidrRange 位为 1 的掩码；
 *     网络地址 = ip & mask，广播地址 = ip | ~mask
 *   - IPv6 :: 压缩的解析与生成：strToIpv6 用「剩余段计数」定位省略段并补零；
 *     ipv6ToStr 扫描最长连续 0 段（≥2 段）并用 :: 表示
 *   - 大区间保护：地址数 > 65536 时默认拒绝枚举（_LARGE_RANGE_ERROR）
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - IPv4 逻辑上是无符号 32 位，但 JS 位运算返回**有符号 int32**；涉及减法/取值
 *     规模时用 `>>> 0` 归一化为无符号（见 Total addresses 计算）
 *   - IPv6 用「8 段 16 位整数数组」而非 BigInt，规避老环境 BigInt 兼容问题
 *   - IPV6_REGEX 用回溯引用 \3\4 精确约束 :: 只能出现一次
 * ============================================================
 */

import Utils from "../Utils.mjs";
import OperationError from "../errors/OperationError.mjs";

/**
 * 【函数】解析 IPv4 CIDR 网段并输出概要（可选枚举全部地址）
 *
 * 参数：
 *   - cidr[1]             : 网络地址字符串（如 "192.168.0.0"）
 *   - cidr[2]             : 前缀长度字符串（如 "24"）
 *   - includeNetworkInfo  : 是否输出 Network/CIDR/Mask/Range/总数 等概要
 *   - enumerateAddresses  : 是否逐行枚举网段内每一个地址
 *   - allowLargeList      : 是否允许枚举超过 65536 个地址的大列表
 * 返回：拼接好的多行文本
 *
 * 算法要点：
 *   - 掩码 mask = ~(0xFFFFFFFF >>> cidrRange)：先无符号右移把低 (32-n) 位填 1，
 *     再整体取反，得到「高 cidrRange 位为 1」的网络掩码（后续按位运算保持 32 位语义）
 *   - 网络地址 ip1 = network & mask；广播地址 ip2 = ip1 | ~mask
 *   - 地址总数 = ((ip2 - ip1) >>> 0) + 1；因 JS 减法可能得到负的有符号值，
 *     这里必须用 >>> 0 归一化为无符号再 +1
 * 边界：
 *   - cidrRange 必须 0..31，否则抛 OperationError（/32 单地址不在此路径处理）
 *   - 枚举阈值：cidrRange >= 16（最多 65536 个地址）才默认允许，否则输出大范围告警
 */
/**
 * Parses an IPv4 CIDR range (e.g. 192.168.0.0/24) and displays information about it.
 *
 * @param {RegExp} cidr
 * @param {boolean} includeNetworkInfo
 * @param {boolean} enumerateAddresses
 * @param {boolean} allowLargeList
 * @returns {string}
 */
export function ipv4CidrRange(cidr, includeNetworkInfo, enumerateAddresses, allowLargeList) {
    const network = strToIpv4(cidr[1]),
        cidrRange = parseInt(cidr[2], 10);
    let output = "";

    if (cidrRange < 0 || cidrRange > 31) {
        throw new OperationError("IPv4 CIDR must be less than 32");
    }

    const mask = ~(0xFFFFFFFF >>> cidrRange),
        ip1 = network & mask,
        ip2 = ip1 | ~mask;

    if (includeNetworkInfo) {
        output += "Network: " + ipv4ToStr(ip1) + "\n";
        output += "CIDR: " + cidrRange + "\n";
        output += "Mask: " + ipv4ToStr(mask) + "\n";
        output += "Range: " + ipv4ToStr(ip1) + " - " + ipv4ToStr(ip2) + "\n";
        output += "Total addresses in range: " + (((ip2 - ip1) >>> 0) + 1) + "\n\n";
    }

    if (enumerateAddresses) {
        if (cidrRange >= 16 || allowLargeList) {
            output += generateIpv4Range(ip1, ip2).join("\n");
        } else {
            output += _LARGE_RANGE_ERROR;
        }
    }
    return output;
}

/**
 * 【函数】解析 IPv6 CIDR 网段并输出概要
 *
 * 参数：
 *   - cidr[1]            : 网络地址字符串；cidr[cidr.length-1] : 前缀长度字符串
 *   - includeNetworkInfo : 是否输出 Network/Shorthand/CIDR/Mask/Range/总数
 * 返回：多行文本
 *
 * 算法要点：
 *   - genIpv6Mask(cidrRange) 生成 8 段 16 位掩码
 *   - 网络段 ip1[i] = network[i] & mask[i]
 *     广播段 ip2[i] = ip1[i] | (~mask[i] & 0x0000FFFF)（补回本段低 16 位）
 *   - 地址总数：把 8 段差值各转二进制、右对齐写入 128 位数组 total，
 *     最后 parseInt(total.join(""), 2) + 1；用字符串承载 128 位结果以规避
 *     Number 只能安全表示 2^53 的限制
 * 边界：cidrRange 必须 0..127，否则抛 OperationError
 */
/**
 * Parses an IPv6 CIDR range (e.g. ff00::/48) and displays information about it.
 *
 * @param {RegExp} cidr
 * @param {boolean} includeNetworkInfo
 * @returns {string}
 */
export function ipv6CidrRange(cidr, includeNetworkInfo) {
    let output = "";
    const network = strToIpv6(cidr[1]),
        cidrRange = parseInt(cidr[cidr.length-1], 10);

    if (cidrRange < 0 || cidrRange > 127) {
        throw new OperationError("IPv6 CIDR must be less than 128");
    }

    const ip1 = new Array(8),
        ip2 = new Array(8),
        total = new Array(128);

    const mask = genIpv6Mask(cidrRange);
    let totalDiff = "";


    for (let i = 0; i < 8; i++) {
        ip1[i] = network[i] & mask[i];
        ip2[i] = ip1[i] | (~mask[i] & 0x0000FFFF);
        totalDiff = (ip2[i] - ip1[i]).toString(2);

        if (totalDiff !== "0") {
            for (let n = 0; n < totalDiff.length; n++) {
                total[i*16 + 16-(totalDiff.length-n)] = totalDiff[n];
            }
        }
    }

    if (includeNetworkInfo) {
        output += "Network: " + ipv6ToStr(ip1) + "\n";
        output += "Shorthand: " + ipv6ToStr(ip1, true) + "\n";
        output += "CIDR: " + cidrRange + "\n";
        output += "Mask: " + ipv6ToStr(mask) + "\n";
        output += "Range: " + ipv6ToStr(ip1) + " - " + ipv6ToStr(ip2) + "\n";
        output += "Total addresses in range: " + (parseInt(total.join(""), 2) + 1) + "\n\n";
    }

    return output;
}

/**
 * 【函数】解析 IPv4 连字符区间（a - b），并反推能容纳该区间的最小 CIDR 子网
 *
 * 参数：
 *   - range[0]           : "起始IP - 结束IP" 字符串
 *   - includeNetworkInfo / enumerateAddresses / allowLargeList : 同 ipv4CidrRange
 * 返回：多行文本
 *
 * 算法要点：
 *   - diff = ip1 ^ ip2：异或后为 1 的位即两地址不同的位；从低位起每右移一位
 *     就 cidr-- 并给 mask 左移补一个 1，循环到 diff 归零，即得刚好覆盖两端的
 *     最小前缀长度 cidr
 *   - mask = ~mask >>> 0 转成网络掩码；network = ip1 & mask 为子网基址
 *   - 枚举阈值：区间地址数 ((ip2-ip1)>>>0) <= 65536 或 allowLargeList 才枚举
 * 边界：传入逆序区间（ip2 < ip1）时差值为极大无符号数，通常触发大范围保护而拒绝枚举
 */
/**
 * Parses an IPv4 hyphenated range (e.g. 192.168.0.0 - 192.168.0.255) and displays information
 * about it.
 *
 * @param {RegExp} range
 * @param {boolean} includeNetworkInfo
 * @param {boolean} enumerateAddresses
 * @param {boolean} allowLargeList
 * @returns {string}
 */
export function ipv4HyphenatedRange(range, includeNetworkInfo, enumerateAddresses, allowLargeList) {
    const ip1 = strToIpv4(range[0].split("-")[0].trim()),
        ip2 = strToIpv4(range[0].split("-")[1].trim());

    let output = "";

    // Calculate mask
    let diff = ip1 ^ ip2,
        cidr = 32,
        mask = 0;

    while (diff !== 0) {
        diff >>= 1;
        cidr--;
        mask = (mask << 1) | 1;
    }

    mask = ~mask >>> 0;
    const network = ip1 & mask,
        subIp1 = network & mask,
        subIp2 = subIp1 | ~mask;

    if (includeNetworkInfo) {
        output += `Minimum subnet required to hold this range:
\tNetwork: ${ipv4ToStr(network)}
\tCIDR: ${cidr}
\tMask: ${ipv4ToStr(mask)}
\tSubnet range: ${ipv4ToStr(subIp1)} - ${ipv4ToStr(subIp2)}
\tTotal addresses in subnet: ${(((subIp2 - subIp1) >>> 0) + 1)}

Range: ${ipv4ToStr(ip1)} - ${ipv4ToStr(ip2)}
Total addresses in range: ${(((ip2 - ip1) >>> 0) + 1)}

`;
    }

    if (enumerateAddresses) {
        if (((ip2 - ip1) >>> 0) <= 65536 || allowLargeList) {
            output += generateIpv4Range(ip1, ip2).join("\n");
        } else {
            output += _LARGE_RANGE_ERROR;
        }
    }
    return output;
}

/**
 * 【函数】解析 IPv6 连字符区间（a - b）并统计地址总数
 *
 * 参数：
 *   - range[0]           : "起始 - 结束" 字符串
 *   - includeNetworkInfo : 是否输出 Range / Shorthand range / 总数
 * 返回：多行文本
 *
 * 算法要点：
 *   - 逐段（8 个 16 位）计算 ip2[i] - ip1[i]，转二进制后右对齐写入 128 位 total 数组
 *   - 总数 = parseInt(total.join(""), 2) + 1（字符串承载 128 位，避免数值溢出）
 */
/**
 * Parses an IPv6 hyphenated range (e.g. ff00:: - ffff::) and displays information about it.
 *
 * @param {RegExp} range
 * @param {boolean} includeNetworkInfo
 * @returns {string}
 */
export function ipv6HyphenatedRange(range, includeNetworkInfo) {
    const ip1 = strToIpv6(range[0].split("-")[0].trim()),
        ip2 = strToIpv6(range[0].split("-")[1].trim()),
        total = new Array(128).fill();

    let output = "",
        t = "",
        i;

    for (i = 0; i < 8; i++) {
        t = (ip2[i] - ip1[i]).toString(2);
        if (t !== "0") {
            for (let n = 0; n < t.length; n++) {
                total[i*16 + 16-(t.length-n)] = t[n];
            }
        }
    }

    if (includeNetworkInfo) {
        output += "Range: " + ipv6ToStr(ip1) + " - " + ipv6ToStr(ip2) + "\n";
        output += "Shorthand range: " + ipv6ToStr(ip1, true) + " - " + ipv6ToStr(ip2, true) + "\n";
        output += "Total addresses in range: " + (parseInt(total.join(""), 2) + 1) + "\n\n";
    }

    return output;
}

/**
 * 【函数】解析换行分隔的 IPv4 列表（可混入 CIDR 写法），归并为一个区间
 *
 * 参数：
 *   - match[0]           : 原始多行文本
 *   - includeNetworkInfo / enumerateAddresses / allowLargeList : 同 ipv4CidrRange
 * 返回：多行文本（内部最终委托 ipv4HyphenatedRange 处理）
 *
 * 算法要点：
 *   - 按 "\n" 拆行并过滤空行（filter(Boolean)）
 *   - 对含 "/" 的 CIDR 条目：算出其网络地址与广播地址，从列表中剔除原条目、
 *     改推入这两个端点（即把网段「压平」成一对地址）
 *   - 整体按 ipv4Compare 排序，取首（最小）与末（最大）组成区间字符串再交给
 *     ipv4HyphenatedRange 复用其最小子网推导与枚举逻辑
 * 边界：列表中每个 CIDR 的前缀长度同样校验 0..31
 */
/**
 * Parses a list of IPv4 addresses separated by a new line (\n) and displays information
 * about it.
 *
 * @param {RegExp} list
 * @param {boolean} includeNetworkInfo
 * @param {boolean} enumerateAddresses
 * @param {boolean} allowLargeList
 * @returns {string}
 */
export function ipv4ListedRange(match, includeNetworkInfo, enumerateAddresses, allowLargeList) {

    let ipv4List = match[0].split("\n");
    ipv4List = ipv4List.filter(Boolean);

    const ipv4CidrList = ipv4List.filter(function(a) {
        return a.includes("/");
    });
    for (let i = 0; i < ipv4CidrList.length; i++) {
        const network = strToIpv4(ipv4CidrList[i].split("/")[0]);
        const cidrRange = parseInt(ipv4CidrList[i].split("/")[1], 10);
        if (cidrRange < 0 || cidrRange > 31) {
            throw new OperationError("IPv4 CIDR must be less than 32");
        }
        const mask = ~(0xFFFFFFFF >>> cidrRange),
            cidrIp1 = network & mask,
            cidrIp2 = cidrIp1 | ~mask;
        ipv4List.splice(ipv4List.indexOf(ipv4CidrList[i]), 1);
        ipv4List.push(ipv4ToStr(cidrIp1), ipv4ToStr(cidrIp2));
    }

    ipv4List = ipv4List.sort(ipv4Compare);
    const ip1 = ipv4List[0];
    const ip2 = ipv4List[ipv4List.length - 1];
    const range = [ip1 + " - " + ip2];
    return ipv4HyphenatedRange(range, includeNetworkInfo, enumerateAddresses, allowLargeList);
}

/**
 * 【函数】解析换行分隔的 IPv6 列表（可混入 CIDR），归并为一个区间
 *
 * 参数：
 *   - match[0]           : 原始多行文本
 *   - includeNetworkInfo : 是否输出概要
 * 返回：多行文本（内部委托 ipv6HyphenatedRange 处理）
 *
 * 算法要点：
 *   - 按行拆分并逐条 trim、过滤空行
 *   - 含 "/" 的条目用 genIpv6Mask 求掩码，算出首/末地址后替换原条目
 *   - 整体按 ipv6Compare 排序，取最小/最大地址组成区间
 * 边界：每个 CIDR 前缀长度校验 0..127
 */
/**
 * Parses a list of IPv6 addresses separated by a new line (\n) and displays information
 * about it.
 *
 * @param {RegExp} list
 * @param {boolean} includeNetworkInfo
 * @returns {string}
 */
export function ipv6ListedRange(match, includeNetworkInfo) {

    let ipv6List = match[0].split("\n");
    ipv6List = ipv6List.filter(function(str) {
        return str.trim();
    });
    for (let i =0; i < ipv6List.length; i++) {
        ipv6List[i] = ipv6List[i].trim();
    }
    const ipv6CidrList = ipv6List.filter(function(a) {
        return a.includes("/");
    });

    for (let i = 0; i < ipv6CidrList.length; i++) {

        const network = strToIpv6(ipv6CidrList[i].split("/")[0]);
        const cidrRange = parseInt(ipv6CidrList[i].split("/")[1], 10);

        if (cidrRange < 0 || cidrRange > 127) {
            throw new OperationError("IPv6 CIDR must be less than 128");
        }

        const cidrIp1 = new Array(8),
            cidrIp2 = new Array(8);

        const mask = genIpv6Mask(cidrRange);

        for (let j = 0; j < 8; j++) {
            cidrIp1[j] = network[j] & mask[j];
            cidrIp2[j] = cidrIp1[j] | (~mask[j] & 0x0000FFFF);
        }
        ipv6List.splice(ipv6List.indexOf(ipv6CidrList[i]), 1);
        ipv6List.push(ipv6ToStr(cidrIp1), ipv6ToStr(cidrIp2));
    }
    ipv6List = ipv6List.sort(ipv6Compare);
    const ip1 = ipv6List[0];
    const ip2 = ipv6List[ipv6List.length - 1];
    const range = [ip1 + " - " + ip2];
    return ipv6HyphenatedRange(range, includeNetworkInfo);
}

/**
 * 【函数】IPv4 点分十进制字符串 → 32 位整数
 *
 * 参数：ipStr，形如 "10.10.0.0"
 * 返回：number；如 "10.10.0.0" → 168427520
 *
 * 算法要点（移位拼接，大端）：
 *   result = (b0 << 24) + (b1 << 16) + (b2 << 8) + b3
 *   把 4 个 0..255 的字节按「最高位字节在左」的顺序依次左移装入一个 32 位整数：
 *   第 0 段占 bit24-31，第 1 段占 bit16-23，第 2 段占 bit8-15，第 3 段占 bit0-7。
 *   注意 << 产生的是 32 位有符号值，当首段 ≥ 128（如 192.x）结果为负数，
 *   这是表示「无符号 32 位」的常见现象，需要按无符号解释时由调用方 >>> 0。
 * 边界：必须恰好 4 段且每段 0..255，否则抛 OperationError（见内部 parseBlocks）。
 */
/**
 * Converts an IPv4 address from string format to numerical format.
 *
 * @param {string} ipStr
 * @returns {number}
 *
 * @example
 * // returns 168427520
 * strToIpv4("10.10.0.0");
 */
export function strToIpv4(ipStr) {
    const blocks = ipStr.split("."),
        numBlocks = parseBlocks(blocks);
    let result = 0;

    result += numBlocks[0] << 24;
    result += numBlocks[1] << 16;
    result += numBlocks[2] << 8;
    result += numBlocks[3];

    return result;

    /**
     * 【内部辅助】把 IPv4 的 4 段数字字符串校验并转为数字数组。
     * 边界：段数必须恰为 4，且每段须落 0..255，否则抛 OperationError。
     */
    /**
     * Converts a list of 4 numeric strings in the range 0-255 to a list of numbers.
     */
    function parseBlocks(blocks) {
        if (blocks.length !== 4)
            throw new OperationError("More than 4 blocks.");

        const numBlocks = [];
        for (let i = 0; i < 4; i++) {
            numBlocks[i] = parseInt(blocks[i], 10);
            if (numBlocks[i] < 0 || numBlocks[i] > 255)
                throw new OperationError("Block out of range.");
        }
        return numBlocks;
    }
}

/**
 * 【函数】32 位整数 → IPv4 点分十进制字符串
 *
 * 参数：ipInt，整数（允许有符号，内部按无符号 32 位解释）
 * 返回：string；如 168427520 → "10.10.0.0"
 *
 * 算法要点（无符号右移 + 掩码，与 strToIpv4 互逆）：
 *   blockA = (ipInt >>> 24) & 255   // 取最高 8 位
 *   blockB = (ipInt >>> 16) & 255   // 取次高 8 位
 *   blockC = (ipInt >>> 8)  & 255   // 取次低 8 位
 *   blockD =  ipInt         & 255   // 取最低 8 位
 *   用「无符号右移 >>>」把目标字节移到最低位，再用 & 255（0xFF）只保留该字节、
 *   清掉其余高位，从而把 32 位整数拆回 4 个 0..255 的十进制段。
 *   这里必须用 >>> 而非 >>，否则最高位为 1 的地址（≥128.x）会因符号扩展出错。
 */
/**
 * Converts an IPv4 address from numerical format to string format.
 *
 * @param {number} ipInt
 * @returns {string}
 *
 * @example
 * // returns "10.10.0.0"
 * ipv4ToStr(168427520);
 */
export function ipv4ToStr(ipInt) {
    const blockA = (ipInt >> 24) & 255,
        blockB = (ipInt >> 16) & 255,
        blockC = (ipInt >> 8) & 255,
        blockD = ipInt & 255;

    return blockA + "." + blockB + "." + blockC + "." + blockD;
}


/**
 * 【函数】IPv6 字符串 → 8 段 16 位整数数组（展开 :: 压缩写法）
 *
 * 参数：ipStr，如 "ff00::1111:2222"
 * 返回：number[8]；如 [65280, 0, 0, 0, 0, 0, 4369, 8738]
 *
 * 算法要点（:: 压缩段定位）：
 *   - IPv6 固定 8 段，外层下标 i 走 0..7，内层游标 j 指向 numBlocks 当前待取段
 *   - 取到 NaN（即 :: 产生的空缺）时该槽填 0；
 *     关键判断 `i === (8 - numBlocks.slice(j).length)`：当「剩余待填槽位数」恰好
 *     等于「剩余有效段数」时，补零结束、开始拷贝真实段，从而正确对齐压缩点
 *   - 非压缩地址时 numBlocks 长度为 8，可直接逐段拷贝，不需补零
 * 边界：段数须 3..8、每段 0..65535，否则抛 OperationError（见内部 parseBlocks）。
 */
/**
 * Converts an IPv6 address from string format to numerical array format.
 *
 * @param {string} ipStr
 * @returns {number[]}
 *
 * @example
 * // returns [65280, 0, 0, 0, 0, 0, 4369, 8738]
 * strToIpv6("ff00::1111:2222");
 */
export function strToIpv6(ipStr) {
    let j = 0;
    const blocks = ipStr.split(":"),
        numBlocks = parseBlocks(blocks),
        ipv6 = new Array(8);

    for (let i = 0; i < 8; i++) {
        if (isNaN(numBlocks[j])) {
            ipv6[i] = 0;
            if (i === (8-numBlocks.slice(j).length)) j++;
        } else {
            ipv6[i] = numBlocks[j];
            j++;
        }
    }
    return ipv6;

    /**
     * 【内部辅助】把 IPv6 的 3~8 段 16 进制字符串校验并转为数字数组。
     * 边界：段数须 3..8（3 段对应至少含一个 :: 的压缩地址），
     * 每段按 16 进制解析且须落 0..65535，否则抛 OperationError。
     */
    /**
     * Converts a list of 3-8 numeric hex strings in the range 0-65535 to a list of numbers.
     */
    function parseBlocks(blocks) {
        if (blocks.length < 3 || blocks.length > 8)
            throw new OperationError("Badly formatted IPv6 address.");
        const numBlocks = [];
        for (let i = 0; i < blocks.length; i++) {
            numBlocks[i] = parseInt(blocks[i], 16);
            if (numBlocks[i] < 0 || numBlocks[i] > 65535)
                throw new OperationError("Block out of range.");
        }
        return numBlocks;
    }
}

/**
 * 【函数】8 段 16 位整数数组 → IPv6 字符串（可选 :: 压缩）
 *
 * 参数：
 *   - ipv6    : number[8]
 *   - compact : true 用 :: 压缩最长连续 0 段；false 输出完整 8 段
 * 返回：string
 *
 * 算法要点（最长零段压缩）：
 *   - 第一趟扫描找「最长连续 0 段」的起止 [start,end]：用 s/e 追踪当前连续 0 段，
 *     每遇 0 且与前一段连续就延伸 e；一旦 (e-s) 超过历史最优就更新 start/end。
 *     因初值 end-start=0 且判据是严格大于，单段 0 不会被压缩，只有 ≥2 段连续 0 才用 ::
 *   - 第二趟输出：段号 i 若等于 start，则只输出一个 ":" 并把 i 直接跳到 end，
 *     用 :: 代表整段被省略的 0（end===7 时补尾冒号以正确表示结尾 ::）
 *   - 非压缩分支：每段用 Utils.hex(v, 4) 左补零成 4 位 16 进制
 *   - 最后统一去掉末尾多余的冒号；全 0 地址会得到 "::"
 */
/**
 * Converts an IPv6 address from numerical array format to string format.
 *
 * @param {number[]} ipv6
 * @param {boolean} compact - Whether or not to return the address in shorthand or not
 * @returns {string}
 *
 * @example
 * // returns "ff00::1111:2222"
 * ipv6ToStr([65280, 0, 0, 0, 0, 0, 4369, 8738], true);
 *
 * // returns "ff00:0000:0000:0000:0000:0000:1111:2222"
 * ipv6ToStr([65280, 0, 0, 0, 0, 0, 4369, 8738], false);
 */
export function ipv6ToStr(ipv6, compact) {
    let output = "",
        i = 0;

    if (compact) {
        let start = -1,
            end = -1,
            s = 0,
            e = -1;

        for (i = 0; i < 8; i++) {
            if (ipv6[i] === 0 && e === (i-1)) {
                e = i;
            } else if (ipv6[i] === 0) {
                s = i; e = i;
            }
            if (e >= 0 && (e-s) > (end - start)) {
                start = s;
                end = e;
            }
        }

        for (i = 0; i < 8; i++) {
            if (i !== start) {
                output += Utils.hex(ipv6[i], 1) + ":";
            } else {
                output += ":";
                i = end;
                if (end === 7) output += ":";
            }
        }
        if (output[0] === ":")
            output = ":" + output;
    } else {
        for (i = 0; i < 8; i++) {
            output += Utils.hex(ipv6[i], 4) + ":";
        }
    }
    return output.slice(0, output.length-1);
}

/**
 * 【函数】枚举两个 IPv4 整数之间的全部地址
 *
 * 参数：ip 起始整数，endIp 结束整数
 * 返回：string[]，每个元素为一个点分十进制地址（含 both 边界）
 *
 * 算法要点：从 ip 递增到 endIp，逐个 ipv4ToStr 入数组；若 endIp < ip（逆序），
 * 则不枚举，返回单元素提示数组 ["Second IP address smaller than first."]。
 * 边界：本函数不做规模保护，调用方需先用 _LARGE_RANGE_ERROR 阈值卡住超大区间。
 */
/**
 * Generates a list of IPv4 addresses in string format between two given numerical values.
 *
 * @param {number} ip
 * @param {number} endIp
 * @returns {string[]}
 *
 * @example
 * // returns ["0.0.0.1", "0.0.0.2", "0.0.0.3"]
 * IP.generateIpv4Range(1, 3);
 */
export function generateIpv4Range(ip, endIp) {
    const range = [];
    if (endIp >= ip) {
        for (; ip <= endIp; ip++) {
            range.push(ipv4ToStr(ip));
        }
    } else {
        range[0] = "Second IP address smaller than first.";
    }
    return range;
}

/**
 * 【函数】由 CIDR 前缀长度生成 IPv6 的 8 段 16 位掩码
 *
 * 参数：cidr，0..128
 * 返回：number[8]，每段 0..65535 的掩码值
 *
 * 算法要点（逐段计算）：
 *   - 第 i 段覆盖整地址的第 i*16 .. i*16+15 位
 *   - 若 cidr > (i+1)*16：该段整段都在网络前缀内，掩码取满 0x0000FFFF
 *   - 否则 shift = cidr - i*16（本段内需保留的高位数，<0 时钳为 0），
 *     掩码 = ~((0x0000FFFF >>> shift) | 0xFFFF0000)：
 *       先用 0xFFFF>>>shift 得到本段低 16 位中「前 shift 位为 1」，
 *       再 |0xFFFF0000 把高 16 位填满，取反后仅保留本段低 16 位中高 shift 位为 1，
 *       这样能把 JS 的 32 位运算结果裁回本段 16 位
 * 边界：shift<0 表示该段完全在前缀之外，掩码为 0
 */
/**
 * Generates an IPv6 subnet mask given a CIDR value.
 *
 * @param {number} cidr
 * @returns {number[]}
 */
export function genIpv6Mask(cidr) {
    const mask = new Array(8);
    let shift;

    for (let i = 0; i < 8; i++) {
        if (cidr > ((i+1)*16)) {
            mask[i] = 0x0000FFFF;
        } else {
            shift = cidr-(i*16);
            if (shift < 0) shift = 0;
            mask[i] = ~((0x0000FFFF >>> shift) | 0xFFFF0000);
        }
    }

    return mask;
}

/**
 * 【函数】IPv4 地址排序比较器
 *
 * 参数：a、b 均为点分十进制字符串
 * 返回：负数表示 a 在前，正数表示 b 在前
 * 算法要点：把两地址都转成数值后相减，借数值大小实现「按 IP 数字序」而非字典序排序
 */
/**
 * Comparison operation for sorting of IPv4 addresses.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function ipv4Compare(a, b) {
    return strToIpv4(a) - strToIpv4(b);
}

/**
 * 【函数】IPv6 地址排序比较器
 *
 * 参数：a、b 均为 IPv6 字符串
 * 返回：负数/0/正数
 * 算法要点：把两地址转成 8 段整数数组，从高位段到低位段逐段比较，
 * 首个不相等段相减即定序；全部相等返回 0。等价于按 128 位无符号大小排序。
 */
/**
 * Comparison operation for sorting of IPv6 addresses.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function ipv6Compare(a, b) {

    const a_ = strToIpv6(a),
        b_ = strToIpv6(b);

    for (let i = 0; i < a_.length; i++) {
        if (a_[i] !== b_[i]) {
            return a_[i] - b_[i];
        }
    }
    return 0;
}

// --- 错误提示常量 ---
/**
 * 超大地址区间告警文案：当枚举请求超过 65536 个地址且用户未选择
 * "Allow large queries" 时作为输出返回，避免一次性生成过大列表卡死浏览器。
 */
const _LARGE_RANGE_ERROR = "The specified range contains more than 65,536 addresses. Running this query could crash your browser. If you want to run it, select the \"Allow large queries\" option. You are advised to turn off \"Auto Bake\" whilst editing large ranges.";

// --- 地址校验正则 ---
/**
 * IPv4 地址匹配正则：匹配单个点分十进制地址 4 段形式，允许两端空白。
 * 注意这里只校验「形如 x.x.x.x」，并不约束每段取值范围（数值范围由 strToIpv4 把关）。
 */
/**
 * A regular expression that matches an IPv4 address
 */
export const IPV4_REGEX = /^\s*((?:\d{1,3}\.){3}\d{1,3})\s*$/;

/**
 * IPv6 地址匹配正则（忽略大小写）：覆盖压缩写法（:: 只能出现一次，由回溯引用
 * \3\4 保证）、完整 8 段写法，以及末段内嵌 IPv4（如 ::ffff:192.168.0.1）的形态。
 */
/**
 * A regular expression that matches an IPv6 address
 */
export const IPV6_REGEX = /^\s*(((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\4)::|:\b|(?![\dA-F])))|(?!\3\4)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4}))\s*$/i;

// --- 协议号查找表 ---
/**
 * 协议号 → 协议信息 查找表（键为十进制协议号 0..255）。
 * 数据来源：IANA Protocol Numbers 注册表
 * （https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml）。
 * 每项结构 {keyword, protocol}：keyword 为协议关键字（如 "TCP"），
 * protocol 为全称（如 "Transmission Control"）。
 * 使用方：ParseIPv4Header 依 IPv4 首部的 protocol 字节查表得传输层协议名；
 * 表中未收录的协议号查得 undefined，调用方需自行兜底（如 || {keyword:"", protocol:""}）。
 * 说明：部分分配项无关键字或为保留/实验用途，keyword 可能为空串。
 */
/**
 * Lookup table for Internet Protocols.
 * Taken from https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
export const protocolLookup = {
    0: {keyword: "HOPOPT", protocol: "IPv6 Hop-by-Hop Option"},
    1: {keyword: "ICMP", protocol: "Internet Control Message"},
    2: {keyword: "IGMP", protocol: "Internet Group Management"},
    3: {keyword: "GGP", protocol: "Gateway-to-Gateway"},
    4: {keyword: "IPv4", protocol: "IPv4 encapsulation"},
    5: {keyword: "ST", protocol: "Stream"},
    6: {keyword: "TCP", protocol: "Transmission Control"},
    7: {keyword: "CBT", protocol: "CBT"},
    8: {keyword: "EGP", protocol: "Exterior Gateway Protocol"},
    9: {keyword: "IGP", protocol: "any private interior gateway (used by Cisco for their IGRP)"},
    10: {keyword: "BBN-RCC-MON", protocol: "BBN RCC Monitoring"},
    11: {keyword: "NVP-II", protocol: "Network Voice Protocol"},
    12: {keyword: "PUP", protocol: "PUP"},
    13: {keyword: "ARGUS (deprecated)", protocol: "ARGUS"},
    14: {keyword: "EMCON", protocol: "EMCON"},
    15: {keyword: "XNET", protocol: "Cross Net Debugger"},
    16: {keyword: "CHAOS", protocol: "Chaos"},
    17: {keyword: "UDP", protocol: "User Datagram"},
    18: {keyword: "MUX", protocol: "Multiplexing"},
    19: {keyword: "DCN-MEAS", protocol: "DCN Measurement Subsystems"},
    20: {keyword: "HMP", protocol: "Host Monitoring"},
    21: {keyword: "PRM", protocol: "Packet Radio Measurement"},
    22: {keyword: "XNS-IDP", protocol: "XEROX NS IDP"},
    23: {keyword: "TRUNK-1", protocol: "Trunk-1"},
    24: {keyword: "TRUNK-2", protocol: "Trunk-2"},
    25: {keyword: "LEAF-1", protocol: "Leaf-1"},
    26: {keyword: "LEAF-2", protocol: "Leaf-2"},
    27: {keyword: "RDP", protocol: "Reliable Data Protocol"},
    28: {keyword: "IRTP", protocol: "Internet Reliable Transaction"},
    29: {keyword: "ISO-TP4", protocol: "ISO Transport Protocol Class 4"},
    30: {keyword: "NETBLT", protocol: "Bulk Data Transfer Protocol"},
    31: {keyword: "MFE-NSP", protocol: "MFE Network Services Protocol"},
    32: {keyword: "MERIT-INP", protocol: "MERIT Internodal Protocol"},
    33: {keyword: "DCCP", protocol: "Datagram Congestion Control Protocol"},
    34: {keyword: "3PC", protocol: "Third Party Connect Protocol"},
    35: {keyword: "IDPR", protocol: "Inter-Domain Policy Routing Protocol"},
    36: {keyword: "XTP", protocol: "XTP"},
    37: {keyword: "DDP", protocol: "Datagram Delivery Protocol"},
    38: {keyword: "IDPR-CMTP", protocol: "IDPR Control Message Transport Proto"},
    39: {keyword: "TP++", protocol: "TP++ Transport Protocol"},
    40: {keyword: "IL", protocol: "IL Transport Protocol"},
    41: {keyword: "IPv6", protocol: "IPv6 encapsulation"},
    42: {keyword: "SDRP", protocol: "Source Demand Routing Protocol"},
    43: {keyword: "IPv6-Route", protocol: "Routing Header for IPv6"},
    44: {keyword: "IPv6-Frag", protocol: "Fragment Header for IPv6"},
    45: {keyword: "IDRP", protocol: "Inter-Domain Routing Protocol"},
    46: {keyword: "RSVP", protocol: "Reservation Protocol"},
    47: {keyword: "GRE", protocol: "Generic Routing Encapsulation"},
    48: {keyword: "DSR", protocol: "Dynamic Source Routing Protocol"},
    49: {keyword: "BNA", protocol: "BNA"},
    50: {keyword: "ESP", protocol: "Encap Security Payload"},
    51: {keyword: "AH", protocol: "Authentication Header"},
    52: {keyword: "I-NLSP", protocol: "Integrated Net Layer Security  TUBA"},
    53: {keyword: "SWIPE (deprecated)", protocol: "IP with Encryption"},
    54: {keyword: "NARP", protocol: "NBMA Address Resolution Protocol"},
    55: {keyword: "MOBILE", protocol: "IP Mobility"},
    56: {keyword: "TLSP", protocol: "Transport Layer Security Protocol using Kryptonet key management"},
    57: {keyword: "SKIP", protocol: "SKIP"},
    58: {keyword: "IPv6-ICMP", protocol: "ICMP for IPv6"},
    59: {keyword: "IPv6-NoNxt", protocol: "No Next Header for IPv6"},
    60: {keyword: "IPv6-Opts", protocol: "Destination Options for IPv6"},
    61: {keyword: "", protocol: "any host internal protocol"},
    62: {keyword: "CFTP", protocol: "CFTP"},
    63: {keyword: "", protocol: "any local network"},
    64: {keyword: "SAT-EXPAK", protocol: "SATNET and Backroom EXPAK"},
    65: {keyword: "KRYPTOLAN", protocol: "Kryptolan"},
    66: {keyword: "RVD", protocol: "MIT Remote Virtual Disk Protocol"},
    67: {keyword: "IPPC", protocol: "Internet Pluribus Packet Core"},
    68: {keyword: "", protocol: "any distributed file system"},
    69: {keyword: "SAT-MON", protocol: "SATNET Monitoring"},
    70: {keyword: "VISA", protocol: "VISA Protocol"},
    71: {keyword: "IPCV", protocol: "Internet Packet Core Utility"},
    72: {keyword: "CPNX", protocol: "Computer Protocol Network Executive"},
    73: {keyword: "CPHB", protocol: "Computer Protocol Heart Beat"},
    74: {keyword: "WSN", protocol: "Wang Span Network"},
    75: {keyword: "PVP", protocol: "Packet Video Protocol"},
    76: {keyword: "BR-SAT-MON", protocol: "Backroom SATNET Monitoring"},
    77: {keyword: "SUN-ND", protocol: "SUN ND PROTOCOL-Temporary"},
    78: {keyword: "WB-MON", protocol: "WIDEBAND Monitoring"},
    79: {keyword: "WB-EXPAK", protocol: "WIDEBAND EXPAK"},
    80: {keyword: "ISO-IP", protocol: "ISO Internet Protocol"},
    81: {keyword: "VMTP", protocol: "VMTP"},
    82: {keyword: "SECURE-VMTP", protocol: "SECURE-VMTP"},
    83: {keyword: "VINES", protocol: "VINES"},
    84: {keyword: "TTP", protocol: "Transaction Transport Protocol"},
    85: {keyword: "NSFNET-IGP", protocol: "NSFNET-IGP"},
    86: {keyword: "DGP", protocol: "Dissimilar Gateway Protocol"},
    87: {keyword: "TCF", protocol: "TCF"},
    88: {keyword: "EIGRP", protocol: "EIGRP"},
    89: {keyword: "OSPFIGP", protocol: "OSPFIGP"},
    90: {keyword: "Sprite-RPC", protocol: "Sprite RPC Protocol"},
    91: {keyword: "LARP", protocol: "Locus Address Resolution Protocol"},
    92: {keyword: "MTP", protocol: "Multicast Transport Protocol"},
    93: {keyword: "AX.25", protocol: "AX.25 Frames"},
    94: {keyword: "IPIP", protocol: "IP-within-IP Encapsulation Protocol"},
    95: {keyword: "MICP (deprecated)", protocol: "Mobile Internetworking Control Pro."},
    96: {keyword: "SCC-SP", protocol: "Semaphore Communications Sec. Pro."},
    97: {keyword: "ETHERIP", protocol: "Ethernet-within-IP Encapsulation"},
    98: {keyword: "ENCAP", protocol: "Encapsulation Header"},
    99: {keyword: "", protocol: "any private encryption scheme"},
    100: {keyword: "GMTP", protocol: "GMTP"},
    101: {keyword: "IFMP", protocol: "Ipsilon Flow Management Protocol"},
    102: {keyword: "PNNI", protocol: "PNNI over IP"},
    103: {keyword: "PIM", protocol: "Protocol Independent Multicast"},
    104: {keyword: "ARIS", protocol: "ARIS"},
    105: {keyword: "SCPS", protocol: "SCPS"},
    106: {keyword: "QNX", protocol: "QNX"},
    107: {keyword: "A/N", protocol: "Active Networks"},
    108: {keyword: "IPComp", protocol: "IP Payload Compression Protocol"},
    109: {keyword: "SNP", protocol: "Sitara Networks Protocol"},
    110: {keyword: "Compaq-Peer", protocol: "Compaq Peer Protocol"},
    111: {keyword: "IPX-in-IP", protocol: "IPX in IP"},
    112: {keyword: "VRRP", protocol: "Virtual Router Redundancy Protocol"},
    113: {keyword: "PGM", protocol: "PGM Reliable Transport Protocol"},
    114: {keyword: "", protocol: "any 0-hop protocol"},
    115: {keyword: "L2TP", protocol: "Layer Two Tunneling Protocol"},
    116: {keyword: "DDX", protocol: "D-II Data Exchange (DDX)"},
    117: {keyword: "IATP", protocol: "Interactive Agent Transfer Protocol"},
    118: {keyword: "STP", protocol: "Schedule Transfer Protocol"},
    119: {keyword: "SRP", protocol: "SpectraLink Radio Protocol"},
    120: {keyword: "UTI", protocol: "UTI"},
    121: {keyword: "SMP", protocol: "Simple Message Protocol"},
    122: {keyword: "SM (deprecated)", protocol: "Simple Multicast Protocol"},
    123: {keyword: "PTP", protocol: "Performance Transparency Protocol"},
    124: {keyword: "ISIS over IPv4", protocol: ""},
    125: {keyword: "FIRE", protocol: ""},
    126: {keyword: "CRTP", protocol: "Combat Radio Transport Protocol"},
    127: {keyword: "CRUDP", protocol: "Combat Radio User Datagram"},
    128: {keyword: "SSCOPMCE", protocol: ""},
    129: {keyword: "IPLT", protocol: ""},
    130: {keyword: "SPS", protocol: "Secure Packet Shield"},
    131: {keyword: "PIPE", protocol: "Private IP Encapsulation within IP"},
    132: {keyword: "SCTP", protocol: "Stream Control Transmission Protocol"},
    133: {keyword: "FC", protocol: "Fibre Channel"},
    134: {keyword: "RSVP-E2E-IGNORE", protocol: ""},
    135: {keyword: "Mobility Header", protocol: ""},
    136: {keyword: "UDPLite", protocol: ""},
    137: {keyword: "MPLS-in-IP", protocol: ""},
    138: {keyword: "manet", protocol: "MANET Protocols"},
    139: {keyword: "HIP", protocol: "Host Identity Protocol"},
    140: {keyword: "Shim6", protocol: "Shim6 Protocol"},
    141: {keyword: "WESP", protocol: "Wrapped Encapsulating Security Payload"},
    142: {keyword: "ROHC", protocol: "Robust Header Compression"},
    253: {keyword: "", protocol: "Use for experimentation and testing"},
    254: {keyword: "", protocol: "Use for experimentation and testing"},
    255: {keyword: "Reserved", protocol: ""}
};
