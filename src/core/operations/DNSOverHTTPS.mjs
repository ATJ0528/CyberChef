/**
 * @author h345983745
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— DNS over HTTPS 查询
 * 【操作】DNS over HTTPS
 * 【功能】对单个域名发起 DNS over HTTPS(DoH) 查询，取回解析器返回的 JSON
 * 【输入】string —— 单个域名（如 "example.com"）
 * 【输出】JSON —— 解析器返回的完整 DoH JSON；若勾选仅要答案则为数据数组
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 用 new URL(resolver) 解析解析器地址，非法地址抛 OperationError
 *   2. 构造 GET 查询参数对象 {name, type, cd}，再用 URLSearchParams 序列化
 *   3. 发起 fetch 请求，请求头 accept: application/dns-json 要求 JSON 响应
 *   4. response.json() 得到 DoH JSON 报文
 *   5. 若勾选 "Answer Data Only" 则调用 extractData() 只取 Answer[].data
 *   6. 网络或解析异常统一包装为 OperationError 抛出
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 本操作不自造 DNS 二进制报文，而是构造 HTTP GET 查询串并消费
 *     解析器（Google/Cloudflare）返回的 DoH JSON，属"构造请求 + 解析 JSON"
 *   - 查询参数：name = 域名，type = 记录类型（A/AAAA/MX…），
 *     cd = Checking Disabled，即是否禁用 DNSSEC 校验
 *   - DoH JSON 结构大致为：
 *     { Status, TC, RD, RA, AD, CD,
 *       Question: [{name, type}],
 *       Answer:   [{name, type, TTL, data}], ... }
 *   - extractData() 遍历 Answer 数组抽取每条记录的 data 字段组成纯值数组；
 *     Answer 为 undefined 时返回空数组
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - manualBake = true：此操作会发起外部网络请求，框架不自动执行，
 *     需用户手动点击 Bake，避免输入过程中被反复触发联网
 *   - Resolver 用 editableOption，可选用内置 Google/Cloudflare，
 *     也可填任何支持 GET 参数 name/type 的自定义 DoH 服务地址
 *   - 用 URL.search = new URLSearchParams(params) 拼接查询串，
 *     由平台负责百分号编码，避免手工拼串带来的转义/注入问题
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";

/**
 * DNS over HTTPS operation
 *
 * 继承自 Operation 基类，只需实现 run()（本例返回 Promise）；构造函数
 * 负责声明元信息。run() 之外的 extractData() 是本文件内的模块级私有函数。
 */
class DNSOverHTTPS extends Operation {

    /**
     * DNSOverHTTPS constructor
     *
     * inputType  = "string"，输入是单个域名文本
     * outputType = "JSON"  ，run() 返回的结果按 JSON 呈现（可折叠查看）
     * manualBake = true    ，标记为需手动触发（因涉及网络请求）
     * args 各参数含义：
     *   [0] Resolver            —— editableOption，解析器地址，内置 Google / Cloudflare
     *   [1] Request Type        —— option，DNS 记录类型（A/AAAA/MX/NS…/ANY）
     *   [2] Answer Data Only    —— boolean，仅返回 Answer 段的 data 值数组
     *   [3] Disable DNSSEC validation —— boolean，映射为查询参数 cd（禁用校验）
     */
    constructor() {
        super();

        this.name = "DNS over HTTPS";
        this.module = "Default";
        this.description = [
            "Takes a single domain name and performs a DNS lookup using DNS over HTTPS.",
            "<br><br>",
            "By default, <a href='https://developers.cloudflare.com/1.1.1.1/dns-over-https/'>Cloudflare</a> and <a href='https://developers.google.com/speed/public-dns/docs/dns-over-https'>Google</a> DNS over HTTPS services are supported.",
            "<br><br>",
            "Can be used with any service that supports the GET parameters <code>name</code> and <code>type</code>."
        ].join("\n");
        this.infoURL = "https://wikipedia.org/wiki/DNS_over_HTTPS";
        this.inputType = "string";
        this.outputType = "JSON";
        this.manualBake = true;
        this.args = [
            {
                name: "Resolver",
                type: "editableOption",
                value: [
                    {
                        name: "Google",
                        value: "https://dns.google.com/resolve"
                    },
                    {
                        name: "Cloudflare",
                        value: "https://cloudflare-dns.com/dns-query"
                    }
                ]
            },
            {
                name: "Request Type",
                type: "option",
                value: [
                    "A",
                    "AAAA",
                    "ANAME",
                    "CERT",
                    "CNAME",
                    "DNSKEY",
                    "HTTPS",
                    "IPSECKEY",
                    "LOC",
                    "MX",
                    "NS",
                    "OPENPGPKEY",
                    "PTR",
                    "RRSIG",
                    "SIG",
                    "SOA",
                    "SPF",
                    "SRV",
                    "SSHFP",
                    "TA",
                    "TXT",
                    "URI",
                    "ANY"
                ]
            },
            {
                name: "Answer Data Only",
                type: "boolean",
                value: false
            },
            {
                name: "Disable DNSSEC validation",
                type: "boolean",
                value: false
            }
        ];
    }

    /**
     * 【主流程】发起 DoH 查询并返回解析结果
     *
     * 参数解构自 args：resolver = 解析器地址，requestType = 记录类型，
     * justAnswer = 是否仅返回答案数据，DNSSEC = 是否禁用 DNSSEC 校验
     * 返回值：一个 Promise，resolve 为 DoH JSON 对象或答案数据数组
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {JSON}
     */
    run(input, args) {
        const [resolver, requestType, justAnswer, DNSSEC] = args;
        // --- 步骤 1：解析解析器地址，非法 URL 直接抛 OperationError ---
        let url = URL;
        try {
            url = new URL(resolver);
        } catch (error) {
            throw new OperationError(error.toString() +
            "\n\nThis error could be caused by one of the following:\n" +
            " - An invalid Resolver URL\n");
        }
        // --- 步骤 2：构造 GET 查询参数并序列化挂到 url.search 上 ---
        const params = {name: input, type: requestType, cd: DNSSEC};

        url.search = new URLSearchParams(params);

        // --- 步骤 3+4：fetch 请求 → 响应 JSON 化 → 按参数决定返回内容 ---
        return fetch(url, {headers: {"accept": "application/dns-json"}}).then(response => {
            return response.json();
        }).then(data => {
            // --- 步骤 5：勾选仅要答案时，从 Answer 段抽取 data 值数组 ---
            if (justAnswer) {
                return extractData(data.Answer);
            }
            return data;
        }).catch(e => {
            // --- 步骤 6：网络/解析异常统一包装为 OperationError ---
            throw new OperationError(`Error making request to ${url}\n${e.toString()}`);
        });

    }
}

/**
 * Construct an array of just data from a DNS Answer section
 *
 * 【私有辅助】把 DoH JSON 的 Answer 段压缩为纯数据数组
 * 输入：data = Answer 数组（每项形如 {name, type, TTL, data}）
 * 返回：由各记录 data 字段组成的新数组；data 为 undefined 时返回 []
 * 算法要点：遍历 Answer，仅保留 data 值，丢弃 name/type/TTL 等元信息，
 * 使输出更适合直接作为下游操作的输入
 *
 * @private
 * @param {JSON} data
 * @returns {JSON}
 */
function extractData(data) {
    if (typeof(data) == "undefined") {
        return [];
    } else {
        const dataValues = [];
        data.forEach(element => {
            dataValues.push(element.data);
        });
        return dataValues;
    }
}

export default DNSOverHTTPS;
