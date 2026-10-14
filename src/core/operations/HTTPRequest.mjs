/**
 * @author tlwr [toby@toby.codes]
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— HTTP 请求发送
 * 【操作】HTTP request（this.name 的值）
 * 【功能】按指定 Method / URL / Headers 发起一次真实 HTTP 请求，返回响应正文
 * 【输入】string —— 当 Method 属于 POST/PUT/PATCH/DELETE 等方法时作为请求体(body)；
 *                  GET / HEAD 时忽略该输入
 * 【输出】string —— 响应正文字符串；开启 Show response metadata 时前置一段元信息
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 从 args 解构出 method、url、headersText、mode、showResponseMetadata
 *   2. url 为空则直接返回空串（不发请求）
 *   3. 逐行解析 Headers 文本：按 CRLF/LF 切行、跳过空行、按第一个 ":" 拆成 Key/Value，
 *      写入浏览器 Headers 对象
 *   4. 组装 fetch 配置：method、headers、mode（cors / no-cors）、cache
 *   5. 非 GET 且非 HEAD 时把 input 挂到 config.body
 *   6. fetch 请求；then 中取响应：opaque 空响应报错；
 *      需要元信息时拼接状态行与暴露的首部，否则直接返回 r.text()
 *   7. catch 中把网络异常统一包装为 OperationError，并附常见排查原因
 * ------------------------------------------------------------
 * 【关键算法】← 请求首部的文本切分与请求行组装
 *   - 首部切分：`headersText.split(/\r?\n/)` 同时兼容 CRLF 与 LF 换行；
 *     每行再 `line.split(":")` 按冒号切分，要求切出长度恰为 2，
 *     否则抛错，避免把 Value 中的冒号误当分隔符
 *   - 请求体判定：仅当 method 不属于 {GET, HEAD} 时才设置 config.body，
 *     因为按 RFC 这两个方法不应携带实体主体
 *   - 模式映射：界面选项文案经 modeLookup 查表转换为 fetch 的 mode 取值
 *   - fetch 由浏览器按 Method + headers + body 自动组装出请求行
 *     `METHOD url HTTP/1.1` 与各首部行
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 这是少数使用 `manualBake = true` 的操作：不随输入变化自动重跑，
 *     避免每次编辑输入都真的发一次网络请求
 *   - 采用 Promise 链（.then/.catch）而非 async/await：run() 直接返回 Promise，
 *     由框架等待其 resolve 后取结果
 *   - catch 内 `e.toString()` 把浏览器各类网络异常归并展示并附排查清单
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";

/**
 * HTTP request operation
 *
 * 【说明】继承 Operation 基类。本操作的 run() 是异步的（返回 Promise），
 *         框架会 await 后才拿到字符串结果。
 */
class HTTPRequest extends Operation {

    /**
     * HTTPRequest constructor
     *
     * 【声明元信息】
     *   name       = "HTTP request"
     *   module     = "Default"
     *   inputType  = "string"（作为请求体）
     *   outputType = "string"（响应正文）
     *   manualBake = true（关闭输入变化时的自动重跑）
     * 【参数 args】
     *   [0] Method   —— 选项：GET/POST/HEAD/PUT/PATCH/DELETE/CONNECT/TRACE/OPTIONS，
     *                   决定请求方法，同时决定 input 是否作为 body
     *   [1] URL      —— 目标地址字符串，为空则 run() 直接返回空串
     *   [2] Headers  —— 多行文本，每行形如 "Key: Value"
     *   [3] Mode     —— 选项：Cross-Origin Resource Sharing / No CORS(受限方法)，
     *                   经 modeLookup 映射为 fetch 的 mode
     *   [4] Show response metadata —— 布尔值，是否在正文前附加状态码与暴露的首部
     */
    constructor() {
        super();

        this.name = "HTTP request";
        this.module = "Default";
        this.description = [
            "Makes an HTTP request and returns the response.",
            "<br><br>",
            "This operation supports different HTTP verbs like GET, POST, PUT, etc.",
            "<br><br>",
            "You can add headers line by line in the format <code>Key: Value</code>",
            "<br><br>",
            "The status code of the response, along with a limited selection of exposed headers, can be viewed by checking the 'Show response metadata' option. Only a limited set of response headers are exposed by the browser for security reasons.",
        ].join("\n");
        this.infoURL = "https://wikipedia.org/wiki/List_of_HTTP_header_fields#Request_fields";
        this.inputType = "string";
        this.outputType = "string";
        this.manualBake = true;
        this.args = [
            {
                "name": "Method",
                "type": "option",
                "value": [
                    "GET", "POST", "HEAD",
                    "PUT", "PATCH", "DELETE",
                    "CONNECT", "TRACE", "OPTIONS"
                ]
            },
            {
                "name": "URL",
                "type": "string",
                "value": ""
            },
            {
                "name": "Headers",
                "type": "text",
                "value": ""
            },
            {
                "name": "Mode",
                "type": "option",
                "value": [
                    "Cross-Origin Resource Sharing",
                    "No CORS (limited to HEAD, GET or POST)",
                ]
            },
            {
                "name": "Show response metadata",
                "type": "boolean",
                "value": false
            }
        ];
    }

    /**
     * 【主流程】解析参数并发起 HTTP 请求
     *
     * 参数来自构造函数声明的 5 个 args（Method / URL / Headers / Mode / Show response metadata）。
     * 返回值是一个 Promise<string>：框架 await 后得到响应正文（可含元信息前缀）。
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        // --- 步骤 1：解构参数 ---
        const [method, url, headersText, mode, showResponseMetadata] = args;

        // --- 步骤 2：URL 为空则短路，直接返回空串 ---
        if (url.length === 0) return "";

        // --- 步骤 3：逐行解析 Headers 文本，写入 Headers 对象 ---
        const headers = new Headers();
        headersText.split(/\r?\n/).forEach(line => {
            line = line.trim();

            if (line.length === 0) return;

            const split = line.split(":");
            if (split.length !== 2) throw `Could not parse header in line: ${line}`;

            headers.set(split[0].trim(), split[1].trim());
        });

        // --- 步骤 4：组装 fetch 配置（mode 经查表映射为 cors / no-cors） ---
        const config = {
            method: method,
            headers: headers,
            mode: modeLookup[mode],
            cache: "no-cache",
        };

        // --- 步骤 5：仅非 GET / HEAD 方法才把输入作为请求体 ---
        if (method !== "GET" && method !== "HEAD") {
            config.body = input;
        }

        // --- 步骤 6：发起请求，异步处理响应与异常 ---
        return fetch(url, config)
            .then(r => {
                if (r.status === 0 && r.type === "opaque") {
                    throw new OperationError("Error: Null response. Try setting the connection mode to CORS.");
                }

                if (showResponseMetadata) {
                    let headers = "";
                    for (const pair of r.headers.entries()) {
                        headers += "    " + pair[0] + ": " + pair[1] + "\n";
                    }
                    return r.text().then(b => {
                        return "####\n  Status: " + r.status + " " + r.statusText +
                            "\n  Exposed headers:\n" + headers + "####\n\n" + b;
                    });
                }
                return r.text();
            })
            .catch(e => {
                throw new OperationError(e.toString() +
                    "\n\nThis error could be caused by one of the following:\n" +
                    " - An invalid URL\n" +
                    " - Making a request to an insecure resource (HTTP) from a secure source (HTTPS)\n" +
                    " - Making a cross-origin request to a server which does not support CORS\n");
            });
    }

}


/**
 * Lookup table for HTTP modes
 *
 * 【说明】把界面上 "Mode" 的中文/英文选项文案映射为浏览器 fetch 的 mode 取值：
 *   "Cross-Origin Resource Sharing"               → "cors"   （允许跨域读响应）
 *   "No CORS (limited to HEAD, GET or POST)"      → "no-cors"（不透明响应，方法受限）
 *
 * @private
 */
const modeLookup = {
    "Cross-Origin Resource Sharing": "cors",
    "No CORS (limited to HEAD, GET or POST)": "no-cors",
};


export default HTTPRequest;
