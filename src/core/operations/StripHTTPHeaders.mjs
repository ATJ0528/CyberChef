/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— HTTP 首部剥离
 * 【操作】Strip HTTP headers（this.name 的值）
 * 【功能】去掉 HTTP 请求/响应报文的首部，只保留消息正文
 * 【输入】string —— 完整 HTTP 报文（起始行 CRLF 首部字段… CRLF CRLF 正文）
 * 【输出】string —— 空行之后的正文部分；找不到分界则原样返回
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 在输入中查找 CRLF 双换行 "\r\n\r\n"（首部块与正文的分界）
 *   2. 若未找到，回退查找 LF 双换行 "\n\n"，正文起点为其后 2 个字符
 *   3. 命中分界则返回其后内容；两种均未命中（headerEnd < 2）则原样返回输入
 * ------------------------------------------------------------
 * 【关键算法】← 首部块与正文的边界（空行）定位
 *   - HTTP 报文格式：`起始行 CRLF 首部字段 CRLF 首部字段 CRLF … CRLF 正文`，
 *     首部与正文之间的**空行**（即连续两个 CRLF）是唯一可靠的边界标记
 *   - headerEnd 语义为「正文起始下标」：
 *     CRLF 情形 = indexOf("\r\n\r\n") + 4（四个字符全跳过）
 *     LF   情形 = indexOf("\n\n") + 2（两个字符全跳过）
 *   - 兜底判定 `headerEnd < 2`：当两种换行都未命中时，
 *     CRLF 分支的 -1+4 会被 LF 分支覆盖，最终残留值恒为 -1+2=1，
 *     故 < 2 即为“无分界可切”，此时原样返回输入，避免误切
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 同时兼容 CRLF 与 LF，无须先归一化换行即可处理不同平台的抓包文本
 *   - checks 用正则 "^HTTP(.|\\s)+?(\\r?\\n){2}" 侦测以 "HTTP" 起始且含空行的响应
 * ============================================================
 */

import Operation from "../Operation.mjs";

/**
 * Strip HTTP headers operation
 *
 * 【说明】以空行为界，丢弃首部块，返回消息正文。
 */
class StripHTTPHeaders extends Operation {

    /**
     * StripHTTPHeaders constructor
     *
     * 【声明元信息】
     *   name       = "Strip HTTP headers"
     *   module     = "Default"
     *   inputType  = "string"（完整 HTTP 报文文本）
     *   outputType = "string"（剥离首部后的正文）
     * 【参数 args】无（this.args = []）
     * 【自动侦测】this.checks 用正则 "^HTTP(.|\\s)+?(\\r?\\n){2}" 识别响应报文
     */
    constructor() {
        super();

        this.name = "Strip HTTP headers";
        this.module = "Default";
        this.description = "Removes HTTP headers from a request or response by looking for the first instance of a double newline.";
        this.infoURL = "https://wikipedia.org/wiki/Hypertext_Transfer_Protocol#Message_format";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [];
        this.checks = [
            {
                pattern:  "^HTTP(.|\\s)+?(\\r?\\n){2}",
                flags:  "",
                args:   []
            }
        ];
    }

    /**
     * 【主流程】按空行定位首部/正文分界，返回正文
     *
     * 无参数（args 恒为空）。
     * headerEnd 保存正文起始下标；无法定位时原样返回输入。
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        // --- 步骤 1：优先按 CRLF 双换行定位分界，正文起点 = 下标 + 4 ---
        let headerEnd = input.indexOf("\r\n\r\n");

        // --- 步骤 2：未找到 CRLF 则回退 LF 双换行，正文起点 = 下标 + 2 ---
        headerEnd = (headerEnd < 0) ? input.indexOf("\n\n") + 2 : headerEnd + 4;

        // --- 步骤 3：找到分界则切出正文，否则（headerEnd < 2）原样返回 ---
        return (headerEnd < 2) ? input : input.slice(headerEnd, input.length);
    }

}

export default StripHTTPHeaders;
