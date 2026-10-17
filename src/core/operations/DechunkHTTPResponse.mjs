/**
 * @author sevzero [sevzero@protonmail.com]
 * @copyright Crown Copyright 2018
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— HTTP 分块传输解码
 * 【操作】Dechunk HTTP response（this.name 的值）
 * 【功能】把 Transfer-Encoding: chunked 的分块响应体还原为原始正文
 * 【输入】string —— 形如 "5\r\nhello\r\n0\r\n\r\n" 的分块编码文本
 * 【输出】string —— 各数据块拼接后的明文正文（不含块头与 CRLF）
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 找第一行（块大小行）的行尾，判定换行为 CRLF 还是 LF
 *   2. 解析块大小为十六进制数 → chunkSize
 *   3. 循环：chunkSize 为 0（终止块）则退出；否则截取该块数据压入 chunks，
 *      跳过数据与其后的行尾换行，读下一行块大小
 *   4. 各块 join("") 后返回
 * ------------------------------------------------------------
 * 【关键算法】← chunked 分块状态机（重点）
 *   - 分块格式：`长度(十六进制)CRLF 数据 CRLF 长度 CRLF 数据 CRLF … 0 CRLF CRLF [trailer]`
 *   - 状态推进由“读块头行 → 截数据 → 跳过行尾 CRLF”三步循环构成：
 *     chunkSizeEnd 始终指向当前块头行的行尾（indexOf 换行 + 换行长度）；
 *     `input.slice(chunkSizeEnd, chunkSize + chunkSizeEnd)` 取数据；
 *     随后 `input = input.slice(chunkSizeEnd + chunkSize + lineEndingsLength)`
 *     把已消费部分整体左移丢弃，读取位置自然前移
 *   - 终止条件：块大小解析为 0 时 break，块体后仅剩的最后一个 CRLF
 *     及其后的 trailer 首部（若有）本实现不再处理，直接丢弃
 *   - 换行风格自适应：以块头行倒数第二个字符是否为 "\r" 判定 "\r\n" / "\n"，
 *     用 lineEndingsLength 跳过数据尾部换行
 *   - 容错：parseInt 解析失败得到 NaN，while 条件 `!isNaN(chunkSize)` 自然退出，
 *     畸形输入不会死循环
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - args 为空：本操作无需任何参数
 *   - checks 提供正则 "^[0-9A-F]+\r\n"（忽略大小写），
 *     供框架“自动侦测”判断输入是否像分块响应
 * ============================================================
 */

import Operation from "../Operation.mjs";

/**
 * Dechunk HTTP response operation
 *
 * 【说明】解码 HTTP/1.1 的 chunked 传输编码，还原消息正文。
 */
class DechunkHTTPResponse extends Operation {

    /**
     * DechunkHTTPResponse constructor
     *
     * 【声明元信息】
     *   name       = "Dechunk HTTP response"
     *   module     = "Default"
     *   inputType  = "string"（分块编码文本）
     *   outputType = "string"（解码后的正文）
     * 【参数 args】无（this.args = []）
     * 【自动侦测】this.checks 用正则匹配分块起始行（十六进制长度 + CRLF），
     *             辅助 CyberChef 判定输入类型
     */
    constructor() {
        super();

        this.name = "Dechunk HTTP response";
        this.module = "Default";
        this.description = "Parses an HTTP response transferred using Transfer-Encoding: Chunked";
        this.infoURL = "https://wikipedia.org/wiki/Chunked_transfer_encoding";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [];
        this.checks = [
            {
                pattern:  "^[0-9A-F]+\r\n",
                flags:  "i",
                args:   []
            }
        ];
    }

    /**
     * 【主流程】chunked 分块状态机，逐块取出数据并拼接
     *
     * 无参数（args 恒为空）。返回各数据块拼接后的正文字符串。
     * 状态变量：chunkSizeEnd（当前块头行尾下标）、lineEndings（换行风格）、
     *           chunkSize（当前块数据字节数，NaN 表示解析失败/结束）。
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const chunks = [];

        // --- 步骤 1：定位首个块头行尾，并以倒数第二字符判定 CRLF / LF 换行风格 ---
        let chunkSizeEnd = input.indexOf("\n") + 1;
        const lineEndings = input.charAt(chunkSizeEnd - 2) === "\r" ? "\r\n" : "\n";
        const lineEndingsLength = lineEndings.length;

        // --- 步骤 2：解析首个块大小（十六进制）；解析失败得 NaN 即结束 ---
        let chunkSize = parseInt(input.slice(0, chunkSizeEnd), 16);

        // --- 步骤 3：循环取块，遇大小为 0 的终止块退出 ---
        while (!isNaN(chunkSize)) {
            if (chunkSize === 0) {
                break;
            }
            // 截取本块数据；再把已消费的「块头行 + 数据 + 行尾 CRLF」整体丢弃
            chunks.push(input.slice(chunkSizeEnd, chunkSize + chunkSizeEnd));
            input = input.slice(chunkSizeEnd + chunkSize + lineEndingsLength);
            // 前进到下一块头行尾并解析其块大小
            chunkSizeEnd = input.indexOf(lineEndings) + lineEndingsLength;
            chunkSize = parseInt(input.slice(0, chunkSizeEnd), 16);
        }
        return chunks.join("");
    }

}

export default DechunkHTTPResponse;
