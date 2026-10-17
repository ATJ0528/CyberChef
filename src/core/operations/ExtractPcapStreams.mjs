/**
 * @author ATJ0528
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Utils from "../Utils.mjs";
import {parsePcap} from "../lib/Pcap.mjs";
import {dissectCapture} from "../lib/PcapPacket.mjs";
import {analysePcap} from "../lib/PcapSession.mjs";

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 提取抓包中的应用层数据
 * 【操作】Extract PCAP streams
 * 【功能】把抓包里的 TCP 流与 UDP 流重组成完整的应用层数据，输出为文本
 * 【输入】ArrayBuffer —— 抓包文件原始字节
 * 【输出】string —— 重组后的应用层载荷（可按需附上流标注）
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 解析容器 → 逐包解包 → 流重组 → 会话归并（复用 PcapSession 的完整链路）
 *   2. 按"提取对象"筛选：仅 TCP 流 / 仅 UDP 流 / 两者
 *   3. 按"方向"筛选：客户端到服务端 / 服务端到客户端 / 双向
 *   4. 按流序号挑出目标流（-1 表示全部）
 *   5. 解码成字符串并按分隔符拼接
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 本操作不自己实现重组，而是完全依赖 PcapSession 给出的会话对象。
 *     会话对象里已经缓存了 reassembled 双向载荷，因此这里只是"取用 + 筛选
 *     + 拼接"。把重组算法留在库里、把取用策略留在操作里，是为了让同一个
 *     重组结果能被多个操作复用（Parse PCAP 的会话识别用的也是它）。
 *   - 字节到字符串用 Latin-1 语义（byteArrayToChars）而非 UTF-8 解码。
 *     原因是抓包载荷可能是任意编码，用 UTF-8 解码遇到非法字节序列会插入
 *     替换字符并破坏原始字节。Latin-1 是逐字节双射，不会丢信息——这是
 *     二进制数据穿越字符串通道时唯一安全的选择。需要 UTF-8 时应后续接
 *     一个 "Decode text" 操作显式转换。
 *   - 方向过滤是在会话已经完成重组的载荷上做的切片，而不是在包级别过滤。
 *     这一点很重要：先过滤包再重组，会因丢包导致序列号空洞、重组失败；
 *     先重组再切片，结果始终完整。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 标注行（--- Stream N ... ---）默认开启，但可以关掉。关掉后输出就是
 *     纯净的载荷，可以直接喂给下游操作；开着则便于人眼阅读。把选择权交给
 *     用户，而不是替他决定。
 *   - 流序号越界时不做静默忽略，而是返回空结果——静默忽略会让人误以为
 *     那条流没有数据。
 * ============================================================
 */

/** 分隔符选项名 → 实际字符串 */
const DELIMITERS = {
    "Double newline": "\n\n",
    "Newline": "\n",
    "CRLF": "\r\n",
    "None": "",
};

/**
 * Extract PCAP streams operation
 */
class ExtractPcapStreams extends Operation {

    /**
     * 构造函数 —— 声明元信息与参数。
     */
    constructor() {
        super();

        this.name = "Extract PCAP streams";
        this.module = "Default";
        this.description = "Reassembles TCP streams and groups UDP flows within a capture file, " +
            "then extracts the application-layer payload in the chosen direction. " +
            "Useful for pulling HTTP requests, DNS queries or other application data out of a capture.";
        this.infoURL = "https://wikipedia.org/wiki/Pcap";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [
            {
                name: "Extract from",
                type: "option",
                value: ["TCP streams", "UDP flows", "Both"],
            },
            {
                name: "Direction",
                type: "option",
                value: ["Client to server", "Server to client", "Both"],
            },
            {
                name: "Stream index",
                type: "number",
                value: -1,
                min: -1,
                hint: "-1 means all streams, 0 is the first stream.",
            },
            {
                name: "Include annotations",
                type: "boolean",
                value: true,
            },
            {
                name: "Delimiter",
                type: "option",
                value: ["Double newline", "Newline", "CRLF", "None"],
            },
        ];
    }

    /**
     * 【主流程】提取应用层数据
     *
     * @param {ArrayBuffer} input - 抓包文件原始字节
     * @param {Object[]} args - [extractFrom, direction, streamIndex, includeAnnotations, delimiter]
     * @returns {string} 重组出的应用层载荷
     */
    run(input, args) {
        const [extractFrom, direction, streamIndex, includeAnnotations, delimiterName] = args;

        // --- 步骤 1：输入校验 ---
        if (!input || input.byteLength === 0) {
            throw new OperationError("No input data. Drop a .pcap or .pcapng capture file into the input.");
        }

        const bytes = new Uint8Array(input);

        let capture;
        try {
            capture = parsePcap(bytes);
        } catch (err) {
            throw new OperationError(`Not a valid capture file: ${err.message}`);
        }

        // --- 步骤 2：走完整的解析 → 解包 → 重组 → 归并链路 ---
        const analysis = analysePcap(capture, {dissectCapture});

        // --- 步骤 3：按传输层筛选 ---
        let conversations = analysis.conversations;
        if (extractFrom === "TCP streams") {
            conversations = conversations.filter((c) => c.transportProtocol === "TCP");
        } else if (extractFrom === "UDP flows") {
            conversations = conversations.filter((c) => c.transportProtocol === "UDP");
        }

        // --- 步骤 4：按流序号挑选。序号是在筛选后的列表上计的，与界面显示一致 ---
        if (streamIndex >= 0) {
            if (streamIndex >= conversations.length) {
                // 越界就返回空，而不是悄悄给出一条不相干的流
                return "";
            }
            conversations = [conversations[streamIndex]];
        }

        // --- 步骤 5：逐条流取出载荷并解码 ---
        const delim = Object.prototype.hasOwnProperty.call(DELIMITERS, delimiterName) ?
            DELIMITERS[delimiterName] :
            "\n\n";

        const parts = [];

        conversations.forEach((conv, i) => {
            const payloads = conv.reassembled || {aToB: new Uint8Array(0), bToA: new Uint8Array(0)};

            // a→b 不一定就是「客户端到服务端」：a/b 只是规范排序。
            // 先问会话谁是客户端，再把两个方向的载荷对号入座。
            const clientIsA = conv.clientSide === "a";
            const c2s = clientIsA ? payloads.aToB : payloads.bToA;
            const s2c = clientIsA ? payloads.bToA : payloads.aToB;

            // 方向 → 要取哪些载荷。
            // 标注里的箭头用 ASCII 的 "->"：本操作的返回值最终会被当成字节序列
            // 输出，非 ASCII 字符（如 U+2192）在字节化时会被截断成乱码。
            const wanted = [];
            if (direction === "Client to server" || direction === "Both") {
                wanted.push({label: "client -> server", data: c2s});
            }
            if (direction === "Server to client" || direction === "Both") {
                wanted.push({label: "server -> client", data: s2c});
            }

            for (const w of wanted) {
                if (!w.data || w.data.length === 0) continue;

                if (includeAnnotations) {
                    parts.push(
                        `--- Stream ${i + 1} [${conv.transportProtocol}/${conv.app.protocol}] ` +
                        `${conv.client.ip}:${conv.client.port} ` +
                        `${conv.server.ip}:${conv.server.port} ` +
                        `(${w.label}, ${w.data.length} bytes) ---`
                    );
                }

                // Latin-1 逐字节映射，不做 UTF-8 解码，理由见文件头【关键算法】第 2 条
                parts.push(Utils.byteArrayToChars(w.data));
            }
        });

        return parts.join(delim);
    }
}

export default ExtractPcapStreams;
