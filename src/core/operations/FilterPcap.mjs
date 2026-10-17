/**
 * @author ATJ0528
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import {parsePcap, writePcap, writePcapng} from "../lib/Pcap.mjs";
import {dissectCapture} from "../lib/PcapPacket.mjs";
import {analysePcap, APP_PROTOCOL} from "../lib/PcapSession.mjs";

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 按条件过滤抓包
 * 【操作】Filter PCAP
 * 【功能】用一个类 BPF 的过滤表达式筛选包，并重新生成一个抓包文件
 * 【输入】ArrayBuffer —— 抓包文件原始字节
 * 【输出】ArrayBuffer —— 过滤后的抓包文件（Wireshark 可直接打开）
 * ------------------------------------------------------------
 * 【过滤语法】
 *   协议关键字（单独成条件）：
 *     tcp  udp  icmp  ip  ipv6  arp
 *     http  tls  ssh  dns  smtp  ftp  pop3  imap  redis  quic  mdns
 *   字段比较：
 *     ip.src == 192.168.1.10      ip.dst != 10.0.0.1
 *     ip.addr == 8.8.8.8          （源或目的任一匹配）
 *     port == 80                  （源或目的任一匹配）
 *     tcp.port == 443    udp.port == 53
 *     tcp.srcport > 1024         udp.dstport == 5353
 *     len > 100          len <= 64        （len 是整个帧的字节数）
 *     payload > 100                        （只算应用层载荷）
 *     tcp.flags.syn == 1         tcp.flags.rst == 0
 *     eth.src == 00:11:22:33:44:55
 *   逻辑运算：
 *     and / &&   or / ||   not / !     以及括号 ( )
 *   示例：
 *     tcp and port == 80 and len > 100
 *     http or dns
 *     ip.addr == 192.168.1.10 and not tcp.flags.ack == 1
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 解析容器 → 逐包解包 → 会话归并（应用层协议在此回填到每个包上）
 *   2. 词法分析：把表达式切成词元序列
 *   3. 语法分析：递归下降，构造语法树
 *   4. 求值：对每个包用语法树求布尔值，保留为真的包
 *   5. 按原始抓包中对应的包重新写出文件
 * ------------------------------------------------------------
 * 【关键算法】
 *   1. 表达式求值采用"先整包归并、再逐包过滤"的顺序。应用层协议（http/tls）
 *      只有看完整条流才能判定，所以必须先做流重组与会话识别，把结论回填到
 *      包上，逐包过滤才可能按 http 这类条件筛。
 *   2. 字段解析对"双向字段"返回候选数组而非单值：ip.addr 与 port 天然对应
 *      源和目的两个值。求值时对数组用 some() 语义（任一命中即真），这样
 *      `port == 80` 才能同时匹配请求与响应两个方向——这也正是 BPF 的行为。
 *   3. 递归下降按优先级分层：or → and → not → primary。把优先级体现为函数
 *      调用层级，而不是在求值阶段处理，可以保证 `a or b and c` 被正确解析为
 *      `a or (b and c)`。手写解析器最容易出的错就是优先级搞反。
 *   4. 数值比较与字符串比较分流：len / port 等字段按数值比，IP 与 MAC
 *      按字符串比。若统一按字符串比，`len > 9` 会把长度 100 判为假
 *      （"100" < "9" 字典序成立）——这是个很隐蔽的坑。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 解析错误带上出错位置与词元内容，而不是抛一句"语法错误"。
 *     用户写过滤表达式时最需要知道的就是"我写到哪儿不对了"。
 *   - 词法分析把 IP、IPv6、MAC、字段名统一按"词"处理，靠后续的字段解析
 *     区分语义。否则光是 `:` 与 `.` 的组合就要写三四条词法规则，且 IPv6
 *     地址（含双冒号缩写）几乎无法用简单规则覆盖。
 *   - 过滤结果为空不算错误，返回零包抓包并附警告，让用户能区分
 *     "表达式写错了"和"确实没有匹配的包"。
 * ============================================================
 */

/** 支持的比较运算符 */
const COMPARISON_OPS = ["==", "!=", ">", "<", ">=", "<="];

/** 数值型比较运算符（其余按字符串比较） */
const NUMERIC_OPS = [">", "<", ">=", "<="];

/**
 * 协议关键字 → 判定函数。
 *
 * 每个函数接收 {pkt, capture} 形式的求值上下文，返回布尔值。
 */
const KEYWORD_TESTS = {
    tcp: (ctx) => !!(ctx.pkt.transport && ctx.pkt.transport.protocol === "TCP"),
    udp: (ctx) => !!(ctx.pkt.transport && ctx.pkt.transport.protocol === "UDP"),
    icmp: (ctx) => !!(ctx.pkt.transport &&
        (ctx.pkt.transport.protocol === "ICMP" || ctx.pkt.transport.protocol === "ICMPv6")),
    ip: (ctx) => !!(ctx.pkt.network && ctx.pkt.network.version === 4),
    ipv6: (ctx) => !!(ctx.pkt.network && ctx.pkt.network.version === 6),
    arp: (ctx) => !!(ctx.pkt.link && ctx.pkt.link.etherType === 0x0806),
    vlan: (ctx) => !!(ctx.pkt.link && ctx.pkt.link.vlan && ctx.pkt.link.vlan.length > 0),
    truncated: (ctx) => !!ctx.pkt.truncated,

    // 应用层关键字：直接比对会话识别结果
    http: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.HTTP,
    tls: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.TLS,
    ssh: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.SSH,
    dns: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.DNS,
    smtp: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.SMTP,
    ftp: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.FTP,
    pop3: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.POP3,
    imap: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.IMAP,
    redis: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.REDIS,
    quic: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.QUIC,
    mdns: (ctx) => ctx.pkt.appProtocol === APP_PROTOCOL.MDNS,
};

/**
 * 词法分析：把表达式拆成词元序列。
 *
 * 词元的形态刻意保持精简——只区分「词」「运算符」「括号」三类。
 * IP、MAC、字段名统统是"词"，语义留给语法分析阶段按名字解释，
 * 理由见文件头【开发技巧】第 2 条。
 *
 * @param {string} expr - 过滤表达式
 * @returns {Object[]} 词元数组，形如 {t: "word"|"op"|"paren", v: string}
 * @throws {Error} 遇到无法识别的字符
 */
function tokenize(expr) {
    const tokens = [];
    let i = 0;

    // 词字符包含点、冒号、连字符，这样 IP / IPv6 / MAC / 字段名都能整体成一个词
    const isWordChar = (c) => /[A-Za-z0-9_.:-]/.test(c);

    while (i < expr.length) {
        const c = expr[i];

        if (/\s/.test(c)) {
            i++;
            continue;
        }

        if (c === "(" || c === ")") {
            tokens.push({t: "paren", v: c});
            i++;
            continue;
        }

        // 双字符运算符必须先于单字符判断，否则 "==" 会被切成两个 "="
        const two = expr.slice(i, i + 2);
        if (["&&", "||", "==", "!=", ">=", "<="].includes(two)) {
            tokens.push({t: "op", v: two});
            i += 2;
            continue;
        }

        if (">" === c || "<" === c) {
            tokens.push({t: "op", v: c});
            i++;
            continue;
        }

        if (c === "!") {
            tokens.push({t: "op", v: "!"});
            i++;
            continue;
        }

        if (isWordChar(c)) {
            let j = i;
            while (j < expr.length && isWordChar(expr[j])) j++;
            tokens.push({t: "word", v: expr.slice(i, j)});
            i = j;
            continue;
        }

        throw new Error(`Unexpected character "${c}" at position ${i}`);
    }

    return tokens;
}

/**
 * 语法分析：词元序列 → 语法树。
 *
 * 采用递归下降。层级从低到高为 or → and → not → primary，
 * 与运算符优先级一致，理由见文件头【关键算法】第 3 条。
 *
 * @param {Object[]} tokens - tokenize() 的输出
 * @returns {Object} 语法树根节点
 * @throws {Error} 语法错误
 */
function parse(tokens) {
    let pos = 0;

    /** 取当前词元但不前进 */
    const peek = () => tokens[pos];
    /** 取当前词元并前进 */
    const next = () => tokens[pos++];

    /** 是否轮到逻辑"或"运算符 */
    const isOr = () => {
        const t = peek();
        return t && ((t.t === "op" && t.v === "||") || (t.t === "word" && t.v === "or"));
    };

    /** 是否轮到逻辑"与"运算符 */
    const isAnd = () => {
        const t = peek();
        return t && ((t.t === "op" && t.v === "&&") || (t.t === "word" && t.v === "and"));
    };

    /** 是否轮到逻辑"非" */
    const isNot = () => {
        const t = peek();
        return t && ((t.t === "op" && t.v === "!") || (t.t === "word" && t.v === "not"));
    };

    /** orExpr := andExpr (('or'|'||') andExpr)* */
    function parseOr() {
        let left = parseAnd();
        while (isOr()) {
            next();
            const right = parseAnd();
            left = {type: "or", left, right};
        }
        return left;
    }

    /** andExpr := notExpr (('and'|'&&') notExpr)* */
    function parseAnd() {
        let left = parseNot();
        while (isAnd()) {
            next();
            const right = parseNot();
            left = {type: "and", left, right};
        }
        return left;
    }

    /** notExpr := ('not'|'!') notExpr | primary */
    function parseNot() {
        if (isNot()) {
            next();
            return {type: "not", expr: parseNot()};
        }
        return parsePrimary();
    }

    /** primary := '(' orExpr ')' | comparison | keyword */
    function parsePrimary() {
        const t = peek();
        if (!t) throw new Error("Unexpected end of expression.");

        if (t.t === "paren" && t.v === "(") {
            next();
            const inner = parseOr();
            const closing = next();
            if (!closing || closing.t !== "paren" || closing.v !== ")") {
                throw new Error("Missing closing parenthesis.");
            }
            return inner;
        }

        if (t.t !== "word") {
            throw new Error(`Expected a field name or protocol, got "${t.v}".`);
        }

        const word = next().v;

        // 后面跟着比较运算符 → 这是一次字段比较
        const opTok = peek();
        if (opTok && opTok.t === "op" && COMPARISON_OPS.includes(opTok.v)) {
            next();
            const valueTok = peek();
            if (!valueTok || valueTok.t === "paren") {
                throw new Error(`Expected a value after "${opTok.v}" for field "${word}".`);
            }
            next();
            return {type: "compare", field: word.toLowerCase(), op: opTok.v, value: valueTok.v};
        }

        // 否则视为协议关键字
        return {type: "keyword", word: word.toLowerCase()};
    }

    const ast = parseOr();
    if (pos < tokens.length) {
        throw new Error(`Unexpected trailing token "${tokens[pos].v}".`);
    }
    return ast;
}

/**
 * 解析字段名，取出该字段在给定包上的候选值。
 *
 * 返回数组表示"双向字段"（源与目的任一）。返回空数组表示该字段
 * 在此包上不存在（例如对 UDP 包取 tcp.srcport）。
 *
 * @param {string} field - 字段名（已转小写）
 * @param {Object} ctx - {pkt, capture}
 * @returns {(string|number)[]} 候选值
 */
function resolveField(field, ctx) {
    const pkt = ctx.pkt;
    const net = pkt.network;
    const tr = pkt.transport;
    const link = pkt.link;

    switch (field) {
        case "ip.src":
            return net ? [net.src] : [];
        case "ip.dst":
            return net ? [net.dst] : [];
        case "ip.addr":
            return net ? [net.src, net.dst] : [];
        case "ip.ttl":
            return net && net.ttl !== null ? [net.ttl] : [];
        case "eth.src":
            return link ? [link.src] : [];
        case "eth.dst":
            return link ? [link.dst] : [];
        case "eth.type":
            return link ? [link.etherType] : [];

        case "port":
            return tr ? [tr.srcPort, tr.dstPort] : [];
        case "tcp.port":
            return tr && tr.protocol === "TCP" ? [tr.srcPort, tr.dstPort] : [];
        case "tcp.srcport":
            return tr && tr.protocol === "TCP" ? [tr.srcPort] : [];
        case "tcp.dstport":
            return tr && tr.protocol === "TCP" ? [tr.dstPort] : [];
        case "udp.port":
            return tr && tr.protocol === "UDP" ? [tr.srcPort, tr.dstPort] : [];
        case "udp.srcport":
            return tr && tr.protocol === "UDP" ? [tr.srcPort] : [];
        case "udp.dstport":
            return tr && tr.protocol === "UDP" ? [tr.dstPort] : [];
        case "tcp.seq":
            return tr && tr.protocol === "TCP" ? [tr.seq] : [];
        case "tcp.ack":
            return tr && tr.protocol === "TCP" ? [tr.ack] : [];
        case "tcp.window":
            return tr && tr.protocol === "TCP" ? [tr.window] : [];

        // len 取整个帧的字节数，与 tcpdump / Wireshark 的 len 语义保持一致。
        // 应用层载荷长度另有 payload 字段——两者绝不可混用：帧长恒大于载荷长
        // （相差一个首部），若共用一个字段，用户按直觉写出的阈值必然失准。
        case "len":
            return [ctx.capturePacket ? ctx.capturePacket.data.length : pkt.payload.length];
        case "origlen":
            return [ctx.capturePacket ? ctx.capturePacket.origLen : pkt.payload.length];
        case "payload":
            return [pkt.payload.length];

        case "transport":
            return tr ? [tr.protocol] : [];
        case "app":
            return pkt.appProtocol ? [pkt.appProtocol] : [];

        default:
            // tcp.flags.<name> 这类带前缀的字段
            if (field.startsWith("tcp.flags.")) {
                const flagName = field.slice("tcp.flags.".length);
                if (tr && tr.protocol === "TCP" && tr.flags &&
                    Object.prototype.hasOwnProperty.call(tr.flags, flagName)) {
                    return [tr.flags[flagName]];
                }
                return [];
            }
            return [];
    }
}

/**
 * 判断包是否被过滤表达式选中。
 *
 * @param {Object} node - 语法树节点
 * @param {Object} ctx - {pkt, capturePacket}
 * @returns {boolean}
 */
function evaluate(node, ctx) {
    switch (node.type) {
        case "or":
            return evaluate(node.left, ctx) || evaluate(node.right, ctx);
        case "and":
            return evaluate(node.left, ctx) && evaluate(node.right, ctx);
        case "not":
            return !evaluate(node.expr, ctx);

        case "keyword": {
            const test = KEYWORD_TESTS[node.word];
            if (!test) {
                throw new Error(
                    `Unknown protocol keyword "${node.word}". ` +
                    `Supported: ${Object.keys(KEYWORD_TESTS).join(", ")}.`
                );
            }
            return test(ctx);
        }

        case "compare": {
            const candidates = resolveField(node.field, ctx);

            // 字段在当前包上不存在 → 视为不匹配（而不是报错）。
            // 这样 `tcp.port == 80` 用在混合抓包上不会因为 UDP 包而失败。
            if (candidates.length === 0) return false;

            return candidates.some((c) => compareValues(c, node.op, node.value));
        }

        default:
            throw new Error(`Internal error: unknown node type "${node.type}".`);
    }
}

/**
 * 单个值的比较。
 *
 * 数值运算符（> < >= <=）走数值比较，== 与 != 则按"能当数字就按数字、
 * 否则按字符串"处理。理由见文件头【关键算法】第 4 条。
 *
 * @param {(string|number|null)} actual - 包上取到的值
 * @param {string} op - 运算符
 * @param {string} expected - 表达式中写的值（词法阶段都是字符串）
 * @returns {boolean}
 */
function compareValues(actual, op, expected) {
    if (actual === null || actual === undefined) return false;

    const actualNum = typeof actual === "number" ? actual : Number(actual);
    const expectedNum = Number(expected);
    const bothNumeric = !Number.isNaN(actualNum) && !Number.isNaN(expectedNum) &&
        String(expected).trim() !== "";

    if (NUMERIC_OPS.includes(op)) {
        // 数值运算符只对数字有意义；非数字字段（如 IP）一律不匹配
        if (!bothNumeric) return false;
        return compareNumbers(actualNum, op, expectedNum);
    }

    if (bothNumeric) return compareNumbers(actualNum, op, expectedNum);

    // 字符串比较（IP、MAC、协议名等）
    const a = String(actual).toLowerCase();
    const b = String(expected).toLowerCase();
    return op === "==" ? a === b : a !== b;
}

/**
 * 数值比较。
 *
 * @param {number} a - 实际值
 * @param {string} op - 运算符
 * @param {number} b - 期望值
 * @returns {boolean}
 */
function compareNumbers(a, op, b) {
    switch (op) {
        case "==": return a === b;
        case "!=": return a !== b;
        case ">": return a > b;
        case "<": return a < b;
        case ">=": return a >= b;
        case "<=": return a <= b;
        default: return false;
    }
}


/**
 * Filter PCAP operation
 */
class FilterPcap extends Operation {

    /**
     * 构造函数 —— 声明元信息与参数。
     */
    constructor() {
        super();

        this.name = "Filter PCAP";
        this.module = "Default";
        this.description = "Filters the packets in a capture file using a BPF-style filter expression, " +
            "then outputs a new capture file containing only the matching packets. " +
            "Supports protocol keywords (tcp, udp, http, tls, dns...), field comparisons " +
            "(ip.addr, tcp.port, len, tcp.flags.syn...) and and/or/not logic.";
        this.infoURL = "https://wikipedia.org/wiki/Berkeley_Packet_Filter";
        this.inputType = "ArrayBuffer";
        this.outputType = "ArrayBuffer";
        this.args = [
            {
                name: "Filter expression",
                type: "string",
                value: "tcp",
            },
            {
                name: "Output format",
                type: "option",
                value: ["Same as input", "pcap", "pcapng"],
            },
        ];
    }

    /**
     * 【主流程】过滤抓包并重新生成文件
     *
     * @param {ArrayBuffer} input - 抓包文件原始字节
     * @param {Object[]} args - [expression, outputFormat]
     * @returns {ArrayBuffer} 过滤后的抓包文件字节
     */
    run(input, args) {
        const [expression, outputFormat] = args;

        // --- 步骤 1：输入校验 ---
        if (!input || input.byteLength === 0) {
            throw new OperationError("No input data. Drop a .pcap or .pcapng capture file into the input.");
        }
        if (!expression || !expression.trim()) {
            throw new OperationError(
                "No filter expression given. Examples: \"tcp\", \"http or dns\", \"ip.addr == 192.168.1.10 and port == 80\"."
            );
        }

        const bytes = new Uint8Array(input);

        let capture;
        try {
            capture = parsePcap(bytes);
        } catch (err) {
            throw new OperationError(`Not a valid capture file: ${err.message}`);
        }

        // --- 步骤 2、3：词法分析 + 语法分析 ---
        let ast;
        try {
            ast = parse(tokenize(expression));
        } catch (err) {
            throw new OperationError(`Invalid filter expression: ${err.message}`);
        }

        // --- 步骤 4：先做完整归并（应用层协议要在此回填到包上），再逐包过滤 ---
        const analysis = analysePcap(capture, {dissectCapture});

        const kept = [];
        for (const pkt of analysis.packets) {
            const capturePacket = capture.packets[pkt.index];
            const ctx = {pkt, capturePacket};

            let matched;
            try {
                matched = evaluate(ast, ctx);
            } catch (err) {
                // 求值错误（如拼错的协议关键字）应整体失败，而不是逐包重复报错
                throw new OperationError(`Filter error: ${err.message}`);
            }

            if (matched && capturePacket) kept.push(capturePacket);
        }

        if (kept.length === 0) {
            throw new OperationError(
                `The filter "${expression}" matched no packets out of ${capture.packetCount}. ` +
                "Check the expression and the capture contents."
            );
        }

        // --- 步骤 5：写出 ---
        const targetFormat = outputFormat === "Same as input" ? capture.format : outputFormat;

        const outBytes = targetFormat === "pcapng" ?
            writePcapng(capture, {packets: kept}) :
            writePcap(capture, {packets: kept});

        // CyberChef 的 ArrayBuffer 输出要求返回 ArrayBuffer，且需对齐到实际长度
        return outBytes.buffer.slice(outBytes.byteOffset, outBytes.byteOffset + outBytes.byteLength);
    }
}

export default FilterPcap;
