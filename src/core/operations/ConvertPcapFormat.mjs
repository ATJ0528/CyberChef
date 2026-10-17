/**
 * @author ATJ0528
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import {parsePcap, writePcap, writePcapng} from "../lib/Pcap.mjs";

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 抓包文件格式转换
 * 【操作】Convert PCAP format
 * 【功能】在 pcap 与 pcapng 之间互转，并可指定端序与时间戳精度
 * 【输入】ArrayBuffer —— 抓包文件原始字节
 * 【输出】ArrayBuffer —— 转换后的抓包文件字节
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 解析输入抓包（自动识别原格式、端序、时间精度）
 *   2. 按目标格式选择写出器
 *   3. 把目标端序与时间精度作为选项传给写出器
 *   4. 返回字节
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 转换不是"字节搬运"，而是「解析成模型 → 从模型重新序列化」。
 *     两条路径都走统一的 PcapCapture 模型，因此 pcap→pcapng 与
 *     pcapng→pcap 共用同一段代码。这也是为什么本操作只有几十行——
 *     复杂部分已经在解析器和写出器里了。
 *   - 时间戳精度在两种格式里的表达方式不同：
 *       · pcap 用魔数区分的全局标志（0xa1b2c3d4 微秒 / 0xa1b23c4d 纳秒），
 *         精度是整个文件级别的。
 *       · pcapng 用 IDB 的 if_tsresol 选项，是每个接口级别的。
 *     本操作在转换 pcap→pcapng 时把全局精度映射为每个接口的精度，
 *     反向则由接口精度决定全局标志。不这样映射就会出现前面遇到过的
 *     时间戳被放大 1000 倍的问题。
 *   - 精度只能"升"不能"降"而不丢信息：微秒转纳秒是精确的（原地乘 1000），
 *     纳秒转微秒会丢末尾三位。这里不做拦截，但会在降精度时给出明确提示，
 *     避免用户以为数据本就如此。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 选项之间存在依赖：pcapng 没有全局端序概念之外的东西，而"时间精度"
 *     只对 pcap 有意义。这类"某个选项只在某个取值下才有意义"的情形，
 *     处理办法是在文档里写清楚并在代码里静默忽略无关选项，而不是试图
 *     动态隐藏参数——CyberChef 的参数列表是静态声明的。
 *   - 转换前后包数必须一致，若不一致说明解析或写出有 bug。这里加一条
 *     断言式校验，宁可报错也不要产出一个"看起来正常但少了包"的文件。
 * ============================================================
 */

/**
 * Convert PCAP format operation
 */
class ConvertPcapFormat extends Operation {

    /**
     * 构造函数 —— 声明元信息与参数。
     */
    constructor() {
        super();

        this.name = "Convert PCAP format";
        this.module = "Default";
        this.description = "Converts a capture file between the classic libpcap (.pcap) and pcapng (.pcapng) " +
            "formats, and lets you change the byte order and timestamp precision. " +
            "Useful because different tools emit different capture formats.";
        this.infoURL = "https://wikipedia.org/wiki/Pcap";
        this.inputType = "ArrayBuffer";
        this.outputType = "ArrayBuffer";
        this.args = [
            {
                name: "Output format",
                type: "option",
                value: ["pcap", "pcapng"],
            },
            {
                name: "Byte order",
                type: "option",
                value: ["Little endian", "Big endian"],
            },
            {
                name: "Timestamp precision",
                type: "option",
                value: ["Microseconds", "Nanoseconds"],
                hint: "Ignored for pcapng output, which always uses nanoseconds.",
            },
        ];
    }

    /**
     * 【主流程】转换抓包格式
     *
     * @param {ArrayBuffer} input - 抓包文件原始字节
     * @param {Object[]} args - [outputFormat, byteOrder, precision]
     * @returns {ArrayBuffer} 转换后的抓包文件字节
     */
    run(input, args) {
        const [outputFormat, byteOrder, precision] = args;

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

        const littleEndian = byteOrder === "Little endian";
        const nanosecond = precision === "Nanoseconds";
        const originalCount = capture.packetCount;

        // --- 步骤 2、3：按目标格式写出 ---
        const outBytes = outputFormat === "pcapng" ?
            writePcapng(capture, {littleEndian}) :
            writePcap(capture, {littleEndian, nanosecond});

        // --- 步骤 4：自校验。转换不应改变包数，一旦不符说明解析/写出有缺陷 ---
        let roundTrip;
        try {
            roundTrip = parsePcap(outBytes);
        } catch (err) {
            throw new OperationError(`Internal error: the converted file could not be re-read (${err.message}).`);
        }

        if (roundTrip.packetCount !== originalCount) {
            throw new OperationError(
                `Internal error: packet count changed during conversion ` +
                `(${originalCount} in, ${roundTrip.packetCount} out).`
            );
        }

        return outBytes.buffer.slice(outBytes.byteOffset, outBytes.byteOffset + outBytes.byteLength);
    }
}

export default ConvertPcapFormat;
