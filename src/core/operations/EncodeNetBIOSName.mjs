/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2017
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— NetBIOS 名称编码
 * 【操作】Encode NetBIOS Name
 * 【功能】把原始 NetBIOS 名称按 First-Level Encoding 编码为
 *        NetBIOS-over-TCP 中使用的可打印字符表示
 * 【输入】byteArray —— 原始名称字节（≤ 16 字节，不足则用空格 0x20 补齐）
 * 【输出】byteArray —— 32 个可打印 ASCII 字符（'A'–'P' 区间）
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 仅当输入 ≤ 16 字节时处理，并就地扩容到 16 字节、用 32(空格) 补齐
 *   2. 逐字节拆成高 4 位与低 4 位两个半字节
 *   3. 每个半字节各加 offset（默认 0x41）得到可打印字符并压入输出
 *   4. 16 字节 → 32 字符，返回结果
 * ------------------------------------------------------------
 * 【关键算法】First-Level Encoding（RFC 1001）
 *   - NetBIOS 名称在客户端接口处恒为 16 字节，其中第 16 字节是名称类型/后缀
 *   - 第一层编码把每个字节拆成两个半字节，各加 0x41('A')，
 *     使整串落入 'A'–'P'，从而伪装成合法的域名标签
 *   - 高半字节取下法：input[i] >> 4；低半字节：input[i] & 0xf；随后各 + offset
 *   - 与 Decode NetBIOS Name 互为逆运算
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - `input.fill(32, len, 16)` 先在本地补齐到 16 字节再编码，
 *     保证输出恒为 32 字符；注意它会就地修改传入的数组
 *   - offset 参数化，同一实现可支持其他偏移约定的编码变体
 * ============================================================
 */

import Operation from "../Operation.mjs";

/**
 * Encode NetBIOS Name operation
 *
 * 继承自 Operation 基类，只需实现 run()；构造函数负责声明元信息
 * （名称、描述、输入输出类型、参数），框架据此生成界面控件。
 */
class EncodeNetBIOSName extends Operation {

    /**
     * EncodeNetBIOSName constructor
     *
     * inputType  = "byteArray"，框架先把 Dish 转成字节数组再传入 run()
     * outputType = "byteArray"，run() 返回的字节数组由框架渲染
     * args[0] Offset —— 数值型，默认 65，即编码时每个半字节加上的基准值 0x41('A')
     * 说明：与 Decode 不同，本操作未声明 checks，不会自动匹配输入形态
     */
    constructor() {
        super();

        this.name = "Encode NetBIOS Name";
        this.module = "Default";
        this.description = "NetBIOS names as seen across the client interface to NetBIOS are exactly 16 bytes long. Within the NetBIOS-over-TCP protocols, a longer representation is used.<br><br>There are two levels of encoding. The first level maps a NetBIOS name into a domain system name.  The second level maps the domain system name into the 'compressed' representation required for interaction with the domain name system.<br><br>This operation carries out the first level of encoding. See RFC 1001 for full details.";
        this.infoURL = "https://wikipedia.org/wiki/NetBIOS";
        this.inputType = "byteArray";
        this.outputType = "byteArray";
        this.args = [
            {
                "name": "Offset",
                "type": "number",
                "value": 65
            }
        ];
    }

    /**
     * 【主流程】NetBIOS 名称编码
     *
     * 参数 args[0] = offset：每个半字节所加的基准值，默认 65(0x41)
     * 返回值：32 个可打印字符的编码结果；输入超过 16 字节时返回空数组
     *
     * @param {byteArray} input
     * @param {Object[]} args
     * @returns {byteArray}
     */
    run(input, args) {
        const output = [],
            offset = args[0];

        // --- 步骤 1：仅接受 ≤16 字节，并就地补齐到 16 字节、用空格 32 填满 ---
        if (input.length <= 16) {
            const len = input.length;
            input.length = 16;
            input.fill(32, len, 16);
            // --- 步骤 2+3：逐字节拆出高/低半字节，各 + offset 输出为一个字符 ---
            for (let i = 0; i < input.length; i++) {
                output.push((input[i] >> 4) + offset);
                output.push((input[i] & 0xf) + offset);
            }
        }

        return output;

    }

}

export default EncodeNetBIOSName;
