/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2017
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— NetBIOS 名称解码
 * 【操作】Decode NetBIOS Name
 * 【功能】把 NetBIOS-over-TCP 中使用 First-Level Encoding 编码过的名称，
 *        还原为原始的 16 字节 NetBIOS 名称
 * 【输入】byteArray —— 至多 32 个可打印 ASCII 字符（编码后的半字节表示）
 * 【输出】byteArray —— 还原后的名称字节序列（已剥离尾部空格填充）
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 长度校验：仅当输入长度 ≤ 32 且为偶数时才是合法编码
 *   2. 每两字节一组，各自减去 offset（默认 0x41）得到两个半字节
 *   3. 高半字节左移 4 位、与低半字节按位或，拼回一个原始字节
 *   4. 从尾部向前剥离值为 32（空格）的填充字节
 * ------------------------------------------------------------
 * 【关键算法】First-Level Encoding 的逆运算（RFC 1001）
 *   - NetBIOS 名称固定为 16 字节；编码时把每个字节拆成两个半字节，
 *     各加 0x41('A') 变成 'A'–'P' 区间内的可打印字符，使 16 字节膨胀为 32 字符
 *   - 解码即其逆运算：(字符 - offset) 取回半字节，再高低拼合：
 *     ((hi & 0xff) - offset) << 4 | (((lo & 0xff) - offset) & 0xf)
 *   - 不采用 fromHex，而是逐字符“减偏移再拼半字节”，是本操作的核心技巧
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - offset 参数化后默认 65(0x41)，同一份逻辑可适配其他偏移约定
 *   - checks 中预置正则 ^\s*\S{32}$，当输入恰为 32 个非空白字符时，
 *     框架会自动推荐使用本操作，提升易用性
 * ============================================================
 */

import Operation from "../Operation.mjs";

/**
 * Decode NetBIOS Name operation
 *
 * 继承自 Operation 基类，只需实现 run()；构造函数负责声明元信息
 * （名称、描述、输入输出类型、参数），框架据此在界面生成控件。
 */
class DecodeNetBIOSName extends Operation {

    /**
     * DecodeNetBIOSName constructor
     *
     * inputType  = "byteArray"，框架先把 Dish 转成字节数组再传入 run()
     * outputType = "byteArray"，run() 返回的字节数组由框架渲染
     * args[0] Offset —— 数值型，默认 65，即编码时每个半字节加上的基准值 0x41('A')
     * checks —— 输入形态匹配规则：长度为 32 的非空白串即自动提示本操作
     */
    constructor() {
        super();

        this.name = "Decode NetBIOS Name";
        this.module = "Default";
        this.description = "NetBIOS names as seen across the client interface to NetBIOS are exactly 16 bytes long. Within the NetBIOS-over-TCP protocols, a longer representation is used.<br><br>There are two levels of encoding. The first level maps a NetBIOS name into a domain system name.  The second level maps the domain system name into the 'compressed' representation required for interaction with the domain name system.<br><br>This operation decodes the first level of encoding. See RFC 1001 for full details.";
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
        this.checks = [
            {
                pattern:  "^\\s*\\S{32}$",
                flags:  "",
                args:   [65]
            }
        ];
    }

    /**
     * 【主流程】NetBIOS 名称解码
     *
     * 参数 args[0] = offset：编码时每个半字节所加的基准值，默认 65(0x41)
     * 返回值：拼合还原后的名称字节数组；输入长度非法时原样返回空数组
     *
     * @param {byteArray} input
     * @param {Object[]} args
     * @returns {byteArray}
     */
    run(input, args) {
        const output = [],
            offset = args[0];

        // --- 步骤 1：长度校验，偶数且不超过 32 字节才是合法编码 ---
        if (input.length <= 32 && (input.length % 2) === 0) {
            // --- 步骤 2+3：每两字符取回两个半字节，高 4 位与低 4 位拼成一个原始字节 ---
            for (let i = 0; i < input.length; i += 2) {
                output.push((((input[i] & 0xff) - offset) << 4) |
                            (((input[i + 1] & 0xff) - offset) & 0xf));
            }
            // --- 步骤 4：从尾部向前剥离值为 32（空格）的填充，遇到非空格即停 ---
            for (let i = output.length - 1; i > 0; i--) {
                if (output[i] === 32) output.splice(i, i);
                else break;
            }
        }

        return output;
    }

}

export default DecodeNetBIOSName;
