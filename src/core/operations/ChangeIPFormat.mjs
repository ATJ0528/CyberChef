/**
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2016
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— IP 地址格式转换
 * 【操作】Change IP format
 * 【功能】把一个（或一批）IPv4 地址在 Dotted Decimal / Decimal / Octal / Hex 四种表示之间互转
 * 【输入】string —— 每行一个 IP 地址，输入格式由参数 "Input format" 指定
 * 【输出】string —— 每行一个转换结果，输出格式由参数 "Output format" 指定
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 按 \n 把输入拆成多行，逐行处理（空行跳过）
 *   2. 若 "Input format" 与 "Output format" 相同，直接原样输出该行（短路，省去转换）
 *   3. 按 "Input format" 把该行转成 4 字节数组 baIp：
 *        Dotted Decimal → 按 "." 切分后逐段 parseInt(…, 10)
 *        Decimal        → fromNumber(value, 10)（先把整串按 10 进制读成 32 位数再拆字节）
 *        Octal          → fromNumber(value, 8)
 *        Hex            → fromHex()
 *   4. 按 "Output format" 把 baIp 渲染为目标格式
 *   5. 各行以 \n 拼接，最后剥掉末尾换行
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 32 位地址与 4 字节数组的互转是本操作的核心：
 *       组装：`(b0 << 24) | (b1 << 16) | (b2 << 8) | b3`，随后 `>>> 0` 强制转为无符号 32 位
 *             （JS 的位运算符结果是有符号的，`>>> 0` 可避免出现负数）
 *       拆解：`decimal >> 24 & 255`、`>> 16 & 255`、`>> 8 & 255`、`& 255` 逐字节取出
 *   - Decimal / Octal 输入是「单个整数标量」，必须先 parseInt(value, radix) 再拆成 4 字节
 *   - Octal 输出时统一加前导 "0" 表示八进制
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - inFormat === outFormat 时直接短路返回，逻辑简单又省一次换算
 *   - 外层循环变量 i 管行、内层复用函数作用域的 j 管字节下标，避免嵌套声明
 *   - 把「拆字节」抽成私有方法 fromNumber(value, radix)，让 run() 的 switch 更干净
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Utils from "../Utils.mjs";
import {fromHex} from "../lib/Hex.mjs";

/**
 * 【类】ChangeIPFormat —— IP 地址格式互转操作
 * 继承 Operation 基类；含一个私有辅助方法 fromNumber()，负责按进制把整数拆成 4 字节。
 */
/**
 * Change IP format operation
 */
class ChangeIPFormat extends Operation {

    /**
     * 【构造函数】声明元信息与两个参数
     * name = "Change IP format"，module = "Default"，inputType/outputType 均为 "string"。
     * args[0] Input format  —— 取值：Dotted Decimal / Decimal / Octal / Hex，决定输入如何解析
     * args[1] Output format —— 取值同上，决定结果如何渲染
     * 两个参数字典一致，可任意组合（相同则原样输出）。
     */
    /**
     * ChangeIPFormat constructor
     */
    constructor() {
        super();

        this.name = "Change IP format";
        this.module = "Default";
        this.description = "Convert an IP address from one format to another, e.g. <code>172.20.23.54</code> to <code>ac141736</code>";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                "name": "Input format",
                "type": "option",
                "value": ["Dotted Decimal", "Decimal", "Octal", "Hex"]
            },
            {
                "name": "Output format",
                "type": "option",
                "value": ["Dotted Decimal", "Decimal", "Octal", "Hex"]
            }
        ];
    }

    /**
     * 【主流程】逐行做 IP 格式互转
     * 参数 args[0]=输入格式、args[1]=输出格式；返回所有结果行拼接后的字符串（不含末尾换行）。
     */
    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [inFormat, outFormat] = args,
            lines = input.split("\n");
        let output = "",
            j = 0;

        for (let i = 0; i < lines.length; i++) {
            if (lines[i] === "") continue;
            let baIp = [];
            let octets;

            // 输入输出格式相同：无需换算，原样透传该行
            if (inFormat === outFormat) {
                output += lines[i] + "\n";
                continue;
            }

            // --- 步骤 3：按输入格式把地址转成 4 字节数组 baIp ---
            // Convert to byte array IP from input format
            switch (inFormat) {
                case "Dotted Decimal":
                    octets = lines[i].split(".");
                    for (j = 0; j < octets.length; j++) {
                        baIp.push(parseInt(octets[j], 10));
                    }
                    break;
                case "Decimal":
                    baIp = this.fromNumber(lines[i].toString(), 10);
                    break;
                case "Octal":
                    baIp = this.fromNumber(lines[i].toString(), 8);
                    break;
                case "Hex":
                    baIp = fromHex(lines[i]);
                    break;
                default:
                    throw new OperationError("Unsupported input IP format");
            }

            let ddIp;
            let decIp;
            let hexIp;

            // --- 步骤 4：按输出格式把字节数组 baIp 渲染为目标表示 ---
            // Convert byte array IP to output format
            switch (outFormat) {
                case "Dotted Decimal":
                    ddIp = "";
                    for (j = 0; j < baIp.length; j++) {
                        ddIp += baIp[j] + ".";
                    }
                    output += ddIp.slice(0, ddIp.length-1) + "\n";
                    break;
                case "Decimal":
                    decIp = ((baIp[0] << 24) | (baIp[1] << 16) | (baIp[2] << 8) | baIp[3]) >>> 0;
                    output += decIp.toString() + "\n";
                    break;
                case "Octal":
                    decIp = ((baIp[0] << 24) | (baIp[1] << 16) | (baIp[2] << 8) | baIp[3]) >>> 0;
                    output += "0" + decIp.toString(8) + "\n";
                    break;
                case "Hex":
                    hexIp = "";
                    for (j = 0; j < baIp.length; j++) {
                        hexIp += Utils.hex(baIp[j]);
                    }
                    output += hexIp + "\n";
                    break;
                default:
                    throw new OperationError("Unsupported output IP format");
            }
        }

        return output.slice(0, output.length-1);
    }

    /**
     * 【私有辅助】把「单个整数形式的 IP」拆成 4 字节数组
     * 输入：value 是整数的字符串表示，radix 为其进制（10 或 8）；
     * 输出：长度为 4 的字节数组，高位字节在前（大端）。
     * 算法要点：先 parseInt(value, radix) 还原成 32 位整数，
     *          再用 `>> 24 & 255` … `& 255` 从高到低逐字节取出。
     */
    /**
     * Constructs an array of IP address octets from a numerical value.
     * @param {string} value The value of the IP address
     * @param {number} radix The numeral system to be used
     * @returns {number[]}
     */
    fromNumber(value, radix) {
        const decimal = parseInt(value, radix);
        const baIp = [];
        baIp.push(decimal >> 24 & 255);
        baIp.push(decimal >> 16 & 255);
        baIp.push(decimal >> 8 & 255);
        baIp.push(decimal & 255);
        return baIp;
    }

}

export default ChangeIPFormat;
