/**
 * @author jb30795 [jb30795@proton.me]
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— IPv6 过渡地址
 * 【操作】IPv6 Transition Addresses
 * 【功能】在 IPv4 地址与其各类 IPv6 过渡地址之间互转，并可把 MAC 地址转成 EUI-64 接口标识
 * 【输入】string —— 每行一个 IPv4、IPv4/24（范围）、MAC 或 IPv6 地址
 * 【输出】string —— 每行对应一组转换结果（可由参数控制是否带文字标签头）
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 按 \n 拆分输入并用 filter(Boolean) 剔除空行
 *   2. 逐行判定类型并分派：
 *        IPv4 纯地址     → ipTransition(行, false)
 *        IPv4 且以 /24 结尾 → ipTransition(行, true)（按范围输出）
 *        MAC 地址        → macTransition(行)
 *        IPv6 地址       → unTransition(行)（反向还原）
 *   3. 依据 args[0] "Ignore ranges" 决定是否跳过含 "/" 的范围行
 *   4. 依据 args[1] "Remove headers" 决定是否省略结果前的文字标签
 *   5. 拼接所有行返回；遇到无法识别的行则给出统一提示
 * ------------------------------------------------------------
 * 【关键算法】
 *   - XOR 表 {"0":"2","1":"3",…,"e":"c","f":"d"} 实现「首字节低 nibble 异或 2」，
 *     等价于翻转字节第 7 位（U/L 通用/本地位）；MAC→EUI-64 与 EUI-64→MAC 都靠它可逆变换
 *   - hexify / intify：字节与两位十六进制互转的基本工具
 *   - 各种过渡前缀：6to4 = 2002::/16；IPv4-mapped = ::ffff:0:0/96；
 *     IPv4-translated = ::ffff:0:0:0/96；NAT64 = 64:ff9b::/96
 *   - MAC→EUI-64：6 字节按 [0][1]:[2]ff:fe[3]:[4][5] 重排（插入 ff:fe），再翻转 U/L 位
 *   - 反向还原：unTransition 用 startsWith 判前缀、用 slice 按固定偏移取出内嵌 IPv4 的
 *     四段十六进制，或取出 EUI-64 各字节；EUI-64 的判据是第 12-13 字节为 FF:FE
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 用一条超长正则统一校验 IPv6 的压缩/展开诸写法，避免手写解析状态机
 *   - args[1]（Remove headers）作为输出开关，贯穿所有转换函数，便于直接复制结果
 *   - 注意：非法输入分支用的是赋值 `output = "…"` 而非 `+=`，会覆盖此前累积结果并给出统一提示
 *   - 目前仅处理 /24 范围
 * ============================================================
 */

import Operation from "../Operation.mjs";

/**
 * 【类】IPv6TransitionAddresses —— IPv6 过渡地址互转操作
 * 继承 Operation 基类，只实现 run()；内部用若干嵌套函数分别完成正/反向转换。
 */
/**
 * IPv6 Transition Addresses operation
 */
class IPv6TransitionAddresses extends Operation {

    /**
     * 【构造函数】声明元信息与两个布尔参数
     * name = "IPv6 Transition Addresses"，module = "Default"，inputType/outputType 均为 "string"。
     * args[0] Ignore ranges  —— true 时忽略带 "/" 的网段行，只处理单个地址（默认 true）
     * args[1] Remove headers —— true 时输出中不带 "6to4:" 等文字标签，便于直接取用（默认 false）
     */
    /**
     * IPv6TransitionAddresses constructor
     */
    constructor() {
        super();

        this.name = "IPv6 Transition Addresses";
        this.module = "Default";
        this.description = "Converts IPv4 addresses to their IPv6 Transition addresses. IPv6 Transition addresses can also be converted back into their original IPv4 address. MAC addresses can also be converted into the EUI-64 format, this can them be appended to your IPv6 /64 range to obtain a full /128 address.<br><br>Transition technologies enable translation between IPv4 and IPv6 addresses or tunneling to allow traffic to pass through the incompatible network, allowing the two standards to coexist.<br><br>Only /24 ranges and currently handled. Remove headers to easily copy out results.";
        this.infoURL = "https://wikipedia.org/wiki/IPv6_transition_mechanism";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
	    {
                "name": "Ignore ranges",
                "type": "boolean",
	        "value": true
	    },
            {
                "name": "Remove headers",
                "type": "boolean",
                "value": false
            }
        ];
    }

    /**
     * 【主流程】逐行识别地址类型并做对应的过渡转换
     * 返回汇总后的文本；args 见构造函数注释。
     */
    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const XOR = {"0": "2", "1": "3", "2": "0", "3": "1", "4": "6", "5": "7", "6": "4", "7": "5", "8": "a", "9": "b", "a": "8", "b": "9", "c": "e", "d": "f", "e": "c", "f": "d"};

        // 【辅助函数】hexify：把十进制字节值转成两位小写十六进制字符串（不足两位左补 0）
        /**
	 * Function to convert to hex
	 */
        function hexify(octet) {
            return Number(octet).toString(16).padStart(2, "0");
        }

        // 【辅助函数】intify：把十六进制字符串按 16 进制解析为整数
        /**
	 * Function to convert Hex to Int
	 */
        function intify(hex) {
            return parseInt(hex, 16);
        }

        // 【正向转换】把 IPv4 转成 6to4 / IPv4-mapped / IPv4-translated / NAT64 四种过渡地址；
        // range=true 时输出网段写法（/40、/120），false 时给出具体地址（/48 或单地址）
        /**
	 * Function converts IPv4 to IPv6 Transtion address
	 */
        function ipTransition(input, range) {
            let output = "";
            const HEXIP = input.split(".");

            /**
	     * 6to4
	     */
            if (!args[1]) {
                output += "6to4: ";
            }
            output += "2002:" + hexify(HEXIP[0]) + hexify(HEXIP[1]) + ":" + hexify(HEXIP[2]);
            if (range) {
                output += "00::/40\n";
            } else {
                output += hexify(HEXIP[3]) + "::/48\n";
            }

            /**
	     * Mapped
	     */
            if (!args[1]) {
                output += "IPv4 Mapped: ";
            }
            output += "::ffff:" + hexify(HEXIP[0]) + hexify(HEXIP[1]) + ":" + hexify(HEXIP[2]);
            if (range) {
                output += "00/120\n";
            } else {
                output += hexify(HEXIP[3]) + "\n";
            }

            /**
	     * Translated
	     */
            if (!args[1]) {
                output += "IPv4 Translated: ";
            }
            output += "::ffff:0:" + hexify(HEXIP[0]) + hexify(HEXIP[1]) + ":" + hexify(HEXIP[2]);
            if (range) {
                output += "00/120\n";
            } else {
                output += hexify(HEXIP[3]) + "\n";
            }

            /**
	     * Nat64
	     */
            if (!args[1]) {
                output += "Nat 64: ";
            }
            output += "64:ff9b::" + hexify(HEXIP[0]) + hexify(HEXIP[1]) + ":" + hexify(HEXIP[2]);
            if (range) {
                output += "00/120\n";
            } else {
                output += hexify(HEXIP[3]) + "\n";
            }

            return output;
        }

        // 【正向转换】把 MAC 地址转成 EUI-64 接口标识：插入 ff:fe 并翻转首字节 U/L 位
        /**
	 * Convert MAC to EUI-64
	 */
        function macTransition(input) {
            let output = "";
            const MACPARTS = input.split(":");
            if (!args[1]) {
                output += "EUI-64 Interface ID: ";
            }
            const MAC = MACPARTS[0] + MACPARTS[1] + ":" + MACPARTS[2] + "ff:fe" + MACPARTS[3] + ":" + MACPARTS[4] + MACPARTS[5];
            output += MAC.slice(0, 1) + XOR[MAC.slice(1, 2)] + MAC.slice(2);

            return output;
        }


        // 【反向转换】把各类过渡 IPv6 地址还原为原始 IPv4 或 MAC；
        // 依次判前缀 2002:(6to4) / ::ffff: 等(Mapped/Translated/NAT64) / 含 FF:FE(EUI-64)
        /**
	 * Convert IPv6 address to its original IPv4 or MAC address
	 */
        function unTransition(input) {
            let output = "";
            let hextets = "";

            /**
	     * 6to4
	     */
            if (input.startsWith("2002:")) {
                if (!args[1]) {
                    output += "IPv4: ";
                }
                output += String(intify(input.slice(5, 7))) + "." + String(intify(input.slice(7, 9)))+ "." + String(intify(input.slice(10, 12)))+ "." + String(intify(input.slice(12, 14))) + "\n";
            } else if (input.startsWith("::ffff:") || input.startsWith("0000:0000:0000:0000:0000:ffff:") || input.startsWith("::ffff:0000:") || input.startsWith("0000:0000:0000:0000:ffff:0000:") || input.startsWith("64:ff9b::") || input.startsWith("0064:ff9b:0000:0000:0000:0000:")) {
		/**
		 * Mapped/Translated/Nat64
		 */
                hextets = /:([0-9a-z]{1,4}):[0-9a-z]{1,4}$/.exec(input)[1].padStart(4, "0") + /:([0-9a-z]{1,4})$/.exec(input)[1].padStart(4, "0");
                if (!args[1]) {
                    output += "IPv4: ";
                }
                output += intify(hextets.slice(-8, -7) +  hextets.slice(-7, -6)) + "." +intify(hextets.slice(-6, -5) +  hextets.slice(-5, -4)) + "." +intify(hextets.slice(-4, -3) +  hextets.slice(-3, -2)) + "." +intify(hextets.slice(-2, -1) +  hextets.slice(-1,)) + "\n";
            } else if (input.slice(-12, -7).toUpperCase() === "FF:FE") {
		/**
		 * EUI-64
		 */
                if (!args[1]) {
                    output += "Mac Address: ";
                }
                const MAC = (input.slice(-19, -17) + ":" + input.slice(-17, -15) + ":" + input.slice(-14, -12) + ":" + input.slice(-7, -5) + ":" + input.slice(-4, -2) + ":" + input.slice(-2,)).toUpperCase();
                output += MAC.slice(0, 1) + XOR[MAC.slice(1, 2)] + MAC.slice(2) + "\n";
            }

            return output;
        }


        // 【Main】输入预处理：按行拆分并按真值过滤，剔除空行后进入主循环
        /**
	 * Main
	 */
        let output = "";
        let inputs = input.split("\n");
        // Remove blank rows
        inputs = inputs.filter(Boolean);

        // --- 主循环：逐行判定类型（IPv4 / IPv4范围 / MAC / IPv6）并分派 ---
        for (let i = 0; i < inputs.length; i++) {
            // if ignore ranges is checked and input is a range, skip
            if ((args[0] && !inputs[i].includes("/")) || (!args[0])) {
                if (/^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$/.test(inputs[i])) {
                    output += ipTransition(inputs[i], false);
                } else if (/\/24$/.test(inputs[i])) {
                    output += ipTransition(inputs[i], true);
                } else if (/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(inputs[i])) {
                    output += macTransition(inputs[i]);
                } else if (/^((?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/.test(inputs[i])) {
                    output += unTransition(inputs[i]);
                } else {
                    output = "Enter compressed or expanded IPv6 address, IPv4 address or MAC Address.";
                }
            }
        }

        return output;
    }

}

export default IPv6TransitionAddresses;
