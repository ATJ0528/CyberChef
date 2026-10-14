/**
 * @author j433866 [j433866@gmail.com]
 * @copyright Crown Copyright 2019
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— SSH 主机公钥解析
 * 【操作】Parse SSH Host Key
 * 【功能】把 SSH 主机公钥（RFC 4253 定义的二进制结构）解析为密钥类型与各参数字段
 * 【输入】string —— Base64 或 Hex 编码的公钥，可带 "ssh-rsa AAAA..." 前缀
 * 【输出】string —— 多行文本，逐行列出 Key type 及各参数
 * ------------------------------------------------------------
 * 【业务流程】
 *   1. 去除首尾空白后，按 Input Format（Auto / Base64 / Hex）把密钥转成字节数组
 *   2. parseKey() 按 SSH 字符串编码逐段切分：每段 = 4 字节大端长度 + 该长度内容
 *   3. 第 1 段是算法名（key type），据其分支展开后续参数字段
 *   4. 拼接为多行文本返回
 * ------------------------------------------------------------
 * 【关键算法】
 *   - SSH 字符串编码（RFC 4253 §6.1）：字段 = 4 字节大端长度前缀 + 内容，
 *     循环读取即可依次切出 algorithm / exponent / modulus / p,q,g,y / curve / point 等
 *   - 4 字节长度解码：代码用“先加后左移 8、循环末尾再右移 8”实现 b0<<24|b1<<16|b2<<8|b3
 *   - 字段暂存为 hex 串（toHexFast），展示前再用 fromHex 还原成字符
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 输入允许是 authorized_keys 的整行 "ssh-rsa AAAA... comment"，正则会先剥掉算法名只留密钥体
 *   - this.checks 让 CyberChef 在检测到 16 组以上十六进制字节串时自动选用 Hex 格式
 * ============================================================
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import Utils from "../Utils.mjs";
import { fromBase64 } from "../lib/Base64.mjs";
import { fromHex, toHexFast } from "../lib/Hex.mjs";

/**
 * Parse SSH Host Key operation
 *
 * 继承 Operation 基类，只需实现 run() 完成公钥结构解析。
 */
class ParseSSHHostKey extends Operation {

    /**
     * ParseSSHHostKey constructor
     *
     * 声明操作元信息与参数：
     *   name "Parse SSH Host Key"、module "Default"、inputType / outputType 均为 string
     *   args[0] "Input Format" —— 选项 Auto / Base64 / Hex；Auto 时由 detectKeyFormat() 自动探测
     *   this.checks —— 供 CyberChef 自动识别输入：匹配 16 组以上十六进制字节串时预设为 Hex
     */
    constructor() {
        super();

        this.name = "Parse SSH Host Key";
        this.module = "Default";
        this.description = "Parses a SSH host key and extracts fields from it.<br>The key type can be:<ul><li>ssh-rsa</li><li>ssh-dss</li><li>ecdsa-sha2</li><li>ssh-ed25519</li></ul>The key format can be either Hex or Base64.";
        this.infoURL = "https://wikipedia.org/wiki/Secure_Shell";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Input Format",
                type: "option",
                value: [
                    "Auto",
                    "Base64",
                    "Hex"
                ]
            }
        ];
        this.checks = [
            {
                pattern:  "^\\s*([A-F\\d]{2}[,;:]){15,}[A-F\\d]{2}\\s*$",
                flags:  "i",
                args:   ["Hex"]
            }
        ];
    }

    /**
     * 【主流程】解析 SSH 主机公钥
     *
     * args[0] = Input Format（Auto / Base64 / Hex）
     * 返回值：多行文本，第一行为 Key type，其后按密钥类型列出对应参数
     *
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        // --- 步骤 1–2：归一化输入并按 SSH 字符串编码解析出全部字段（fields 为各字段 hex 串）---
        const [inputFormat] = args,
            inputKey = this.convertKeyToBinary(input.trim(), inputFormat),
            fields = this.parseKey(inputKey),
            keyType = Utils.byteArrayToChars(fromHex(fields[0]), "");

        // --- 步骤 3：第 1 段为算法名，据其分支输出对应参数字段 ---
        let output = `Key type: ${keyType}`;

        if (keyType === "ssh-rsa") {
            output += `\nExponent: 0x${fields[1]}`;
            output += `\nModulus: 0x${fields[2]}`;
        } else if (keyType === "ssh-dss") {
            output += `\np: 0x${fields[1]}`;
            output += `\nq: 0x${fields[2]}`;
            output += `\ng: 0x${fields[3]}`;
            output += `\ny: 0x${fields[4]}`;
        } else if (keyType.startsWith("ecdsa-sha2")) {
            output += `\nCurve: ${Utils.byteArrayToChars(fromHex(fields[1]))}`;
            output += `\nPoint: 0x${fields.slice(2)}`;
        } else if (keyType === "ssh-ed25519") {
            output += `\nx: 0x${fields[1]}`;
        } else {
            output += "\nUnsupported key type.";
            output += `\nParameters: ${fields.slice(1)}`;
        }

        return output;
    }

    /**
     * Converts the key to binary format from either hex or base64
     *
     * 先把可能的 "ssh-rsa AAAA..." 前缀剥掉只留密钥体；
     * Auto 时调 detectKeyFormat() 探测编码，再按 Hex / Base64 解码为 byteArray
     *
     * @param {string} inputKey
     * @param {string} inputFormat
     * @returns {byteArray}
     */
    convertKeyToBinary(inputKey, inputFormat) {
        const keyPattern = new RegExp(/^(?:ssh|ecdsa-sha2)\S+\s+(\S*)/),
            keyMatch = inputKey.match(keyPattern);

        if (keyMatch) {
            inputKey = keyMatch[1];
        }

        if (inputFormat === "Auto") {
            inputFormat = this.detectKeyFormat(inputKey);
        }
        if (inputFormat === "Hex") {
            return fromHex(inputKey);
        } else if (inputFormat === "Base64") {
            return fromBase64(inputKey, null, "byteArray");
        } else {
            throw new OperationError("Invalid input format.");
        }
    }


    /**
     * Detects if the key is base64 or hex encoded
     *
     * 依次用 hexPattern、b64Pattern 试匹配，命中则返回 "Hex" / "Base64"，
     * 两者都不匹配时抛 OperationError
     *
     * @param {string} inputKey
     * @returns {string}
     */
    detectKeyFormat(inputKey) {
        const hexPattern = new RegExp(/^(?:[\dA-Fa-f]{2}[ ,;:]?)+$/);
        const b64Pattern = new RegExp(/^\s*(?:[A-Za-z\d+/]{4})+(?:[A-Za-z\d+/]{2}==|[A-Za-z\d+/]{3}=)?\s*$/);

        if (hexPattern.test(inputKey)) {
            return "Hex";
        } else if (b64Pattern.test(inputKey)) {
            return "Base64";
        } else {
            throw new OperationError("Unable to detect input key format.");
        }
    }


    /**
     * Parses fields from the key
     *
     * 输入 byteArray，输出各字段的 hex 串数组。
     * SSH 字符串编码：每段 = 4 字节大端长度 + 该长度内容；
     * 长度 <= 0（长度解出错）时提前 break，避免死循环
     *
     * @param {byteArray} key
     */
    parseKey(key) {
        const fields = [];
        while (key.length > 0) {
            const lengthField = key.slice(0, 4);
            let decodedLength = 0;
            for (let i = 0; i < lengthField.length; i++) {
                decodedLength += lengthField[i];
                decodedLength = decodedLength << 8;
            }
            decodedLength = decodedLength >> 8;
            // Break if length wasn't decoded correctly
            if (decodedLength <= 0) break;

            fields.push(toHexFast(key.slice(4, 4 + decodedLength)));
            key = key.slice(4 + decodedLength);
        }

        return fields;
    }

}

export default ParseSSHHostKey;
