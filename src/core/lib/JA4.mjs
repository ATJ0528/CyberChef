/**
 * JA4 resources.
 *
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2024
 * @license Apache-2.0
 *
 * JA4 Copyright 2023 FoxIO, LLC.
 * @license BSD-3-Clause
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 共享算法库
 * 【文件】src/core/lib/JA4.mjs
 * 【职责】实现 FoxIO JA4 / JA4S 系列 TLS 指纹：解析 Client Hello / Server
 *         Hello，抽取版本、SNI、密码套件、扩展、ALPN 等特征并依规范归一化
 *         （忽略 GREASE、排序、SHA256 截断），生成可跨连接稳定比对的指纹串
 * 【被谁使用】被以下操作 import（已 grep 核实）：
 *         operations/JA4Fingerprint（调用 toJA4）、
 *         operations/JA4ServerFingerprint（调用 toJA4S）
 * ------------------------------------------------------------
 * 【导出接口】
 *   - toJA4(bytes)  → {JA4, JA4_o, JA4_r, JA4_ro} : 客户端指纹（4 个变体）
 *   - toJA4S(bytes) → {JA4S, JA4S_r}               : 服务端指纹（2 个变体）
 *   - tlsVersionMapper(version) → string : 版本号→两字符标识（内部函数）
 *   - isAlphanumeric(byte)      → boolean : ASCII 字母数字判断（内部函数）
 *   - alpnFingerprint(rawBytes) → string : ALPN 两字符指纹（内部函数）
 * ------------------------------------------------------------
 * 【关键算法】JA4 指纹格式逐位拆解（客户端 toJA4）
 *   形如： t 13 d 15 10 h2 _ <12位密码哈希> _ <12位扩展哈希>
 *   ┌ 第 1 位   ptype   ：连接类型，t=TCP / q=QUIC（当前仅实现 t，QUIC TODO）
 *   ├ 第 2~3 位 version ：TLS 版本两字符（13/12/11/10/s3/s2/s1/00）。取自
 *   │                    supported_versions 扩展中的最高版本（忽略 GREASE）；
 *   │                    无该扩展时退回 Client Hello 的 Protocol Version，
 *   │                    Handshake 版本字段忽略
 *   ├ 第 4 位   sni     ：d=存在 SNI 扩展（目标是域名）/ i=无（目标是 IP）
 *   ├ 第 5~6 位 cipherLen：非 GREASE 密码套件个数，两位十进制，>99 记 "99"
 *   ├ 第 7~8 位 extLen  ：非 GREASE 扩展个数，两位十进制，>99 记 "99"
 *   ├ 第 9~10位 alpn    ：首个 ALPN 值的首/尾字符；无 ALPN 时为 "00"
 *   └ 下划线后两段各 12 位 = SHA256(规范化列表) 截断为 12 位十六进制：
 *       · 密码哈希：所有非 GREASE 密码套件的 4 位十六进制小写值，逗号连接，
 *         **按字典序排序**后取 SHA256 前 12 位（排序保证同一套件集合指纹相同）
 *       · 扩展哈希：非 GREASE 扩展类型的 4 位十六进制值排序（并 **剔除
 *         SNI(0000) 与 ALPN(0010)**，因其已体现在 a 段，使同一应用无论访问
 *         域名/IP 或变换 ALPN，b 段保持一致），再拼上 signature_algorithms
 *         的**出现顺序**（不排序），取 SHA256 前 12 位
 *   变体：JA4_o=原始顺序（未排序）的哈希版；JA4_r / JA4_ro=未哈希的原始串，
 *         便于调试与人工核对列表内容。
 *
 *   JA4S 服务端格式： t 13 08 h2 _ <chosen cipher 4位hex> _ <12位扩展哈希>
 *         服务端**不剔除 GREASE**、无 SNI 段，且改记服务端选中的单个密码套件。
 *
 *   "忽略 GREASE"：GREASE 是一组保留值（如 0x0a0a、0x1a1a…），客户端每次
 *   连接会随机插入若干，用于探测中间盒是否合规。若把它们计入指纹，每次握手
 *   都会变化，因此必须排除，以得到稳定的指纹。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 解析复用同目录 TLS.mjs 的 parseTLSRecord / parseHighestSupportedVersion /
 *     parseFirstALPNValue，将 TLS 二叉结构解析与指纹计算解耦。
 *   - 入口先校验 handshakeType（Client Hello=0x01 / Server Hello=0x02），
 *     不符即抛 OperationError，把底层异常包装成对用户友好的错误信息。
 *   - 哈希统一走 core 的 runHash("sha256", …)，结果截取前 12 位十六进制字符。
 * ============================================================
 */

import OperationError from "../errors/OperationError.mjs";
import { parseTLSRecord, parseHighestSupportedVersion, parseFirstALPNValue } from "./TLS.mjs";
import { toHexFast } from "./Hex.mjs";
import { runHash } from "./Hash.mjs";
import Utils from "../Utils.mjs";


/**
 * 【客户端指纹】由 TLS Client Hello 字节流计算 JA4 指纹
 *
 * 流程：parseTLSRecord 解析 → 确认 handshakeType 为 0x01（Client Hello）
 * → 逐段提取 ptype/version/sni/cipherLen/extLen/alpn
 * → 分别对密码套件列表与扩展列表计算 12 位截断 SHA256
 * → 拼装出排序/原始 × 哈希/明文 共 4 个变体。
 *
 * 注意：数据非法（非 Client Hello）时抛 OperationError。
 * 另：入参虽标注为 string，实际返回的是一个含 JA4 及其变体的对象。
 *
 * Calculate the JA4 from a given TLS Client Hello Stream
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toJA4(bytes) {
    let tlsr = {};
    try {
        tlsr = parseTLSRecord(bytes);
        if (tlsr.handshake.value.handshakeType.value !== 0x01) {
            throw new Error();
        }
    } catch (err) {
        throw new OperationError("Data is not a valid TLS Client Hello. QUIC is not yet supported.\n" + err);
    }

    /* QUIC
        “q” or “t”, which denotes whether the hello packet is for QUIC or TCP.
        TODO: Implement QUIC
    */
    const ptype = "t";

    /* TLS Version
        TLS version is shown in 3 different places. If extension 0x002b exists (supported_versions), then the version
        is the highest value in the extension. Remember to ignore GREASE values. If the extension doesn’t exist, then
        the TLS version is the value of the Protocol Version. Handshake version (located at the top of the packet)
        should be ignored.
    */
    let version = tlsr.handshake.value.helloVersion.value;
    for (const ext of tlsr.handshake.value.extensions.value) {
        if (ext.type.value === "supported_versions") {
            version = parseHighestSupportedVersion(ext.value.data);
            break;
        }
    }
    version = tlsVersionMapper(version);

    /* SNI
        If the SNI extension (0x0000) exists, then the destination of the connection is a domain, or “d” in the fingerprint.
        If the SNI does not exist, then the destination is an IP address, or “i”.
    */
    let sni = "i";
    for (const ext of tlsr.handshake.value.extensions.value) {
        if (ext.type.value === "server_name") {
            sni = "d";
            break;
        }
    }

    /* Number of Ciphers
        2 character number of cipher suites, so if there’s 6 cipher suites in the hello packet, then the value should be “06”.
        If there’s > 99, which there should never be, then output “99”. Remember, ignore GREASE values. They don’t count.
    */
    let cipherLen = 0;
    for (const cs of tlsr.handshake.value.cipherSuites.value) {
        if (cs.value !== "GREASE") cipherLen++;
    }
    cipherLen = cipherLen > 99 ? "99" : cipherLen.toString().padStart(2, "0");

    /* Number of Extensions
        Same as counting ciphers. Ignore GREASE. Include SNI and ALPN.
    */
    let extLen = 0;
    for (const ext of tlsr.handshake.value.extensions.value) {
        if (ext.type.value !== "GREASE") extLen++;
    }
    extLen = extLen > 99 ? "99" : extLen.toString().padStart(2, "0");

    /* ALPN Extension Value
        The first and last characters of the ALPN (Application-Layer Protocol Negotiation) first value.
        If there are no ALPN values or no ALPN extension then we print “00” as the value in the fingerprint.
    */
    let alpn = "00";
    for (const ext of tlsr.handshake.value.extensions.value) {
        if (ext.type.value === "application_layer_protocol_negotiation") {
            alpn = alpnFingerprint(parseFirstALPNValue(ext.value.data));
            break;
        }
    }

    /* Cipher hash
        A 12 character truncated sha256 hash of the list of ciphers sorted in hex order, first 12 characters.
        The list is created using the 4 character hex values of the ciphers, lower case, comma delimited, ignoring GREASE.
    */
    const originalCiphersList = [];
    for (const cs of tlsr.handshake.value.cipherSuites.value) {
        if (cs.value !== "GREASE") {
            originalCiphersList.push(toHexFast(cs.data));
        }
    }
    const sortedCiphersList = [...originalCiphersList].sort();
    const sortedCiphersRaw = sortedCiphersList.join(",");
    const originalCiphersRaw = originalCiphersList.join(",");
    const sortedCiphers = runHash(
        "sha256",
        Utils.strToArrayBuffer(sortedCiphersRaw)
    ).substring(0, 12);
    const originalCiphers = runHash(
        "sha256",
        Utils.strToArrayBuffer(originalCiphersRaw)
    ).substring(0, 12);

    /* Extension hash
        A 12 character truncated sha256 hash of the list of extensions, sorted by hex value, followed by the list of signature
        algorithms, in the order that they appear (not sorted).
        The extension list is created using the 4 character hex values of the extensions, lower case, comma delimited, sorted
        (not in the order they appear). Ignore the SNI extension (0000) and the ALPN extension (0010) as we’ve already captured
        them in the a section of the fingerprint. These values are omitted so that the same application would have the same b
        section of the fingerprint regardless of if it were going to a domain, IP, or changing ALPNs.
    */
    const originalExtensionsList = [];
    let signatureAlgorithms = "";
    for (const ext of tlsr.handshake.value.extensions.value) {
        if (ext.type.value !== "GREASE") {
            originalExtensionsList.push(toHexFast(ext.type.data));
        }
        if (ext.type.value === "signature_algorithms") {
            signatureAlgorithms = toHexFast(ext.value.data.slice(2));
            signatureAlgorithms = signatureAlgorithms.replace(/(.{4})/g, "$1,");
            signatureAlgorithms = signatureAlgorithms.substring(0, signatureAlgorithms.length - 1);
        }
    }
    const sortedExtensionsList = [...originalExtensionsList].filter(e => e !== "0000" && e !== "0010").sort();
    const sortedExtensionsRaw = sortedExtensionsList.join(",") + "_" + signatureAlgorithms;
    const originalExtensionsRaw = originalExtensionsList.join(",") + "_" + signatureAlgorithms;
    const sortedExtensions = runHash(
        "sha256",
        Utils.strToArrayBuffer(sortedExtensionsRaw)
    ).substring(0, 12);
    const originalExtensions = runHash(
        "sha256",
        Utils.strToArrayBuffer(originalExtensionsRaw)
    ).substring(0, 12);

    return {
        "JA4":    `${ptype}${version}${sni}${cipherLen}${extLen}${alpn}_${sortedCiphers}_${sortedExtensions}`,
        "JA4_o":  `${ptype}${version}${sni}${cipherLen}${extLen}${alpn}_${originalCiphers}_${originalExtensions}`,
        "JA4_r":  `${ptype}${version}${sni}${cipherLen}${extLen}${alpn}_${sortedCiphersRaw}_${sortedExtensionsRaw}`,
        "JA4_ro": `${ptype}${version}${sni}${cipherLen}${extLen}${alpn}_${originalCiphersRaw}_${originalExtensionsRaw}`,
    };
}


/**
 * 【服务端指纹】由 TLS Server Hello 字节流计算 JA4S 指纹
 *
 * 流程：parseTLSRecord 解析 → 确认 handshakeType 为 0x02（Server Hello）
 * → 提取 version/extLen/alpn → 记录服务端选中的单个 cipher 套件
 * → 对全部扩展类型列表计算 12 位截断 SHA256 → 拼装出 JA4S 与 JA4S_r。
 *
 * 与服务端指纹的差异：不剔除 GREASE、无 SNI 段、密码位是"选中的单个套件"
 * 而非套件个数。
 *
 * Calculate the JA4Server from a given TLS Server Hello Stream
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toJA4S(bytes) {
    let tlsr = {};
    try {
        tlsr = parseTLSRecord(bytes);
        if (tlsr.handshake.value.handshakeType.value !== 0x02) {
            throw new Error();
        }
    } catch (err) {
        throw new OperationError("Data is not a valid TLS Server Hello. QUIC is not yet supported.\n" + err);
    }

    /* QUIC
        “q” or “t”, which denotes whether the hello packet is for QUIC or TCP.
        TODO: Implement QUIC
    */
    const ptype = "t";

    /* TLS Version
        TLS version is shown in 3 different places. If extension 0x002b exists (supported_versions), then the version
        is the highest value in the extension. Remember to ignore GREASE values. If the extension doesn’t exist, then
        the TLS version is the value of the Protocol Version. Handshake version (located at the top of the packet)
        should be ignored.
    */
    let version = tlsr.handshake.value.helloVersion.value;
    for (const ext of tlsr.handshake.value.extensions.value) {
        if (ext.type.value === "supported_versions") {
            version = parseHighestSupportedVersion(ext.value.data);
            break;
        }
    }
    version = tlsVersionMapper(version);

    /* Number of Extensions
        2 character number of cipher suites, so if there’s 6 cipher suites in the hello packet, then the value should be “06”.
        If there’s > 99, which there should never be, then output “99”.
    */
    let extLen = tlsr.handshake.value.extensions.value.length;
    extLen = extLen > 99 ? "99" : extLen.toString().padStart(2, "0");

    /* ALPN Extension Chosen Value
        The first and last characters of the ALPN (Application-Layer Protocol Negotiation) first value.
        If there are no ALPN values or no ALPN extension then we print “00” as the value in the fingerprint.
    */
    let alpn = "00";
    for (const ext of tlsr.handshake.value.extensions.value) {
        if (ext.type.value === "application_layer_protocol_negotiation") {
            alpn = alpnFingerprint(parseFirstALPNValue(ext.value.data));
            break;
        }
    }

    /* Chosen Cipher
        The hex value of the chosen cipher suite
    */
    const cipher = toHexFast(tlsr.handshake.value.cipherSuite.data);

    /* Extension hash
        A 12 character truncated sha256 hash of the list of extensions.
        The extension list is created using the 4 character hex values of the extensions, lower case, comma delimited.
    */
    const extensionsList = [];
    for (const ext of tlsr.handshake.value.extensions.value) {
        extensionsList.push(toHexFast(ext.type.data));
    }
    const extensionsRaw = extensionsList.join(",");
    const extensionsHash = runHash(
        "sha256",
        Utils.strToArrayBuffer(extensionsRaw)
    ).substring(0, 12);

    return {
        "JA4S":    `${ptype}${version}${extLen}${alpn}_${cipher}_${extensionsHash}`,
        "JA4S_r":  `${ptype}${version}${extLen}${alpn}_${cipher}_${extensionsRaw}`,
    };
}


/**
 * 【版本映射】把两字节 TLS 版本号映射为 JA4 使用的两字符版本标识
 *   0x0304→"13"、0x0303→"12"、0x0302→"11"、0x0301→"10"、0x0300→"s3"（SSL3.0）、
 *   0x0200→"s2"、0x0100→"s1"，其余未知值统一返回 "00"。
 *
 * Takes a TLS version value and returns a JA4 TLS version string
 * @param {Uint8Array} version - Two byte array of version number
 * @returns {string}
 */
function tlsVersionMapper(version) {
    switch (version) {
        case 0x0304: return "13"; // TLS 1.3
        case 0x0303: return "12"; // TLS 1.2
        case 0x0302: return "11"; // TLS 1.1
        case 0x0301: return "10"; // TLS 1.0
        case 0x0300: return "s3"; // SSL 3.0
        case 0x0200: return "s2"; // SSL 2.0
        case 0x0100: return "s1"; // SSL 1.0
        default: return "00"; // Unknown
    }
}

/**
 * 【私有工具】判断一个字节是否为 ASCII 字母或数字（0-9 / A-Z / a-z）
 * 用三个区间逐个比较，供 alpnFingerprint 判断能否直接以字符形式呈现。
 *
 * Checks if a byte is ASCII alphanumeric (0-9, A-Z, a-z).
 * @param {number} byte
 * @returns {boolean}
 */
function isAlphanumeric(byte) {
    return (byte >= 0x30 && byte <= 0x39) ||
           (byte >= 0x41 && byte <= 0x5A) ||
           (byte >= 0x61 && byte <= 0x7A);
}

/**
 * 【私有工具】由原始 ALPN 字节计算 2 字符 ALPN 指纹
 *
 * 规则：若首字节与尾字节均为 ASCII 字母数字，则直接取这两个字符
 * （如 "h2"→"h2"、"http/1.1"→"h1"）；否则退化为十六进制表示——取首字节
 * 的第一个 hex 位，拼上尾字节的第二个 hex 位。空或缺失时返回 "00"。
 *
 * Computes the 2-character ALPN fingerprint from raw ALPN bytes.
 * If both first and last bytes are ASCII alphanumeric, returns their characters.
 * Otherwise, returns first hex digit of first byte + last hex digit of last byte.
 * @param {Uint8Array|null} rawBytes
 * @returns {string}
 */
function alpnFingerprint(rawBytes) {
    if (!rawBytes || rawBytes.length === 0) return "00";
    const firstByte = rawBytes[0];
    const lastByte = rawBytes[rawBytes.length - 1];
    if (isAlphanumeric(firstByte) && isAlphanumeric(lastByte)) {
        return String.fromCharCode(firstByte) + String.fromCharCode(lastByte);
    }
    const firstHex = firstByte.toString(16).padStart(2, "0");
    const lastHex = lastByte.toString(16).padStart(2, "0");
    return firstHex[0] + lastHex[1];
}
