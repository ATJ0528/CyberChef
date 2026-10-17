/**
 * Protocol parsing functions.
 *
 * @author n1474335 [n1474335@gmail.com]
 * @copyright Crown Copyright 2022
 * @license Apache-2.0
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 共享算法库
 * 【文件】src/core/lib/Protocol.mjs
 * 【职责】为协议解析类操作提供两个通用工具：把解析得到的 JSON 对象渲染成
 *         可读的 HTML 表格（objToTable），以及把字节序列转成任意精度大整数字符串
 *         （bytesToLargeNumber）；本身不含 Operation 类。
 * 【被谁使用】（grep 查证）
 *   - src/core/operations/ParseTCP.mjs       ← objToTable, bytesToLargeNumber
 *   - src/core/operations/ParseTLSRecord.mjs ← objToTable
 *   - src/core/operations/ParseUDP.mjs       ← objToTable
 * ------------------------------------------------------------
 * 【导出接口】
 *   - objToTable(obj, nested=false) → string
 *       : 递归地把对象渲染成 Bootstrap 风格 HTML 表格（Field/Value 两列），
 *         嵌套对象转成内层子表格
 *   - bytesToLargeNumber(bs) → string
 *       : Uint8Array → 十六进制串 → BigNumber 十进制字符串（用于承载超 64 位整数）
 * ------------------------------------------------------------
 * 【关键算法】
 *   - 递归渲染：objToTable 遇到值为 object 时递归调用自身并置 nested=true，
 *     内层用 table-borderless 样式嵌入外层单元格
 *   - 大数转换：先 toHexFast 得 16 进制串，再 BigNumber(hex, 16).toString()
 *     转十进制，规避 Number 只有 53 位安全精度的问题（如 128 位整数）
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 渲染前对键与值统一 Utils.escapeHtml，防止被解析数据里的
 *     < > " 等字符破坏 HTML 结构（XSS / 布局错乱）
 *   - 值为 function 的键直接跳过，避免把方法渲染进表格
 * ============================================================
 */

import BigNumber from "bignumber.js";
import {toHexFast} from "../lib/Hex.mjs";
import Utils from "../Utils.mjs";

/**
 * 【函数】递归地把 JSON 对象渲染成 HTML 表格
 *
 * 参数：
 *   - obj    : 待渲染对象（通常为协议解析结果）
 *   - nested : 是否为嵌套层；顶层（false）带表头与边框，内层（true）去掉表头、
 *              改用无边框样式并收紧外边距，使子表格嵌入父表格单元格
 * 返回：HTML 表格字符串
 *
 * 算法要点：
 *   - 顶层输出 Field/Value 两列表头，嵌套层不输出表头
 *   - 遍历 Object.keys(obj)：值为 function 的项跳过（不渲染方法）
 *   - 值仍是对象（且非 null）时递归调用自身并置 nested=true，生成子表格
 *   - 其余值用 String() 转换后经 Utils.escapeHtml 转义再填入单元格
 * 边界：null 被当作普通值渲染（不递归）；键与值都做 HTML 转义以防御注入。
 */
/**
 * Recursively displays a JSON object as an HTML table
 *
 * @param {Object} obj
 * @returns string
 */
export function objToTable(obj, nested=false) {
    let html = `<table
        class='table table-sm table-nonfluid ${nested ? "mb-0 table-borderless" : "table-bordered"}'
        style='table-layout: fixed; ${nested ? "margin: -1px !important;" : ""}'>`;
    if (!nested)
        html += `<tr>
            <th>Field</th>
            <th>Value</th>
        </tr>`;

    for (const key of Object.keys(obj)) {
        const value = obj[key];
        if (typeof value === "function")
            continue;

        html += `<tr><td style='word-wrap: break-word'>${Utils.escapeHtml(String(key))}</td>`;
        if (value !== null && typeof value === "object")
            html += `<td style='padding: 0'>${objToTable(value, true)}</td>`;
        else
            html += `<td>${Utils.escapeHtml(String(value))}</td>`;
        html += "</tr>";
    }
    html += "</table>";
    return html;
}

/**
 * 【函数】把字节序列转成任意精度大整数的十进制字符串
 *
 * 参数：bs，Uint8Array（大端字节序）
 * 返回：string，十进制表示
 *
 * 算法要点：
 *   - 先用 toHexFast(bs) 把字节数组转成 16 进制串
 *   - 再 new BigNumber(hex, 16).toString() 以 16 进制解析、按 10 进制输出；
 *     借 BigNumber 支持任意精度，从而安全表示超过 Number 53 位安全范围的整数
 *     （如 TCP 序号 / IPv6 地址的 128 位数值）
 * 边界：空数组得到 0；不校验字节序，调用方需自行保证为大端。
 */
/**
 * Converts bytes into a BigNumber string
 * @param {Uint8Array} bs
 * @returns {string}
 */
export function bytesToLargeNumber(bs) {
    return BigNumber(toHexFast(bs), 16).toString();
}
