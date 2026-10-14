/**
 * Stream class for parsing binary protocols.
 *
 * @author n1474335 [n1474335@gmail.com]
 * @author tlwr [toby@toby.codes]
 * @copyright Crown Copyright 2018
 * @license Apache-2.0
 *
 */

/**
 * ============================================================
 * 【模块】网络协议解析（Networking）— 共享算法库
 * 【文件】src/core/lib/Stream.mjs
 * 【职责】提供"带游标的字节流读取器"，把解析二进制协议时手工计算偏移量的
 *         工作，抽象为按数据类型顺序读取（readInt/readString/getBytes…）
 * 【被谁使用】被以下操作/库 import（已 grep 核实）：
 *         lib/FileSignatures.mjs、lib/TLS.mjs、operations/ELFInfo、
 *         operations/HASSHClientFingerprint、operations/HASSHServerFingerprint、
 *         operations/JA3Fingerprint、operations/JA3SFingerprint、
 *         operations/ParseTCP、operations/ParseTLSRecord、operations/ParseUDP、
 *         operations/StripIPv4Header、operations/StripTCPHeader、
 *         operations/StripUDPHeader、operations/Untar
 * ------------------------------------------------------------
 * 【导出接口】
 *   - new Stream(input, pos=0, bitPos=0) : 建立游标流
 *   - clone()                            → Stream : 复制当前游标状态
 *   - getBytes(numBytes=null)            → Uint8Array : 取字节并前移游标
 *   - readString(numBytes=-1)            → string : 读到 NUL 或读到上限
 *   - readInt(numBytes, endianness="be") → number : 按端序读整数
 *   - readBits(numBits, endianness="be") → number : 位级读取（可跨字节）
 *   - continueUntil(val)                 → void : 跳转到目标字节/字节序列
 *   - consumeWhile(val)                  → void : 连续跳过指定字节
 *   - consumeIf(val)                     → void : 条件跳过单字节
 *   - moveForwardsBy / moveBackwardsBy / moveBackwardsByBits / moveTo
 *   - hasMore()                          → boolean : 是否还有未读数据
 *   - carve(start=0, finish=position)    → Uint8Array : 取已读区间切片
 * ------------------------------------------------------------
 * 【关键算法】← 核心，务必理解
 *   1. 游标推进模型：每个读方法先按当前 position 取值，再把 position 推进
 *      相应字节数；涉及位读取时同时推进 bitPos。所有读方法结束都把 bitPos
 *      归零，保证字节级读取始终落在字节边界上（不会残留半字节错位）。
 *   2. 端序处理：readInt 用 `val = val << 8; val |= byte` 逐字节移位拼接，
 *      大端顺序遍历字节、小端逆序遍历，无需额外反转数组。
 *   3. 位级读取：readBits 先消费当前字节剩余位，再整字节吞入，最后对多读的
 *      位做"退回"处理（回退 position 并设置 bitPos），实现半字节挂起。
 *   4. 序列查找：continueUntil 对数组目标采用 Boyer-Moore-Horspool 跳跃表
 *      （preprocess 构建 skiptable），失配时按表大步前跳而非逐位回退。
 *   5. 【未使用 DataView】本实现刻意基于 Uint8Array + 原生位运算，而非
 *      DataView。原因：DataView 只能按 1/2/4/8 字节定长读取，无法满足
 *      readBits 这类非字节对齐的位域需求；且少一层对象封装，访问更快。
 * ------------------------------------------------------------
 * 【开发技巧】
 *   - 越界"双策略"：读方法（readInt/readString/getBytes…）越界时返回
 *     undefined（软失败，便于容错解析畸形包继续往下读）；移动方法
 *     （moveTo/moveForwardsBy 等）越界时抛 Error（硬失败，表示错位不可恢复）。
 *   - clone() 用于"试探性读取"：先复制游标再试读，失败就丢弃副本、原流
 *     游标不受影响，是解析可变长/嵌套结构时回滚的常用手段。
 *   - getBytes() 返回的是 slice 副本，改动它不会影响底层缓冲区。
 * ============================================================
 */

/**
 * A Stream can be used to traverse a binary blob, interpreting sections of it
 * as various data types.
 *
 * 【类说明】带游标（cursor）的字节流读取器。底层持有一个 Uint8Array，用
 * position（字节下标）与 bitPos（字节内位偏移）共同描述"读到哪了"。上层
 * 协议解析器只需按字段类型顺序调用 readInt/readString/readBits…，游标自动
 * 推进，从而把"手工累加偏移量"变成"顺序读取"，显著降低解析二进制协议时
 * 算错偏移量的风险。
 */
export default class Stream {

    /**
     * 【构造函数】创建一个带游标的字节流读取器
     *
     * 游标由两个字段共同描述：
     *   - position：下一个待读字节的下标（0 起，单位=字节）
     *   - bitPos  ：当前字节内已消费的位数（0~7），供位级读取（readBits）使用
     * 默认从头（0,0）开始；传入 pos/bitPos 可从缓冲区中间某处续读（续读常
     * 用于嵌套/递归解析）。
     *
     * @param {Uint8Array} input
     * @param {number} pos
     * @param {number} bitPos
     */
    constructor(input, pos=0, bitPos=0) {
        this.bytes = input;
        this.length = this.bytes.length;
        this.position = pos;
        this.bitPos = bitPos;
    }

    /**
     * 【克隆】返回一个与原流状态完全相同的新 Stream
     *
     * 新流与原流共享同一个底层 bytes 引用（浅拷贝），但各自拥有独立的
     * position/bitPos。典型用途是"试探性读取后回溯"：先 clone 再读，若不
     * 满足预期就丢弃 clone，原流的游标不受任何影响。
     *
     * Clone this Stream returning a new identical Stream.
     *
     * @returns {Stream}
     */
    clone() {
        return new Stream(this.bytes, this.position, this.bitPos);
    }

    /**
     * 【字节读取】从当前游标取出 numBytes 个字节，或取出剩余全部字节
     *
     * - numBytes 为 null（默认）时一直读到缓冲区末尾，常用于一次性取走载荷
     * - 返回的是 Uint8Array 切片（新数组，不与源共享内存）
     * - 读取后游标前移，并把 bitPos 归零，保证后续按字节对齐读取
     * - 游标已越界（position > length）时返回 undefined
     *
     * Get a number of bytes from the current position, or all remaining bytes.
     *
     * @param {number} [numBytes=null]
     * @returns {Uint8Array}
     */
    getBytes(numBytes=null) {
        if (this.position > this.length) return undefined;

        const newPosition = numBytes !== null ?
            this.position + numBytes :
            this.length;
        const bytes = this.bytes.slice(this.position, newPosition);
        this.position = newPosition;
        this.bitPos = 0;
        return bytes;
    }

    /**
     * 【字符串读取】把后续字节按 Latin-1（每字节一个码位）解释为字符串，
     * 遇到 0x00（NUL）提前结束，或读到 numBytes 上限
     *
     * 细节：即使中途因 NUL 提前 break，游标仍会整体前移 numBytes，因此
     * 调用方拿到的是"定长字段"读取效果，不会因 NUL 导致后续字段错位。
     * numBytes 为 -1 时读到缓冲区末尾。
     *
     * Interpret the following bytes as a string, stopping at the next null byte or
     * the supplied limit.
     *
     * @param {number} [numBytes=-1]
     * @returns {string}
     */
    readString(numBytes=-1) {
        if (this.position > this.length) return undefined;

        if (numBytes === -1) numBytes = this.length - this.position;

        let result = "";
        for (let i = this.position; i < this.position + numBytes; i++) {
            const currentByte = this.bytes[i];
            if (currentByte === 0) break;
            result += String.fromCharCode(currentByte);
        }
        this.position += numBytes;
        this.bitPos = 0;
        return result;
    }

    /**
     * 【整数读取】把后续 numBytes 个字节按大端(be)/小端(le)拼成一个整数
     *
     * 算法：循环中 `val = val << 8; val |= byte` 逐字节左移拼接。
     * 大端从前往后取字节，小端从后往前取字节（仅反转迭代方向即可）。
     * 注意 JS 位运算按 32 位有符号处理，numBytes > 4 会发生溢出。
     *
     * Interpret the following bytes as an integer in big or little endian.
     *
     * @param {number} numBytes
     * @param {string} [endianness="be"]
     * @returns {number}
     */
    readInt(numBytes, endianness="be") {
        if (this.position > this.length) return undefined;

        let val = 0;
        if (endianness === "be") {
            for (let i = this.position; i < this.position + numBytes; i++) {
                val = val << 8;
                val |= this.bytes[i];
            }
        } else {
            for (let i = this.position + numBytes - 1; i >= this.position; i--) {
                val = val << 8;
                val |= this.bytes[i];
            }
        }
        this.position += numBytes;
        this.bitPos = 0;
        return val;
    }

    /**
     * 【位读取】从当前位游标起读取 numBits 个比特（大端/小端），支持跨字节、
     * 非字节对齐的位域（如 TLS 记录层、各种协议标志位）
     *
     * 算法要点（三步）：
     *   1. 先用 bitMask(bitPos) 取出当前字节内剩余的位作为起始缓冲，并把
     *      当前字节内的 bitPos 消耗掉
     *   2. 若位数仍不够，则不断吞入整字节：大端左移拼接、小端右移拼接
     *   3. 若最后多吞了超过 numBits 的位，则"退回"多余部分：大端右移丢弃，
     *      小端用掩码截断，并把 position 回退 1、bitPos 设为剩余位数，从而
     *      实现"半字节挂起"——下次读取可从字节中间继续
     *
     * Reads a number of bits from the buffer in big or little endian.
     *
     * @param {number} numBits
     * @param {string} [endianness="be"]
     * @returns {number}
     */
    readBits(numBits, endianness="be") {
        if (this.position > this.length) return undefined;

        let bitBuf = 0,
            bitBufLen = 0;

        // Add remaining bits from current byte
        bitBuf = this.bytes[this.position++] & bitMask(this.bitPos);
        if (endianness !== "be") bitBuf >>>= this.bitPos;
        bitBufLen = 8 - this.bitPos;
        this.bitPos = 0;

        // Not enough bits yet
        while (bitBufLen < numBits) {
            if (endianness === "be")
                bitBuf = (bitBuf << bitBufLen) | this.bytes[this.position++];
            else
                bitBuf |= this.bytes[this.position++] << bitBufLen;
            bitBufLen += 8;
        }

        // Reverse back to numBits
        if (bitBufLen > numBits) {
            const excess = bitBufLen - numBits;
            if (endianness === "be")
                bitBuf >>>= excess;
            else
                bitBuf &= (1 << numBits) - 1;
            bitBufLen -= excess;
            this.position--;
            this.bitPos = 8 - excess;
        }

        return bitBuf;

        /**
         * 【私有工具】按当前位偏移构造读取掩码
         * 大端返回 `(1 << (8 - bitPos)) - 1`（保留尚未读取的低位）；
         * 小端返回 `256 - (1 << bitPos)`（保留已对齐的高位）。
         *
         * Calculates the bit mask based on the current bit position.
         *
         * @param {number} bitPos
         * @returns {number} The bit mask
         */
        function bitMask(bitPos) {
            return endianness === "be" ?
                (1 << (8 - bitPos)) - 1 :
                256 - (1 << bitPos);
        }
    }

    /**
     * 【游标跳转】向前消费字节，直到遇到指定字节或字节序列为止
     *
     * 两种模式：
     *   - val 为数字：逐字节线性扫描，命中后游标停在匹配字节的下一格
     *   - val 为数组：采用 Boyer-Moore-Horspool 风格的跳跃算法——先由
     *     preprocess() 依据目标序列构建失配跳转表 skiptable，比对失配时按
     *     表一次跳过多个字节（而非一次只退一格），明显快于朴素逐位比对；
     *     找到完整序列后把游标回退 length，使其停在序列的起始处
     *
     * Consume the stream until we reach the specified byte or sequence of bytes.
     *
     * @param {number|List<number>} val
     */
    continueUntil(val) {
        if (this.position > this.length) return;

        this.bitPos = 0;

        if (typeof val === "number") {
            while (++this.position < this.length && this.bytes[this.position] !== val) {
                continue;
            }
            return;
        }

        // val is an array

        /**
         * 【私有工具】由待查找的目标序列构建 BMH 失配跳转表
         * skiptable[byte] = len - index，即某字节在目标序列中的位置决定失配时
         * 可以安全前跳的距离（越靠后的字节，跳得越少）。
         *
         * Builds the skip forward table from the value to be searched.
         *
         * @param {Uint8Array} val
         * @param {Number} len
         * @returns {Uint8Array}
         */
        function preprocess(val, len) {
            const skiptable = new Array();
            val.forEach((element, index) => {
                skiptable[element] = len - index;
            });
            return skiptable;
        }

        const length = val.length;
        const initial = val[length-1];
        this.position = length;

        // Get the skip table.
        const skiptable = preprocess(val, length);
        let found;

        while (this.position < this.length) {
            // Until we hit the final element of val in the stream.
            while ((this.position < this.length) && (this.bytes[this.position++] !== initial));

            found = true;

            // Loop through the elements comparing them to val.
            for (let x = length-1; x >= 0; x--) {
                if (this.bytes[this.position - length + x] !== val[x]) {
                    found = false;

                    // If element is not equal to val's element then jump forward by the correct amount.
                    this.position += skiptable[val[x]];
                    break;
                }
            }
            if (found) {
                this.position -= length;
                break;
            }
        }
    }


    /**
     * 【游标跳转】只要下一个字节等于 val 就持续消费（用于一次跳过连续相同的
     * 填充字节，如一串 0xFF 或 0x00），遇到不同值立即停止；结束后 bitPos 归零
     *
     * Consume bytes if they match the supplied value.
     *
     * @param {Number} val
     */
    consumeWhile(val) {
        while (this.position < this.length) {
            if (this.bytes[this.position] !== val) {
                break;
            }
            this.position++;
        }
        this.bitPos = 0;
    }

    /**
     * 【游标跳转】仅当下一个字节等于 val 时才消费它（单字节条件消费）
     * 常用于解析可选的尾部填充字节或字段分隔符；不匹配则游标原地不动
     *
     * Consume the next byte if it matches the supplied value.
     *
     * @param {number} val
     */
    consumeIf(val) {
        if (this.bytes[this.position] === val) {
            this.position++;
            this.bitPos = 0;
        }
    }

    /**
     * 【游标移动】沿读取方向前进 numBytes 个字节
     *
     * 边界：目标位置越界（<0 或 >length）时抛出 Error——这是"硬失败"，与读
     * 方法的软失败（返回 undefined）不同，用于表示已不可恢复的错位。
     *
     * Move forwards through the stream by the specified number of bytes.
     *
     * @param {number} numBytes
     */
    moveForwardsBy(numBytes) {
        const pos = this.position + numBytes;
        if (pos < 0 || pos > this.length)
            throw new Error("Cannot move to position " + pos + " in stream. Out of bounds.");
        this.position = pos;
        this.bitPos = 0;
    }

    /**
     * 【游标移动】沿回退方向后退 numBytes 个字节，越界时抛出 Error
     * 常用于解析"先读长度再回退"或撤销一次试探性读取。
     *
     * Move backwards through the stream by the specified number of bytes.
     *
     * @param {number} numBytes
     */
    moveBackwardsBy(numBytes) {
        const pos = this.position - numBytes;
        if (pos < 0 || pos > this.length)
            throw new Error("Cannot move to position " + pos + " in stream. Out of bounds.");
        this.position = pos;
        this.bitPos = 0;
    }

    /**
     * 【游标移动】在位级别后退 numBits 个比特
     *
     * 若当前字节内剩余位数（bitPos）够退，就直接减 bitPos；否则先退到字节
     * 边界，再按整字节递归回退（每次后退 1 字节、把 bitPos 置 8 后继续，
     * 直到剩余位数被消化）。主要用于撤销 readBits 的位级读取。
     *
     * Move backwards through the strem by the specified number of bits.
     *
     * @param {number} numBits
     */
    moveBackwardsByBits(numBits) {
        if (numBits <= this.bitPos) {
            this.bitPos -= numBits;
        } else {
            if (this.bitPos > 0) {
                numBits -= this.bitPos;
                this.bitPos = 0;
            }

            while (numBits > 0) {
                this.moveBackwardsBy(1);
                this.bitPos = 8;
                this.moveBackwardsByBits(numBits);
                numBits -= 8;
            }
        }
    }

    /**
     * 【游标移动】把游标直接定位到绝对位置 pos，越界时抛出 Error
     * 随机访问入口，配合 hasMore()/carve() 可用于分段解析定长记录。
     *
     * Move to a specified position in the stream.
     *
     * @param {number} pos
     */
    moveTo(pos) {
        if (pos < 0 || pos > this.length)
            throw new Error("Cannot move to position " + pos + " in stream. Out of bounds.");
        this.position = pos;
        this.bitPos = 0;
    }

    /**
     * 【状态查询】游标是否还未到缓冲区末尾（即还有未读字节）
     * 解析循环通常写作 `while (stream.hasMore()) { … }`。
     *
     * Returns true if there are more bytes left in the stream.
     *
     * @returns {boolean}
     */
    hasMore() {
        return this.position < this.length;
    }

    /**
     * 【切片】返回从 start 到 finish 之间的字节切片，默认区间为 [0, position)
     *
     * 细节：若 bitPos > 0，说明当前字节还有位没读完（半个字节也已被消费），
     * 此时 finish 需 +1 把这一字节也算进去，避免边界字节被漏掉。
     *
     * Returns a slice of the stream up to the current position.
     *
     * @param {number} [start=0]
     * @param {number} [finish=this.position]
     * @returns {Uint8Array}
     */
    carve(start=0, finish=this.position) {
        if (this.bitPos > 0) finish++;
        return this.bytes.slice(start, finish);
    }

}
