# PCAP 操作使用指南

CyberChef 原本只能把网络数据当作普通字节处理，看不到抓包文件的结构。
本分支新增了四个操作，使 CyberChef 可以直接读取、筛选、重组和转换
`.pcap` / `.pcapng` 抓包文件。

| 操作 | 输入 | 输出 | 用途 |
| --- | --- | --- | --- |
| Parse PCAP | ArrayBuffer | 文本 / HTML | 查看包列表、单包详情、会话与统计 |
| Filter PCAP | ArrayBuffer | ArrayBuffer | 按表达式筛选包，生成新的抓包文件 |
| Extract PCAP streams | ArrayBuffer | string | 重组 TCP 流 / 归并 UDP 流并提取载荷 |
| Convert PCAP format | ArrayBuffer | ArrayBuffer | pcap 与 pcapng 互转、字节序与时间精度转换 |

四个操作都是 `ArrayBuffer` 入口，因为抓包文件是二进制。在 CyberChef
里把文件拖进 Input 面板即可，拖入时 Input 面板会自动切换到文件模式。

## 快速开始

1. 拖入一个 `.pcap` 或 `.pcapng` 文件。
2. 从 Operations 列表里搜索 `PCAP`，把需要的操作加入 Recipe。
3. 操作按顺序执行，前一步的输出就是后一步的输入。

如果没有文件，也可以把十六进制文本粘进 Input，先接一个
`From Hex` 操作，再接 PCAP 操作。这种情况下第一个操作收到的仍然是
完整的抓包字节。

## 操作参考

### Parse PCAP

把抓包结构化成可读的文本。参数：

- **Max packets**：解析多少个包后停止，默认 10000，`0` 表示不限制。
  大型抓包文件建议先设成较小的值，确认格式解析正确后再放开。
- **Display**：输出视图。
  - `Packet list`：每包一行的摘要（时间、源/目的、协议、长度）。
  - `Packet details`：每个包的分层结构（链路层 / 网络层 / 传输层 / 应用层）。
  - `Conversations`：按五元组归并后的会话列表，含应用层协议识别结果。
  - `Capture info`：容器格式、字节序、链路类型、包数与告警。

### Filter PCAP

按过滤表达式保留匹配的包，并按原容器格式重新写出。

参数：

- **Filter expression**：过滤表达式，默认 `tcp`。
- **Output format**：`Same as input`（默认）、`pcap`、`pcapng`。

过滤语法接近 Wireshark 的显示过滤器，但只实现了一个精简子集：

#### 协议关键字

关键字单独作为条件使用：

```text
tcp  udp  icmp  ip  ipv6  arp  vlan  truncated
http  tls  ssh  dns  smtp  ftp  pop3  imap  redis  quic  mdns
```

应用层关键字依赖前面的会话识别结果，因此 `http`、`tls` 这类条件
对每个包判断的是"它所属的会话被识别成了什么协议"，而不是包内
恰好出现了哪些字节。

#### 字段比较

| 字段 | 含义 | 示例 |
| --- | --- | --- |
| `ip.src` / `ip.dst` | IPv4/IPv6 源、目的地址 | `ip.src == 192.168.1.10` |
| `ip.addr` | 源或目的任一匹配 | `ip.addr == 8.8.8.8` |
| `ip.ttl` | TTL / Hop Limit | `ip.ttl < 10` |
| `eth.src` / `eth.dst` | MAC 地址 | `eth.src == 00:11:22:33:44:55` |
| `eth.type` | 以太网类型（数值） | `eth.type == 2048` |
| `port` | 源或目的端口 | `port == 80` |
| `tcp.port` / `udp.port` | 指定传输层的任一端口 | `udp.port == 53` |
| `tcp.srcport` / `tcp.dstport` | 单侧端口 | `tcp.srcport > 1024` |
| `udp.srcport` / `udp.dstport` | 单侧端口 | `udp.dstport == 5353` |
| `tcp.seq` / `tcp.ack` / `tcp.window` | TCP 序号、确认号、窗口 | `tcp.window == 0` |
| `tcp.flags.<name>` | `syn` `ack` `fin` `rst` `psh` `urg` | `tcp.flags.syn == 1` |
| `len` | 整个帧的字节数 | `len > 100` |
| `origlen` | 抓包时记录的原长 | `origlen > len` |
| `payload` | 应用层载荷字节数 | `payload > 100` |
| `transport` | 传输层协议名 | `transport == TCP` |
| `app` | 应用层协议名 | `app == HTTP` |

字符串值直接写成不带引号的词，比较时忽略大小写；因此
`app == HTTP` 与 `app == http` 等价。表达式里不要加引号，引号不是
词法分析的合法字符。

#### 运算符与逻辑

比较：`==` `!=` `>` `<` `>=` `<=`
逻辑：`and` / `&&`、`or` / `||`、`not` / `!`，以及括号
优先级：`not` > 比较 > `and` > `or`

字段在当前包上不存在时（例如对手里没有传输层的 ARP 包取
`tcp.srcport`）视为不匹配，而不是报错。这样一条表达式可以安全地
用在混合抓包上。

示例：

```text
tcp and port == 80 and len > 100
http or dns
ip.addr == 192.168.1.10 and not tcp.flags.ack == 1
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### Extract PCAP streams

把抓包里的 TCP 流重组成完整字节流，并把 UDP 按双向四元组归并成流，
然后按方向输出应用层载荷。参数：

- **Extract**：`TCP streams` / `UDP flows` / `Both`。
- **Direction**：`Client to server` / `Server to client` / `Both`。
- **Stream index**：只取第几条流，`-1` 表示全部。
- **Include stream annotations**：是否输出 `--- Stream N ... ---` 标注行。
- **Delimiter**：多条流之间的分隔符，`Double newline` / `Newline` /
  `CRLF` / `None`。

客户端/服务端的判定规则：

- TCP：发送 SYN 而不用 ACK 确认的一方是客户端。
- UDP：端口号较小的一方是服务端；端口相同再按地址排序。

输出中的载荷按 Latin-1 语义逐字节映射为字符，不做 UTF-8 解码——
抓包载荷可能是任意编码，UTF-8 解码遇到非法字节会插入替换字符并
破坏原始数据。需要按 UTF-8 阅读时，在后面接一个 `Decode text` 操作
并选择 UTF-8。

### Convert PCAP format

参数：

- **Output format**：`pcap` 或 `pcapng`。
- **Byte order**：`Little endian` / `Big endian`（仅 pcap）。
- **Timestamp precision**：`Microseconds` / `Nanoseconds`（仅 pcap；
  pcapng 固定使用纳秒）。

## 配方示例

CyberChef 的配方可以通过 URL 的 `#recipe=` 参数分享。在界面里按
"Save recipe" 得到的 JSON 形如：

```json
[
  {"op": "Parse PCAP", "args": [10000, "Packet list"]},
  {"op": "Filter PCAP", "args": ["http or dns", "Same as input"]}
]
```

几个常用组合：

- **只看 HTTP 请求**：`Parse PCAP`（Display = `Conversations`）
  → `Filter PCAP`（`http`）→ `Extract PCAP streams`
  （Extract = `TCP streams`，Direction = `Client to server`）。
- **导出 DNS 查询**：`Filter PCAP`（`dns`）→ `Convert PCAP format`
  （`pcap`，Big endian）→ `To Hex`，便于交给其他工具。
- **排查重传**：`Filter PCAP`（`tcp.flags.syn == 1`）→ `Parse PCAP`
  （Display = `Packet details`），看握手是否完整。

## 处理链路与代码位置

四个操作共用三个库模块，重组与解包逻辑只实现一次：

| 文件 | 职责 |
| --- | --- |
| `src/core/lib/Pcap.mjs` | 容器层：识别 pcap / pcapng，读出包记录 |
| `src/core/lib/PcapPacket.mjs` | 协议层：以太网 / VLAN / IPv4 / IPv6 / ARP / TCP / UDP 逐层解包 |
| `src/core/lib/PcapSession.mjs` | 会话层：TCP 重组、UDP 归并、应用层协议识别 |
| `src/core/operations/ParsePcap.mjs` | 操作层：格式化输出 |
| `src/core/operations/FilterPcap.mjs` | 操作层：过滤器词法/语法分析、求值、重新写出 |
| `src/core/operations/ExtractPcapStreams.mjs` | 操作层：按方向与序号取用会话载荷 |
| `src/core/operations/ConvertPcapFormat.mjs` | 操作层：写出 pcap / pcapng |

分层顺序是"容器 → 协议 → 会话 → 操作"。操作层只负责取用与呈现，
不重复实现解码，这样新加一个基于抓包的操作时不必再写一遍解包代码。

## 测试

抓包相关的测试是独立的 Node 脚本，位于 `tests/lib/`：

```bash
node tests/lib/pcap-smoke.mjs         # 端到端冒烟
node tests/lib/pcap-detect.mjs        # 应用层协议识别
node tests/lib/pcap-write.mjs         # 写出与格式转换
node tests/lib/pcap-filter.mjs        # 过滤表达式
node tests/lib/pcap-streams.mjs       # TCP / UDP 流提取
node tests/lib/pcap-errors.mjs        # 错误处理与边界条件
node tests/lib/pcap-frames.mjs        # IPv6 / VLAN / ARP 帧解析
```

也可以一次跑完：

```bash
npm run test:pcap
```

每个脚本自行生成测试所需的二进制夹具（`tests/lib/PcapFixtures.mjs`），
不依赖外部样本文件。脚本以退出码表示结果，可以直接接进 CI。

## 已知限制

- 暂不支持 TCP 乱序重排与丢包重传去重，只按序号顺序拼接已到达的段。
- VLAN 只剥一层 802.1Q，不支持 QinQ。
- 链路层仅支持以太网（link type 1）。
- pcapng 只读 Enhanced Packet Block 与 Simple Packet Block，
  不解析注释块与其他选项。
- 应用层协议识别基于首包特征与端口兜底，不是完整的协议状态机。
