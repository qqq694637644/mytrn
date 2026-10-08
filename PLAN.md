# mytrn — 单 A / 单 B UDP 隧道与指定 TCP 端口转发计划

> 当前唯一有效的实现计划。与已淘汰的 HTTP GET、自定义 DATA/ACK 帧、第三方 rendezvous、B 公网被动入口等旧设计不兼容，也不保留兼容层。

## 1. 目标与不可变的网络方向

**B（境外 VPS）通过自己本机的 WARP SOCKS5 `UDP ASSOCIATE`，主动连接 A（境内 Windows）的 STUN 公网映射。**

```text
数据面（B 主动拨入 A）：
B agent QUIC client
  -> B localhost WARP SOCKS5 UDP :40000
  -> Cloudflare/WARP UDP 出口
  -> 电信 NAT1 公网 endpoint（由 A 同 socket STUN 得到）
  -> A 家用光猫/路由器 UDP 39999 端口映射
  -> A Windows agent UDP :39999（QUIC server）

控制面（低频、独立于数据面）：
A agent -> A 本机 v2rayN SOCKS5 :10810
        -> VLESS / Cloudflare CDN
        -> B HTTP /control/mapping :18080
```

不租 C 节点，不要求 B 有可直接访问的公网 UDP 或 TCP 业务入口。B 的公网 IP 可能被 GFW 封锁，但这不影响以上已分离的连接方向。

历史探测已经验证 `B WARP SOCKS5 UDP -> A STUN 映射` 的双向 UDP 包 5/5 成功；这不等于 QUIC 新版已在真实跨境链路验证通过，也不代表不配置家用路由器端口映射就一定可打通。

### A 侧地址与端口的区别

```text
A 进程固定绑定：UDP 39999
家用路由器固定转发：UDP 39999 -> A 内网 IP:39999
电信上层 NAT1：A 经 STUN 获得公网 IP:PORT（可能不是 39999）
```

例如此前 STUN 观察到 `119.98.144.218:55781`；它是一次历史观测值，不写死在实现中。B **仅使用最新的 STUN 公网 IP:PORT** 主动拨入 A。

## 2. MVP 范围（确认）

- **节点**：单 A、单 B；A 固定 Windows / Python 3.13、固定内网 IP、UDP 39999；B 为 Linux VPS。
- **真实转发**：只支持配置允许的 **TCP 目标端口**，不是只有 PING/PONG。B 本机 `127.0.0.1:listen_port` 上的 TCP 流量进入 B 已主动建立的 QUIC 隧道，由 A 连接其白名单目标（可以是 A 本机或 A 内网另一台设备）。B 本机监听是本地应用入口，**不是 B 对公网暴露业务端口**。
- **连通与恢复**：映射变化后目标为几分钟内恢复；断网、A/B agent 重启、B SOCKS5 UDP relay 断开后自动尝试重连。
- **部署**：前台 Python 进程，不做 Windows 服务或 systemd；用户自行维护防火墙、光猫路由器永久映射。
- **配置**：A/B 各自通过本机 Web UI 修改 JSON 配置，保存后需重启进程。只保存本地密钥与状态；示例配置可提交，真实配置、私钥不进 Git。
- **不做**：TCP 全局透明代理、TUN、通用 SOCKS 服务、UDP 业务端口转发、多节点、自动公网穿透配置、应用热重载、旧协议兼容。

## 3. 数据面实现（QUIC over WARP SOCKS5 UDP）

### QUIC 会话

1. B 接到经控制面登记的 A endpoint 和 A TLS 证书；使用证书固定验证 A 身份。
2. B 经 `socks5://127.0.0.1:40000` 的 `UDP ASSOCIATE` 发送 QUIC Initial，**B 为 QUIC client，A 为 QUIC server**。
3. QUIC/TLS 握手完成后，B 立即通过首条双向流（stream 0）发送绑定时间戳与随机 nonce 的 `data_psk` HMAC 会话证明。
4. A 验证通过并返回 `OK`，B 才将状态转成 `DATA_ACTIVE`，允许建立业务流。认证失败直接终止会话，不提供降级、密钥回退或明文兼容。
5. A 对未完成会话认证的 QUIC 连接设置短超时（当前 20 秒）；仅已完成应用层认证的健康会话拥有单会话保护，不允许未认证请求无限占据唯一槽位。

### 指定 TCP 端口转发

```text
B 本机业务程序 -> B agent 127.0.0.1:listen_port
-> B 已建立的 QUIC stream -> WARP SOCKS5 UDP -> A UDP :39999
-> A 按 targets 白名单连接 target_host:target_port
-> 双向 TCP <-> QUIC stream 数据转发
```

- B 的 `forwards[].id` 必须对应 A `targets` 中同名规则；A 不接受 B 自由指定任意目标地址/端口。
- 每个业务 stream 仍需要 `data_psk` HMAC、时间戳、nonce 验证，拒绝重放；底层 QUIC 提供 TLS 加密、重传、流量控制、拥塞控制和多路复用。
- OPEN/OK 控制头是行分隔 JSON/文本，**只限制换行符之前的头部长度**（1024 字节），同一帧中跟随的 TCP payload 必须完整透传。
- 处理双向 TCP 半关闭；两方向均完成后立即回收应用层 stream，不等待 QUIC session 关闭。拒绝、异常、连接超时也必须进入最终回收路径。
- 当前限制：最多 32 条并发业务 stream、单 stream 已发送未确认数据应用层缓冲限额；半关闭长期无响应时有超时保护。具体数值以源码为准。

## 4. 控制面与 endpoint 维护

### A

1. 使用**同一个 UDP :39999 socket** 同时收发 STUN 和 QUIC，避免另一个 STUN socket 测到无关映射。
2. 启动时发现 endpoint，通过 v2rayN SOCKS5 → VLESS/CF 向 B 的 `POST /control/mapping` 上报 JSON（IP、端口、A 证书），HTTP 头 `X-Control-Token` 鉴权；不把 token 放入 GET URL。
3. 周期性 STUN/keepalive（建议 15 秒），检测 IP 或公网端口变化；连续两次发现相同的新 endpoint 后才确认变化、通知 B。
4. endpoint 变动时，A 主动结束旧 QUIC 会话以允许 B 重拨新映射。相同 endpoint 不重复触发重连。
5. 正常连接时不高频 HTTP poll；保留 30 分钟低频登记和数据面长时间静默后的再登记，以处理 B 重启/状态丢失。
6. 网络错误自动重试，失败原因可从状态接口/日志定位。

### B

1. HTTP 控制监听地址/端口可配置（默认仅本机 `127.0.0.1:18080`，与现有 VLESS/CF 配合）。
2. 保存最新 endpoint 和经控制面验证的 A 证书/指纹；A 证书更换必须由管理员重新确认信任，不能悄然切换。
3. 控制面更新**同一个** endpoint 不断开有效 QUIC；只有真正变化才通知连接循环更换目标。
4. WARP SOCKS5 UDP relay 关闭、QUIC 心跳失效或 endpoint 更新后自动重建连接。
5. Web UI 只能在 **QUIC/TLS + data_psk 会话认证** 全部成功后显示 `DATA_ACTIVE`。

## 5. 配置、密钥和运行方式

从根目录运行：

```text
python -m pip install -r requirements.txt
python -m mytrn init a          # A 上创建随机控制/数据/管理密钥
python -m mytrn init b          # B 上创建独立配置
python -m mytrn a               # A 前台运行
python -m mytrn b               # B 前台运行
```

把 A 的 `control_token`、`data_psk` 配到 B；B 的 `admin_token` 独立。Web UI：A `127.0.0.1:18881`，B `127.0.0.1:18882`；配置 JSON 保存重启生效。真实配置 `config.a.json`、`config.b.json`、证书私钥、状态目录在 `.gitignore` 中。

配置要求：

- **严格校验**：不接受未识别、缺失的配置字段或未知的转发规则字段；删除 `allow_private_endpoint` 等仅为测试引入的开关。
- `control_bind`、`control_port`、`web_bind`、`web_port` 等均按明确角色配置。Web UI 默认回环地址，不公开部署。
- A `targets`、B `forwards` 一一按规则 ID 配对；业务监听默认 B 回环地址。不要在无防火墙与鉴权防护下暴露 B Web UI、控制 API 或业务端口到公网。

参见 [`README.md`](README.md) 和 `config.*.example.json`。

## 6. 验证门槛

### 已知历史验证（旧探测器）

- A 的 CF/VLESS 控制连接通 B：通过。
- A 的 STUN 映射观测：通过。
- B 的 WARP SOCKS5 `UDP ASSOCIATE` 和经 WARP 的 STUN：通过。
- B WARP UDP → A NAT 映射、A 直接应答 → B：5/5 通过。

### MVP 自动化回归（离线真实 socket）

- A/B 经模拟 SOCKS5 UDP relay 和 STUN 建立加密 QUIC/TCP echo，验证实际数据转发。
- **100 次连续短 TCP 连接**，双向完成后无 stream 残留。
- **40 次目标拒绝连接后恢复服务**，资源不泄漏，新连接能成功。
- 正确头部与大块 TCP payload 合并到达不应误判超长；超长头应拒绝。
- `data_psk` 不一致时，QUIC 握手可能成功，但不能进入 `DATA_ACTIVE`，业务不可用。
- 控制 token 错误、A 证书错误、错误配置键、A/B 启停与 B 状态恢复。
- endpoint 真实变化、WARP UDP relay 中断后恢复和未认证会话短超时需要独立回归验证。
- GitHub Actions 要求 Windows 与 Linux 的 Python 3.13 测试通过。

### 尚需用户真实环境验证

- 国内电信 NAT1/家用光猫映射 ↔ 境外 B 的 WARP SOCKS5 QUIC 实测。
- 长时间运行（6 小时和 24 小时），记录断线恢复时间、endpoint 变化、RTT、丢包、代理重建次数、内存/连接占用。
- 实际 endpoint 变化后几分钟内恢复为目标，不在缺少实网观测时宣称达标。

## 7. 后续阶段（MVP 通过之后）

1. 优化真实中美网络下 QUIC 参数与监控，补齐长稳和异常网络覆盖。
2. 按需求决定是否加入指定 UDP 业务端口转发，而不是提前开发全局代理。
3. 仅在明确需要时考虑服务化、Web 配置热更新、性能与安全加固；不扩展为多节点或复杂平台。
