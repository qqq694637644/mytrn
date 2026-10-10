# mytrn — A Python + 单 Xray 控制/数据面，B 使用 x-ui

**核心目的：让中国境内 Windows A 的应用通过境外 VPS B 访问互联网，即使 B 公网 IP 在国内无法直接访问。**

```text
建立隧道：B x-ui Xray → 现有 WARP SOCKS5 UDP :40000 → 电信 NAT 公网 IP:PORT → A Python UDP :39999 → A Xray UDP :40001
用户上网：A 浏览器 → v2rayN（只负责本机流量收集）→ A Xray SOCKS5 :10808 → VLESS reverse/mKCP/TLS → B freedom → 网站
控制面：A Python → 自己管理的 A Xray SOCKS5 :10909 → VLESS/TLS/XHTTP (packet-up / chrome / h3) → Cloudflare CDN → B 现有 VLESS :26417 → B x-ui Go HTTP（使用实际监听端口）
```

Xray-core v26.3.27 **原生负责** SOCKS5、CF CDN/VLESS/TLS/XHTTP 控制通道、VLESS reverse/mKCP/TLS 数据通道、重传和代理连接。A 的 Python 只负责 STUN/UDP 39999、低频 HTTP 注册、生成配置并管理自己的**一个** Xray 进程、本机 Web 配置。B 由**已实现的 x-ui Go + x-ui 唯一 Xray 进程**管理 endpoint、WARP 出站和境外 freedom。**没有自写 QUIC/KCP/TCP-over-UDP。**

已在用户真实的电信 NAT1 + 美国 VPS WARP 上用独立 [Python PoC](poc/xray26327/README.md) 验证 B 连接 A 和 A 代理请求经 B `freedom` 到 `ifconfig.me:443`。**本正式 Python Agent 版本已通过本机真实 Xray + 模拟 SOCKS5 UDP/STUN/控制链的集成测试；自动恢复机制尚未在你的真实 A/B 环境完成验收。**

## 安装（A 和 B）

需 Python 3.13（A 已有）和 A 本机的 **Xray-core v26.3.27** 二进制。A Python 管理自己的一个 Xray 子进程，**不控制 B x-ui 管理的 Xray、VLESS、Caddy 或 WARP**。同仓库旧 `python -m mytrn b` 仅保留用于历史 PoC/独立测试；**实际 B 不要同时启动旧 Python Agent**。

在仓库根目录运行：

```bash
python -m pip install -r requirements.txt
```

### 初始化并配置 A（Windows）

```powershell
python -m mytrn init a
python -m mytrn a
```

- `init a` **只需一次**，生成 `config.a.json`，其中有随机 `control_token`、`vless_uuid`、`admin_token`；**不要将这些凭据提交 GitHub**。初始化时终端会打印 Web 管理 token。**升级现有 A 时直接复用原来的配置和证书目录，不要重新 init。**
- 在 A 浏览器打开 `http://127.0.0.1:18881`，输入 `admin_token` 后读取配置。
- 设置 `xray_bin` 为 A 本机 **v26.3.27** Xray 的绝对路径，如 `C:/Tools/Xray/xray.exe`。
- 保留 `udp_bind=0.0.0.0`、`udp_port=39999`、`xray_udp_port=40001`、`socks_port=10808`。A 光猫/路由器的 `UDP 39999 → A 固定内网 IP:39999` 规则必须已经生效；**不要映射 40001**。
- 在 A Web UI 的“**控制面：CF CDN / VLESS + XHTTP**”中，从**目前已经正常工作的 v2rayN 节点**填写：`control_cf_address`（CDN 地址）、`control_cf_port`、`control_cf_uuid`（该 VLESS 节点的 UUID，非 MyTRN UUID）、`control_cf_server_name`（TLS SNI）、`control_cf_xhttp_host`（XHTTP Host）、`control_cf_xhttp_path`（XHTTP Path）、`control_cf_xhttp_mode`（截图为 `packet-up`）、`control_cf_fingerprint`（截图为 `chrome`）、`control_cf_alpn`（截图为 `h3`）。**先前 A 使用 WS，与你实际能用的 XHTTP 节点不符，是控制请求失败的关键原因。**
- `control_host` / `control_port` 是通过上述 CF/VLESS 出站实际访问的 **B x-ui Go HTTP 控制服务 IP:PORT**（通常端口 18080），不是 CF 域名。确认 B VLESS 代理能访问该 HTTP 地址；不要默认认为远端 loopback 一定可达。
- `control_proxy_port` 默认 `10909`，是**Python 专用、本机回环的 Xray SOCKS5 入站**；用户数据 `10808` 只由 v2rayN 使用。A 的 Python **不再依赖 v2rayN `10810` 做控制**。旧 `control_socks5` 字段读取时删除并由新 CF 配置项取代；没有填写 CF 节点时控制注册明确失败，不直连 B、不回退 v2rayN，mKCP 数据入口仍可以启动。
- 点击保存，然后**退出并重新执行 `python -m mytrn a`**。重启后 A 会用同一个 `39999` UDP socket 做 STUN 并在变化时注册 B。
- **检测 CF → B 控制链路（只读）**：在重启 A 后点击网页的检测按钮，Python 用 A Xray 本地 `10909` SOCKS5 经 XHTTP 访问 B Go `/control/mapping` 的 GET 接口。只有收到 B Go 特有的 HTTP `405` JSON 才算控制 HTTP 路径可达；**不会执行注册、改变 STUN endpoint 或触发 B 重启**。如果仍看到 `[WinError 64]`，查看 `state.a/xray-a.log`，依次核对 XHTTP、HTTP/3 UDP 443、TLS 指纹、ALPN、SNI/Host/Path，以及 B Go 当前控制端口（以 x-ui 实际值为准）。
- 旧 A 配置中的 `control_cf_ws_host`、`control_cf_ws_path` 在首次读取/保存时分别改名为 `control_cf_xhttp_host`、`control_cf_xhttp_path`，保留你已经填写的值；运行时**没有 WebSocket 兜底或 v2rayN 控制通道**。原配置的 admin_token、control_token、VLESS UUID、A TLS 证书和 mKCP 端口不变。

#### A/B 双端 mKCP 调参（保留现有 Python A + x-ui B）

- A Web UI `http://127.0.0.1:18881` 新增“**A 端 mKCP 传输参数**”表单，直接显示当前值并可独立保存：MTU、TTI、上行容量、下行容量、拥塞控制、读取缓冲、写入缓冲；也可在原有 JSON 编辑器中修改对应 `mkcp_*` 字段。
- **只改变 A 的 mKCP 参数时**，保存后当前 Python Agent 会在约 3 秒内对新的 Xray 26.3.27 配置执行 `run -test`，通过后仅重启 A 的**专用 Xray 子进程**。UDP Gateway/STUN `39999`、Web、控制上报及 NAT 映射不重建。普通配置（如端口/控制路径）变更仍需重启 Python Agent。
- B 的 mKCP 参数独立在 **x-ui → 入站列表 → MyTRN → 编辑** 中修改，使用 x-ui 的单 Xray 进程重启机制；不再需要运行独立 B Python Agent。
- 新字段兼容旧 `config.a.json`：没有 `mkcp_*` 键时自动显示**之前实际生效的默认值**，**不会改变**原有 token、UUID、STUN/控制路径或 A 的 UDP 端口。

| 参数 | A/B 当前有效默认值 | 说明 |
| --- | --- | --- |
| MTU | `1200` 字节 | A 当前 Python Xray 和 B 已验证配置；考虑 WARP UDP、NAT 路径的包头额外开销 |
| TTI | `50` 毫秒 | Xray 26.3.27 默认；过大可能增加时延，且当前内核存在窗口计算分母限制，UI 最大 1000 |
| uplinkCapacity / downlinkCapacity | `5 / 20` MB/s | **协议容量参数，不是测速结果或实际限速**；上下行在 A/B 各自设置 |
| congestion | `false` | 改变窗口控制行为，建议单独比较 |
| readBufferSize / writeBufferSize | `2 / 2` MB | `writeBufferSize` 影响发送缓冲；该核心版本的 `readBufferSize` 虽可配置，当前读取窗口并未使用其值 |

当前 Xray 26.3.27 **不支持**旧 mKCP `header`、`seed`，因此不暴露。建议先记录当前成功的基线，再每次只改一个值；调整期间 A/B 数据面会短暂重连，但控制链路仍走原有 CF/VLESS。可在 A 端用 `curl.exe --proxy socks5h://127.0.0.1:10808 https://ifconfig.me` 检查真实业务流量是否恢复。

### B 已集成 x-ui（Linux VPS）

- B **只运行 x-ui Go + x-ui 管理的唯一 Xray**，不启动旧 `python -m mytrn b`；因此不需要单独的 B Python `18882` Web 页面或第二份 Xray JSON。
- 在 x-ui 现有**入站列表 → MyTRN**业务行，填写 A 的 MyTRN `control_token` 和 `vless_uuid`，这些**不是 CF VLESS `26417` 的 UUID**。
- B 的 HTTP 控制接口必须能通过 A 的 CF/VLESS 出站到达；A 注册报文仍是原有 `POST /control/mapping`，包含 A STUN 公网 IP:PORT 和 A 的 TLS 公钥证书。B Go 校验 token、固定证书指纹，公网映射变化时按既定方式重启同一个 Xray。
- B 数据面复用**现有 WARP SOCKS5 UDP `127.0.0.1:40000`**，并主动连接 A 的公网 STUN endpoint；用户网站流量从 B 现有 `freedom` 出站，不经过 WARP 出站网站。

推荐顺序：**先在 B x-ui 配好 MyTRN，并确认原有 VLESS/CF 服务可用；再在 A Web UI 填写现有 CF 节点的 TLS/XHTTP 参数及 B HTTP 地址；最后重启 A Python Agent**。不改动 v2rayN 已有的用户代理分流到 A `10808` 的规则。

## Web UI 与验证

| 功能 | A Windows | B Linux |
| --- | --- | --- |
| Web UI | `127.0.0.1:18881` | 既有 x-ui 面板的入站列表 MyTRN 行 |
| 进程 | `python -m mytrn a` + A 自有 Xray | x-ui Go + x-ui 原有单 Xray |
| 浏览器代理 | `127.0.0.1:10808`（SOCKS5） | 无需对公网监听 |
| 控制面代理 | `127.0.0.1:10909`（Python 专用，Xray VLESS/TLS/XHTTP (packet-up / chrome / h3) 经 CF） | 普通 Go HTTP 控制服务（如 `:18080`） |
| UDP 端口 | `39999`，光猫转发 | B 通过 WARP SOCKS5 UDP 主动连接 A |
| Xray 配置 | `state.a/xray-a.json` | x-ui 原有统一 `bin/config.json` |
| 管理 Web 状态 | STUN 映射、CF 控制注册、Xray、外网出口测试 | MyTRN endpoint、信任证书及配置应用状态 |

修改配置仍可使用 Web JSON 编辑器，**A 的 mKCP 另提供专用调参表单**；字段严格校验，不提供旧 QUIC Agent 兼容字段。仅修改 A mKCP 时自动重启 A Xray 生效，其他配置仍需重启 Agent；mytrn 会先用 `xray run -test` 校验新内核配置再启动子进程。

### 最重要的真实验收

在 A Windows 上执行：

```powershell
curl.exe --proxy socks5h://127.0.0.1:10808 https://ifconfig.me
curl.exe --proxy socks5h://127.0.0.1:10808 -I https://github.com/
```

预期返回 B 的境外出口 IP，B 的 **x-ui 管理的单 Xray 日志**中可以看到 MyTRN 内部 reverse-in 路由到既有 freedom 的网站连接。**不要为了验证数据面而停止 B 整个 x-ui Xray**，以免同时中断既有 VLESS `26417`、`16360`。

A Web UI 还有 **“从 A 验证外网出口”**按钮，实际通过 `socks5://127.0.0.1:10808` 代理访问 `https://api.ipify.org`；只有真实请求成功才显示出口 IP。B Xray 进程 `running`、STUN `OK` 或控制注册 `OK` 均不等于网页代理已经可用。

## 自动恢复行为

- **A STUN 检测**：默认每 20 秒在同一个 UDP `39999` socket 检查真实公网映射，连续两次发现新 endpoint 才确认变更。偶发超时不清空旧 endpoint，也不主动重启 Xray。
- **低频控制**：A 启动和 endpoint 变化时通过**A 自有 Xray 的 CF/VLESS 控制通道**上报，不经过 v2rayN；正常每 30 分钟刷新，长期没收到 B 的 UDP 包时可每 120 秒刷新。控制面不会高频轮询。
- **B 自动应用变更**：B x-ui Go 保存 token 认证的 endpoint 与 A TLS 证书，只在真实变更时调度 **x-ui 原有单 Xray** 配置重建/整进程重启。B Go 进程本身仍在提供控制 HTTP 服务。
- **Xray 进程**：A Python 只负责 A 自己的子进程意外退出后的自动重新启动，**不管理 B 的 Xray**；B x-ui 沿用既有的进程管理。
- **Windows UDP**：A 的 UDP 网关禁用 Winsock 的 UDP ICMP `WSAECONNRESET` 行为，防止 B 旧 relay 端口关闭后导致 A UDP socket 与 STUN 接收异常。

## 安全与限制

- **单 A / 单 B，且不是 Windows 服务或 systemd 服务**；进程在当前终端运行，关闭终端后不保证继续运行。
- A 的私钥只保存在 `state.a/a-key.pem`；B x-ui 首次注册固定证书指纹，**以后证书变化将被拒绝**。证书确需更换时，先核实身份，再使用 B x-ui MyTRN 编辑中的“重新信任”流程；不要关闭 TLS 验证。
- 默认 Web UI 仅监听回环地址，配置/状态接口需要 `admin_token`。管理令牌和生成配置不进 Git。不要把 Web UI 的明文 HTTP 直接开放公网。
- 本版 A 浏览器通过 **SOCKS5 TCP CONNECT** 上网，不是系统全局 VPN、TUN、全设备 DNS/UDP 透明代理；建议应用使用 `socks5h` 把域名解析交给 B，防止浏览器本地 DNS 泄漏。
- 当前网关有有限数量的 UDP peer 映射和过期处理，**没有实现公网 DoS 防护或生产级长期抗压**。安全假设仍是你已手动配置的单 A + 单 B 网络环境。
- 本 Python Agent 的自动重连已通过真实 Xray 26.3.27 + **本机模拟 STUN/SOCKS5 UDP** 回归。用户提供的跨境成功日志证明的是此前 PoC 的实网路径；**正式 Agent 新增的自动 STUN 注册和故障恢复还需要在真实 A/B 上复核**，不应宣称已完成长稳验收。

## 测试

```powershell
python -m pip install -r requirements.txt
python -m pip install pytest
python -m pytest -q
```

设置 `MYTRN_XRAY_BIN` 为真实 Xray 26.3.27 可执行文件时，增加本机完整运行自动化测试：**真实的 A Xray CF/VLESS/TLS/XHTTP (packet-up / chrome / h3) 控制出站** → 本机真实 Xray 模拟既有 CF VLESS 服务 → 测试用 B HTTP 控制 API；数据面使用模拟 WARP SOCKS5 UDP/STUN、真实 VLESS reverse/mKCP/TLS、实际本地 HTTP 代理请求、B 测试 Xray 重启和 NAT endpoint 变化恢复。**此集成测试的 B 是独立 Python 测试服务，不等同于你真实 VPS 上 x-ui Go 的部署验收。**

原来的自写 Python QUIC/TCP 转发代码已整体删除；[`poc/xray26327/`](poc/xray26327/) 留作可复现的架构验证材料。A 保留 Python，B 使用已有的 x-ui Go 集成；不增加 A Go 迁移或旧控制 SOCKS5 兼容通道。
