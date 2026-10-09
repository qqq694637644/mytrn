# mytrn — A 经 B 的反向代理上网（Python 版）

**核心目的：让中国境内 Windows A 的应用通过境外 VPS B 访问互联网，即使 B 公网 IP 在国内无法直接访问。**

```text
建立隧道：B Xray → B WARP SOCKS5 UDP :40000 → 电信 NAT 公网 IP:PORT → A UDP :39999
用户上网：A 浏览器 → A Xray SOCKS5 :10808 → VLESS reverse/mKCP/TLS → B freedom → 网站
控制面：A → v2rayN SOCKS5 :10810 → CF CDN/VLESS → B HTTP :18080
```

Xray-core v26.3.27 **原生负责** SOCKS5、VLESS reverse、mKCP、TLS、重传和代理连接。mytrn 的 Python 代码**仅**负责 A 的单 UDP 端口网关/STUN、低频注册、B 的 endpoint 配置更新、独立 Xray 进程和本地 Web 配置。**没有自写 QUIC/KCP/TCP-over-UDP。**

已在用户真实的电信 NAT1 + 美国 VPS WARP 上用独立 [Python PoC](poc/xray26327/README.md) 验证 B 连接 A 和 A 代理请求经 B `freedom` 到 `ifconfig.me:443`。**本正式 Python Agent 版本已通过本机真实 Xray + 模拟 SOCKS5 UDP/STUN/控制链的集成测试；自动恢复机制尚未在你的真实 A/B 环境完成验收。**

## 安装（A 和 B）

需 Python 3.13（A 已有）和单独的 **Xray-core v26.3.27** 二进制。此程序不会修改/重启 B 上 x-ui 已管理的 Xray、VLESS 或 WARP 服务。用独立目录、独立端口运行专用 Xray 子进程。

在仓库根目录运行：

```bash
python -m pip install -r requirements.txt
```

### 初始化并配置 A（Windows）

```powershell
python -m mytrn init a
python -m mytrn a
```

- `init a` **只需一次**，生成 `config.a.json`，其中有随机 `control_token`、`vless_uuid`、`admin_token`；**不要将这些凭据提交 GitHub**。初始化时终端会打印 Web 管理 token。
- 在 A 浏览器打开 `http://127.0.0.1:18881`，输入 `admin_token` 后读取配置。
- 设置 `xray_bin` 为 A 本机 **v26.3.27** Xray 的绝对路径，如 `C:/Tools/Xray/xray.exe`。
- 保留 `udp_bind=0.0.0.0`、`udp_port=39999`、`xray_udp_port=40001`、`socks_port=10808`。A 光猫/路由器的 `UDP 39999 → A 固定内网 IP:39999` 规则必须已经生效；**不要映射 40001**。
- 设置 `control_host` 为既有 v2rayN/CF/VLESS **能到达 B 控制 API 的地址**，不是浏览器上网代理地址；`control_socks5` 默认 `socks5://127.0.0.1:10810`，控制端口默认 `18080`。
- 点击保存，然后**退出并重新执行 `python -m mytrn a`**。重启后 A 会用同一个 `39999` UDP socket 做 STUN 并在变化时注册 B。

### 初始化并配置 B（Linux VPS）

```bash
python3 -m mytrn init b
python3 -m mytrn b
```

- B 的本地 Web UI 默认 `http://127.0.0.1:18882`，可通过 VPS 终端或**安全的 SSH 本地端口转发**访问；默认不暴露公网 Web UI。
- 在 B Web 配置中，把 A 配置文件的 **`control_token` 和 `vless_uuid` 原样复制到 B**。这是单 A + 单 B 的认证绑定，不是把 B 的独立 `admin_token` 复制到 A。修改后保存并重启 B。
- 将 `xray_bin` 指向 B 实际使用的**独立 Xray 26.3.27** 文件，如 `/root/xray26327/xray-linux-amd64`，不要修改 x-ui 运行中的二进制文件或服务。
- `warp_socks5` 默认 `socks5://127.0.0.1:40000`，直接复用现有 WARP 本地代理。
- `control_bind` 默认 `127.0.0.1`，`control_port` 默认 `18080`：如果 B 现有 VLESS/CF 控制链能连到 B 的回环接口，**保持回环最安全**。若现有架构确实只能经 B 公网接口访问该端口，可把 `control_bind` 改为 `0.0.0.0`，并用 VPS 防火墙限制访问来源；所有注册仍必须带强随机 token。
- B 首次启动没有 A endpoint 时，会等待控制注册，**不会主动使用被墙的 B 公网 IP 建立业务通道**。成功注册后 B 生成 `xray-b.json`，使用 WARP SOCKS5 UDP 主动拨 A 的 STUN 公网 IP:PORT。

推荐启动顺序：**A/B 两端先执行 `init` → 在 B Web UI 填入 A 的 `control_token` 和 `vless_uuid` 并重启 B → 在 A Web UI 设置控制地址/Xray 路径并重启 A**。如果 B 控制 API 已配置好而 A 还未启动，B 可以先保持前台运行并等待注册。

## Web UI 与验证

| 功能 | A Windows | B Linux |
| --- | --- | --- |
| Web UI（默认仅本机） | `127.0.0.1:18881` | `127.0.0.1:18882` |
| 进程 | `python -m mytrn a` | `python3 -m mytrn b` |
| 浏览器代理 | `127.0.0.1:10808`（SOCKS5） | 无需对公网监听 |
| UDP 端口 | `39999`，光猫转发 | B 通过 WARP SOCKS5 UDP 主动连接 A |
| 专用 Xray 配置 | `state.a/xray-a.json` | `state.b/xray-b.json` |
| 管理 Web 状态 | STUN 映射、控制注册、Xray、外网出口测试 | 最新 A endpoint、证书指纹、Xray 状态 |

修改配置通过 Web JSON 编辑器完成；字段严格校验，**不提供旧 QUIC Agent 兼容字段或自动升级**。保存后需重启 Agent 才会生效；mytrn 会先用 `xray run -test` 校验生成的内核配置，再启动自己的子进程。

### 最重要的真实验收

在 A Windows 上执行：

```powershell
curl.exe --proxy socks5h://127.0.0.1:10808 https://ifconfig.me
curl.exe --proxy socks5h://127.0.0.1:10808 -I https://github.com/
```

预期返回 B 的境外出口 IP，B 的专用 Xray 日志中可看到 `reverse-in -> b-internet` 及 `freedom` 主动连接目标。**要验证代理流量真的经 B 出网**：临时停止 B 的 mytrn（不要停止 x-ui），A 上同样的代理请求应当失败。

A Web UI 还有 **“从 A 验证外网出口”**按钮，实际通过 `socks5://127.0.0.1:10808` 代理访问 `https://api.ipify.org`；只有真实请求成功才显示出口 IP。B Xray 进程 `running`、STUN `OK` 或控制注册 `OK` 均不等于网页代理已经可用。

## 自动恢复行为

- **A STUN 检测**：默认每 20 秒在同一个 UDP `39999` socket 检查真实公网映射，连续两次发现新 endpoint 才确认变更。偶发超时不清空旧 endpoint，也不主动重启 Xray。
- **低频控制**：A 启动和 endpoint 变化时通过现有 v2rayN/CF/VLESS 上报；正常每 30 分钟刷新，长期没收到 B 的 UDP 包时可每 120 秒刷新。控制面不会高频轮询。
- **B 自动应用变更**：保存最近一次经过 token 认证的 endpoint 与 A TLS 证书；只有 IP 或端口**真的变化**才验证新配置并受控重启 B 的独立 Xray。B Agent 重启能读回保存的 endpoint 继续主动拨号。
- **Xray 进程**：A/B 自有子进程意外退出时，mytrn 自动尝试重新启动；不会管理或影响 x-ui 的 Xray。应用层业务隧道重连由 Xray 原生机制负责。
- **Windows UDP**：A 的 UDP 网关禁用 Winsock 的 UDP ICMP `WSAECONNRESET` 行为，防止 B 旧 relay 端口关闭后导致 A UDP socket 与 STUN 接收异常。

## 安全与限制

- **单 A / 单 B，且不是 Windows 服务或 systemd 服务**；进程在当前终端运行，关闭终端后不保证继续运行。
- A 的私钥只保存在 `state.a/a-key.pem`；B 首次注册固定证书指纹，**以后证书变化将被拒绝**。需带外核实后手动删除 B `state.b/registration.json` 并重启来重新信任；不要关闭 TLS 验证。
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

设置 `MYTRN_XRAY_BIN` 为真实 Xray 26.3.27 可执行文件时，增加 A/B 完整运行自动化测试（控制 SOCKS5 TCP、模拟 WARP UDP、STUN、HTTPS 基础设施除外的本地 HTTP 代理请求、B 进程重启、NAT endpoint 变化、偶发 STUN 失败）。CI 会在 Windows/Linux 下载固定 SHA256 的官方 Xray 26.3.27 后运行。

原来的自写 Python QUIC/TCP 转发代码已整体删除；[`poc/xray26327/`](poc/xray26327/) 留作可复现的架构验证材料。后续正式迁移 Go 时，**只重写编排层**，继续复用 Xray 内核、相同数据方向和实际测试标准。
