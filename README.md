# mytrn

**B 经 WARP SOCKS5 UDP 主动连接 A 的 NAT1 公网映射**。控制面通过现有 CF/VLESS 链路低频上报 A 的公网 endpoint；数据面不经过 VLESS，而使用 WARP SOCKS5 UDP 承载加密 QUIC TCP 流。无需再租第三台 VPS。

## 当前功能（MVP）

- A：Windows / Python 3.13，固定 UDP 39999；与 STUN 共用同一 socket；支持两次确认 endpoint 变更、启动注册、30 分钟兜底 refresh、网络异常重试。
- B：Linux / Python 3.10+，`socks5://127.0.0.1:40000` UDP ASSOCIATE；B **主动**向 A 建立 QUIC 会话；连接断开/代理关闭后自动重拨。
- **真实 TCP 端口转发**：B 本机 `127.0.0.1:监听端口` → QUIC/WARP/SOCKS5 UDP → A → 白名单中配置的目标 TCP 地址和端口，支持多条 TCP 连接。
- 安全：QUIC/TLS 加密，B 从经鉴权的控制面接收并固定（pin）A 的证书。**QUIC TLS 握手后必须先用 `data_psk` 完成会话认证**，否则不会进入 `DATA_ACTIVE`；每条转发流还会使用 HMAC、时间戳和 nonce 鉴权；仅能访问 A 显式允许的端口。
- 配置通过 A、B 各自的**本机 Web 界面**修改，保存在 `config.a.json` 和 `config.b.json`；修改后重启生效。
- 不实现系统 TUN、不建立任何公网 HTTP/SOCKS 业务入口；B 本机监听仅是把 **B 本机的指定 TCP 流量** 交给已主动拨通的隧道。

### 网络方向

```text
A Windows:39999 --家庭光猫 UDP 39999 端口转发-- 电信 NAT1 public_ip:public_port
             ^                                      |
             |                                      |
             +--------- WARP UDP egress <--- B SOCKS5:40000  <--- B agent 发起 QUIC

A --v2rayN SOCKS5:10810 --VLESS/CF CDN--> B HTTP:18080  (仅注册/变化/兜底)
```

端口含义必须区分：本地 UDP `39999` ≠ STUN 得到的公网 UDP 端口。B 使用后者发包。例如历史探测出现过 `119.98.144.218:55781`；这**只是历史观测值**，运行时不应写死。

## 安装

A Windows PowerShell 和 B Linux 均使用：

```shell
python -m pip install -r requirements.txt
```

推荐 Python 3.13；`aioquic` 用于加密可靠 QUIC 流，`aiohttp` 用于本地 Web UI/控制面。

## 首次初始化（只做一次）

A：

```powershell
python -m mytrn init a
python -m mytrn a
```

B：

```bash
python3 -m mytrn init b
python3 -m mytrn b
```

`init` 创建**带随机高强度 token**的真实配置文件，终端只在初始化时打印 Web 管理 token。**不要将生成的 config 文件提交 GitHub。** 注意 A/B `init` 生成各自独立的密钥，需要把 **A 的 `control_token`、`data_psk` 原样复制到 B**（`admin_token` 不需要复制）。

Web UI 默认：

- A: `http://127.0.0.1:18881`
- B: `http://127.0.0.1:18882`

Web 页面输入初始化时打印的 `admin_token`，读取 JSON 配置，修改后点击保存，**Ctrl+C 结束并重启 agent** 使配置生效。Web UI 默认只监听本地；远程管理 B 请使用 SSH 本地端口转发，**不要直接将 Web UI 暴露公网明文 HTTP**。

### A 的关键参数（Web UI）

```json
{
  "local_udp_bind": "0.0.0.0",
  "local_udp_port": 39999,
  "stun_servers": ["stun.cloudflare.com:3478"],
  "control_socks5": "socks5://127.0.0.1:10810",
  "control_host": "B控制面地址",
  "control_port": 18080,
  "targets": { "demo": { "host": "127.0.0.1", "port": 8080 } }
}
```

这里仅展示相关字段；Web UI 保存必须保留完整 JSON 中的其他安全字段。

**A 家庭光猫必须长期保持 UDP 39999 → A 固定内网 IP:39999 的端口映射。** Windows 防火墙由你自行管理。`targets` 是允许访问的 A 本机或内网 TCP 服务白名单，`id` 由 B 的 `forwards[].id` 引用。不要放宽为任意地址/端口。

### B 的关键参数（Web UI）

```json
{
  "control_bind": "0.0.0.0",
  "control_port": 18080,
  "warp_socks5": "socks5://127.0.0.1:40000",
  "forwards": [
    { "id": "demo", "listen_host": "127.0.0.1", "listen_port": 18081 }
  ]
}
```

同样保留完整 JSON 其他字段。若已有 VLESS/CF 出站能在 B 本机连接 `127.0.0.1:18080`，优先将 `control_bind` 保持默认 `127.0.0.1`。若你已经验证只能让 v2rayN 通过 B 公网 IPv4 连到 `18080`，可设为 `0.0.0.0`，但需要限制防火墙来源、使用强 control_token；A 必须**确实通过 VLESS/CF** 走代理到 B。不要把 HTTP 控制 API 当成直接公网 API。

### 测试真实转发

例如 A 有 HTTP 服务：`127.0.0.1:8080`，A 的 `targets.demo` 对应它；B `forwards.demo` 监听 B 本机 `127.0.0.1:18081`。

在 B 本机执行：

```bash
curl -v http://127.0.0.1:18081/
```

数据在 B 侧进入一个本地 TCP socket，但隧道连接始终是 **B → WARP SOCKS5 UDP → A**。目标 TCP 连接由 A agent 连接到 A 本机/内网允许的目标服务，而不是打开 B 公网端口。更换目标只需修改 A 的 `targets` 和 B 的 `forwards`，保存并重启两端 agent。

## 运维与恢复

- A 启动后从固定 UDP socket 发 STUN；正常情况按约 15 秒维持并检测映射；连续两次发现新 endpoint 后自动通过控制面上报 B。
- A 不做频繁 HTTP status poll。正常情况下只在启动、endpoint 变化、数据面长期静默或 30 分钟兜底刷新时上报。
- B 保存最近登记的 A endpoint 和 TLS 证书到 `state.b/registration.json`，重启后可用旧 endpoint 立即尝试连接，不必等待控制面轮询。
- B QUIC PING/PONG、代理断线检测和重连；A/B 进程重启、WARP SOCKS5 断线会自动重建会话。A endpoint 变化确认后会关闭旧 QUIC 会话，B 在收到映射更新后重新认证并连接。
- 若 A 的证书/私钥遗失导致证书更新，B 会拒绝自动替换被固定的证书。**先通过安全带外渠道核验 A 的新证书指纹，再由管理员备份并删除 B 的 `state.b/registration.json` 以重新建立信任。**
- 第一版 agent 为前台命令运行；暂不创建 Windows 服务或 systemd 服务。

## 现有验证与限制

`python -m pytest -q` 在本机使用模拟 STUN、SOCKS5 UDP relay、真实 A/B QUIC 和 TCP echo 服务执行端到端测试。额外包括连续 100 次短连接、40 次失败转发后服务恢复、协议头与大块 TCP 数据合包、错误 `data_psk` 拒绝、模拟 NAT endpoint 变化及模拟 WARP UDP relay 中断后的重新连通；**真实的电信 NAT1 + CF/VLESS + WARP 跨境链路仍需现场验证**。

- 首版只支持固定**TCP** 目标端口转发，不是任意 SOCKS 代理或 UDP 端口转发，也不是全局 TUN。
- 第一版不提供实时热更新。Web UI 保存配置后重启进程才应用。
- 本地内测通过不能替代真实长稳、延迟、丢包、断网重连测试。
- 当前应用层有并发 stream 上限和单 stream 待发送数据缓冲限制，但尚未完成高并发吞吐和长时间性能验证，也没有 QoS 或多节点调度；不可据此宣称生产级长期高吞吐稳定性。
- 配置采用严格键名校验；未知键（包括历史测试开关 `allow_private_endpoint`）直接报错，不保留旧协议兼容。

详见 [`PLAN.md`](PLAN.md)。
