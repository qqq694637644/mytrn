# MyTRN v3 — 原生 Hysteria 2 / Brutal + 固定本地 UDP 动态中继（不使用 frp）

MyTRN 是独立的反向上网架构：B（VPS）经现有 WARP SOCKS5 UDP 主动访问 A（境内 Windows）的 STUN 公网映射；A 本地 SOCKS5 上网经同一条反向链路到 B 的 Xray freedom 出口。**不依赖 frp/frps，运行时不保留 mKCP 兼容模式。**

## 固定架构

```text
A Windows
  v2rayN / 浏览器 → A Xray SOCKS5 127.0.0.1:10808
  A Xray VLESS reverse-out → Hysteria 2 / QUIC / Brutal (listen 127.0.0.1:40001)
              ↑
  Python UDP 0.0.0.0:39999 (STUN + opaque QUIC packets; router forwards 39999)
              ↑
  B Xray VLESS reverse-in → Xray Hysteria 2 outbound
      → 固定 UDP 127.0.0.1:41001
      → B x-ui Go MyTRN 动态中继（只热更新 A 公网 IP:Port）
      → WARP SOCKS5 UDP ASSOCIATE 127.0.0.1:40000
              ↓
  B existing freedom → internet (MyTRN website traffic)
```

- 控制面保持独立：A Python 自己的 Xray 控制 SOCKS5 `127.0.0.1:10909` → VLESS/TLS/XHTTP（packet-up / chrome / h3）→ Cloudflare → B x-ui Go HTTP `POST /control/mapping`（默认 127.0.0.1:18080）。
- Python 负责 STUN、固定 UDP 数据网关端口 **39999**、配置、Web 状态和专用 Xray 子进程，不实现 QUIC、拥塞控制、TCP 复用或者重传。
- VPS B 使用 x-ui「入站列表 → MyTRN」业务行（x-ui PR #16）；**不运行第二份 B Python Agent，也不启动第二个 B Xray**。历史独立 B Python 仅供本机集成测试。
- **x-ui MyTRN Go 中继**仅在 VPS 回环 UDP 127.0.0.1:41001 接收 B Xray QUIC，向 WARP SOCKS5 UDP ASSOCIATE 的回环 relay 发送带 A 公网目标 IP:Port 的 SOCKS5 UDP 帧。原来 Xray 内部的 `mytrn-warp` outbound 和 `dialerProxy` 均已删除，不保留兼容模式。WARP 失败立即丢包，不得原生 VPS 直连 A 的公网映射。
- A 的 STUN 检测到新公网映射后继续经原有 CF/VLESS/XHTTP 认证控制面上报；B 更新 Go 中继的目标地址，**不重新生成、重启或热替换整个 Xray**。本次不增加并行备用 QUIC 链路，也不更改 A 的 Xray/Python 数据面；A 端沿用已经升级到 Hy2 的配置即可。
- A Xray 的 `security=tls`、证书指纹固定校验、B 的 `disableSystemRoot=true` 和 `allowInsecure=false` 全部保留。

## 破坏式升级（旧 mKCP → Hy2-only）

**先升级两端代码，再同时应用配置。升级窗口内数据面会中断。不要仅升级一侧。**

A 端务必复用现有 `config.a.json` 和 `state.a` TLS 身份；不要重新执行 `init a`，否则 UUID、Token、证书身份都可能变化。

在 A 端 Python 工程根目录执行：

```powershell
python -m mytrn migrate-hy2 --role a --config config.a.json
```

迁移只由你明确执行一次：删除 `mkcp_*` 字段，加入默认 `hy2_up_mbps=64` 和 `hy2_down_mbps=64`，原样保留 token、UUID、CF 节点、端口等内容。会生成私有备份 `config.a.json.before-hy2.json`，若备份已存在则拒绝覆盖。**启动运行时不接受旧 mKCP 配置，也不做协议回退。**

B 端 x-ui 使用 MyTRN 新表单，原 mKCP 参数不再参与任何运行时配置。首次读到新增 SQLite Hy2 字段为空时使用 64/64 默认值；旧 mKCP 列不再使用。

### 从已安装的 Hy2 v2 升级到固定本地中继 v3

这一次 **只需更新 VPS x-ui**，A 端 Python/配置/UDP 39999 均不必修改。由于 B 的 Xray 出站地址从公网改到 127.0.0.1:41001，首次应用新架构需要重启一次 Xray；之后 A 公网 IP/端口改变不会再触发 Xray 重启。不要同时运行旧的 `mytrn-warp` Xray SOCKS outbound 作为兜底。

升级前备份 x-ui 数据库和现有证书。确保 `127.0.0.1:41001/udp` 没有被其他进程占用、B 的 WARP SOCKS5 端口已在回环监听。MyTRN 的 WARP SOCKS5 地址**只能**设置为 IPv4 回环地址，不能使用 VPS 公网网卡。

## Hysteria 2 Brutal 参数

两端独立配置，名称均为本端视角：

| 节点 | 字段 | 默认 | 含义 |
|---|---|---|---|
| A Windows | `hy2_up_mbps` | 64 | A→B 的发送目标 |
| A Windows | `hy2_down_mbps` | 64 | B→A 的接收目标 |
| B x-ui | `hy2UpMbps` | 64 | B→A 的发送目标 |
| B x-ui | `hy2DownMbps` | 64 | A→B 的接收目标 |

均限制 1–10000 Mbps。Brutal 会按收发双方的目标协商发包速率，丢包补偿时的实际 pacing 可能大于配置值；它不是硬性运营商限速或已测得的业务吞吐。

Xray 26.3.27 使用 `network: hysteria` + `hysteriaSettings: {version:2, auth:...}`，并通过 `finalmask.quicParams` 的 `congestion: brutal`、`brutalUp`、`brutalDown` 来设置发送器；TLS `alpn` 必须是 `["h3"]`。QUIC PMTU 探测关闭、连接空闲超时设为 15 秒、B 端保活 5 秒（A/B 均生成这两项），以减少旧 reverse 会话滞留；这些数值不代表已经完成真实线路参数优化。

Hy2 Auth 由已有、双方一致的控制 Token 派生：

```text
HMAC-SHA256(key = UTF8(control_token),
            message = UTF8("mytrn-hysteria2-auth-v1"))
→ lowercase hex
```

不增加需要人工同步的第二份密钥；修改 Token 时 A、B 必须同时更新并重新连接，Go B 会调度 Xray 重启。

A Web 地址默认 `http://127.0.0.1:18881`；只变更 Hy2 Mbps 时，Python 可执行 `xray run -test` 后自动更换**A 自己**的 Xray 子进程，UDP 39999 网关不重启。B x-ui 修改 Brutal Mbps、VLESS UUID、认证 Token 或 TLS 证书仍会重启唯一 Xray；**修改 A NAT 映射或 WARP SOCKS5 地址/端口，仅热更新 Go 中继或重新协商 SOCKS5 UDP，不重启 Xray**。

## 初始化及控制节点

初次部署：

```powershell
python -m pip install -r requirements.txt
python -m mytrn init a
python -m mytrn a
```

A 的本机 Web 中填写已经能访问 CF 的 VLESS XHTTP 控制节点信息：CDN 地址与端口、控制 UUID、TLS SNI、Host、Path、mode（通常 packet-up）、fingerprint（chrome）、ALPN（h3），以及 B 的可达 HTTP 控制地址与端口。可使用 Web「检测 CF → B 控制链路」验证可达性。**不使用直连 B 的公网 IP 作控制回退。**

B x-ui 入站列表的 MyTRN 中填入 A 的 `vless_uuid` 和 `control_token`、配置本机 WARP SOCKS5 :40000 并启用。B 控制 HTTP 必须通过 A 的 CF/VLESS 出站可达；不要想当然认为本机回环可由代理直接访问。

用户请求的真实检查：

```powershell
curl.exe --proxy socks5h://127.0.0.1:10808 https://ifconfig.me
curl.exe --proxy socks5h://127.0.0.1:10808 -I https://github.com/
```

应返回 B 网站出口 IP；不要将 WARP 建连成功、STUN 映射成功或 Xray 进程 running 当作端到端成功。MyTRN 只提供 SOCKS5 TCP CONNECT，不是 TUN/VPN 或全设备 UDP 透明代理；请用 `socks5h` 在远端解析域名。

## 测试和已知界限

```powershell
python -m pip install -r requirements.txt pytest
python -m pytest -q
$env:MYTRN_XRAY_BIN = 'C:\path\to\xray.exe'
python -m pytest -q tests/test_agents.py -k full_python_agents_real_xray
```

CI/本机测试使用真实 Xray 26.3.27、模拟 WARP SOCKS5 UDP、模拟 STUN/CF 控制端点；它们不会证明真实跨境 UDP 包长/吞吐或七天稳定性。回归必须覆盖：控制注册、端到端 SOCKS5、B Xray 重启恢复、运营商映射变化、WARP 失败时无原生直连。

**这是破坏式升级，MyTRN v3 不提供 mKCP 或 Xray 旧 `dialerProxy` 备用线路。历史 PoC 留在 `poc/` 只作离线复现，不参与当前部署。**
