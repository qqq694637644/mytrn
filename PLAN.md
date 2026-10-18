# MyTRN v3 — Hysteria 2 / Brutal + Go 回环 UDP 动态中继

> 本文是当前 MyTRN 的唯一实施依据。mKCP 方案已退役，不保留运行时兼容、协议探测或原生直连回退。完整部署手册见 [README.md](README.md)。历史 [poc/xray26327/](poc/xray26327/) 仅供复现旧方案，不参与正式启动。

## 目标及约束

- A（中国 Windows）本地浏览器 / v2rayN → A Xray SOCKS5 :10808 → VLESS reverse-out → Xray 原生 Hysteria2/QUIC/Brutal 数据面。
- B（VPS）Xray Hy2 只拨本地固定 `127.0.0.1:41001` → x-ui Go UDP 中继动态选择 A 的公网 `IP:Port` → **必须经 WARP SOCKS5 UDP ASSOCIATE** :40000 → A UDP 39999 → A Python 透明 UDP 网关 → A Xray 本地 UDP :40001。
- 经 reverse-in 到 B 的网站业务继续由 B 既有 Xray **freedom** 出站；WARP 负责 B→A 隧道承载，网站 freedom 与强制 WARP 隧道是两条不同路径。
- A Python 继续使用独立控制：自身 Xray SOCKS5 :10909 → CF/VLESS/TLS/XHTTP（h3，packet-up）→ x-ui Go `/control/mapping`。A 公网 IP、端口和证书低频注册；B 使用单个现有 Xray 进程及 x-ui 的 MyTRN 配置合并。
- 官方 frp/frps 不参与；不增加公网 B 入站端口；不编写 QUIC、拥塞算法、TCP mux 或 SOCKS5 中转。
- A 控制 Token 同时作为 HMAC-SHA256 的密钥派生 Hy2 Auth（固定上下文 `mytrn-hysteria2-auth-v1`）；两端使用现有 TLS 身份固定验证 + ALPN h3，绝不使用 `allowInsecure=true`。
- 配置只接受 `hy2_up_mbps` / `hy2_down_mbps`（A）和 `hy2UpMbps` / `hy2DownMbps`（B），范围 1–10000 Mbps，默认 64/64。Brutal 依据对端接收目标协商；发包补偿不限于应用 payload 速率。

## 代码交付范围

1. **mytrn Python A**：移除 mKCP 热路径配置、Web 控件与字段；为 VLESS reverse inbound 生成 `network=hysteria`，`hysteriaSettings` 和 `finalmask.quicParams`。保持 A Windows UDP 39999 STUN 与 gateway socket 不变。修改数据面 Mbps 时只重启 A 专用 Xray，不重启 Python 网关。
2. **x-ui Go B**：在现有 MyTRN 行显示 Hysteria2/Brutal、B 端 64/64 目标 Mbps；VLESS reverse outbound 保持 Hysteria/TLS h3，但**只使用固定本地 UDP :41001**，删除 Xray WARP SOCKS5 outbound 和旧 `dialerProxy`；由 x-ui Go 进程进行 WARP SOCKS5 UDP ASSOCIATE，与认证控制上报热切换公网目标，Xray 进程不重启。Token 更换仍触发 Xray 更新。
3. **一次性破坏式升级**：A 显式 CLI `migrate-hy2` 将旧 `mkcp_*` 字段改成 `hy2_*`，自动私有备份旧配置，拒绝备份覆盖；保留所有身份/控制/STUN 参数。没有旧协议静默 fallback。
4. **可验证性**：Python 与 Go HMAC 测试向量一致；各自输入边界/认证/WARP/TLS 校验；Xray 26.3.27 真二进制 `run -test`，模拟 WARP SOCKS5 UDP 的 A→B SOCKS5 请求及 B Xray 进程重启/重连测试；GitHub Linux CI 编译、测试、UI 回归。

## 验收准则

- A SOCKS5 `127.0.0.1:10808` 实际完成网站的请求、响应；只验证 STUN 成功或 Xray 进程运行不算数据面成功。
- Xray 两端日志确有 Brutal 激活；上下行速率更改后按本端目标生效；64/64、128/192 都可以配置，无残留 `kcpSettings`。
- 在 30s/60s 抖动内恢复目标是缩短重连时长，需记录首次接通与 B 重启、Xray 崩溃、NAT endpoint 变化后的端到端恢复耗时。失败不可视为完成验收。
- 使用模拟 WARP SOCKS5 UDP 验证 Go 中继只向回环发送 UDP、端点热更新不会改写 Xray 配置和重启 Xray、WARP 断线或 SOCKS5 BND 非回环地址时不发生任何原生直连回退。真实 VPS 抓包仍需验证 WARP 强制。
- 不干扰 B 现有 x-ui Caddy、VLESS 26417 和其他旧业务入口；B MyTRN 状态来自实际活动配置而非单纯进程存活。
- 因两端切换不兼容，必须在同一维护窗口升级；单边升级会中断数据面，但独立 CF 控制链仍能正常注册。

## 尚需现场测试

跨境真实 WARP UDP 包长、路径 MTU、实际 throughput、重连稳定性、七天持续运行不是本地 mock 或 CI 能够证明的内容。使用本人实际网络测量，与 frpc/XTCP 另行比较；不得把本地模拟速度当成跨境测速承诺。
