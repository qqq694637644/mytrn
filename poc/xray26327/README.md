# Xray-core v26.3.27 原生反向代理 / mKCP / WARP SOCKS5 UDP PoC

## 验证目的（仅验证关键架构，不做完整 mytrn）

> **目标：境内 A 通过境外 B 访问互联网；但底层连接必须由 B 经 WARP SOCKS5 UDP 主动连接 A 的 NAT 公网映射。**

本实验只用 Python 管理一个 UDP 入口并生成配置，不实现任何自研 KCP、QUIC、TCP 转发或 SOCKS5 业务代理。所有业务通信由 **原生 Xray-core v26.3.27** 处理。

```text
业务：A 应用 -> A Xray SOCKS5 127.0.0.1:10808
     -> Xray VLESS reverse-out -> [反向通道] -> B VLESS reverse-in
     -> B freedom -> 外网（从 B 出口访问网站）

底层：B Xray mKCP/TLS 出站 -> dialerProxy=warp-socks5
     -> B 的现有 WARP SOCKS5 UDP 127.0.0.1:40000
     -> Cloudflare/WARP UDP 出口 -> A 经 STUN 发现的公网 IP:PORT
     -> 家用光猫路由器固定映射 UDP 39999 -> A Windows:39999
     -> Python UDP gate -> 127.0.0.1:40001 -> A Xray VLESS/mKCP 入站
```

**B 的已有 x-ui 和 CF/VLESS 节点不要停机或覆盖。** 本 demo 运行独立 Xray 进程：B 不监听公网服务端口，不重写 x-ui 的配置、不改其 systemd 服务。其上游 WARP SOCKS5 正常服务即可。

PoC **不包含** Web UI、CF/VLESS 动态 endpoint 注册、生产级抗攻击 UDP 会话管理或完整断线恢复。它验证后这些控制/运维功能才适合整体迁移到 Go。该目录不会修改仓库现存旧 QUIC Agent，后续正式改造需整体替换旧实现。

## 已做的源码核查

以用户指定 fork 的 [Xray-core v26.3.27](https://github.com/qqq694637644/Xray-core/tree/v26.3.27) 为准；该 tag 对应提交 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

1. [`transport/internet/kcp/dialer.go`](https://github.com/qqq694637644/Xray-core/blob/v26.3.27/transport/internet/kcp/dialer.go) 的 mKCP 拨号使用 `internet.DialSystem`。
2. [`transport/internet/dialer.go`](https://github.com/qqq694637644/Xray-core/blob/v26.3.27/transport/internet/dialer.go) 中 `dialerProxy` 的 UDP 会被重定向到指定 SOCKS 出站。
3. [`proxy/socks/client.go`](https://github.com/qqq694637644/Xray-core/blob/v26.3.27/proxy/socks/client.go) 的 UDP outbound 使用 SOCKS5 `UDP ASSOCIATE`。
4. 该版本 VLESS 原生反向代理由 **A inbound 用户的 `reverse: {"tag":"reverse-out"}`** 和 **B outbound 顶层 `settings.reverse: {"tag":"reverse-in"}`** 配对，不使用老的 `reverse.bridges/portals`。用户 x-ui 仓库中旧的 mKCP Portal/VMess 配置与这个 VLESS 机制不同。
5. **Windows TLS 特例**：[`transport/internet/tls/config_windows.go`](https://github.com/qqq694637644/Xray-core/blob/v26.3.27/transport/internet/tls/config_windows.go) 默认不把自带证书载入根 CA 池；对于此 PoC 自签证书，B `tlsSettings` 必须指定 `disableSystemRoot: true`，仅信任生成的 A CA。仍保留 `allowInsecure: false` 和固定 `serverName: mytrn-a.test`。

## 第一步：在本机验证真实 Xray 内核（无需海外 VPS）

准备 Xray 26.3.27 可执行文件（A Windows 可用 Xray-windows-64；Linux 则为 Xray-linux-64），以及 Python 3.13：

```bash
python -m pip install -r poc/xray26327/requirements.txt
python poc/xray26327/demo.py selftest --xray "C:\\tools\\xray\\xray.exe"
```

Linux 示例：

```bash
python3 poc/xray26327/demo.py selftest --xray /usr/local/bin/xray
```

`selftest` 会自动：

- 在临时目录生成自签 TLS 证书、唯一 UUID 和 A/B Xray 配置；运行两个**真实 Xray 26.3.27 进程**。
- 启动纯 Python mock SOCKS5 UDP relay 来模拟 B 的 WARP SOCKS5 **数据报接口**，但不会宣称它与 WARP 的所有行为相同。
- 启动 Python UDP gate（模拟 A 的公网入站 UDP 39999）和本地 HTTP 回显站点（模拟 B 可连接的外网目标）。
- 在 A SOCKS5 发起真正的 `CONNECT localhost:...`，把**域名**交给 B 解析；只有通过 reverse+mKCP/SOCKS5 UDP 到达 B freedom 后才能拿到测试站点的随机响应。
- 对 A 和 B 生成的 Xray 配置执行 `xray run -test -config ...`；配置检查通过与数据测试通过会分别输出状态。

成功示例（在 Windows 用官方发布的 v26.3.27，提交 `d2758a0` 实测）：

```text
CONFIG_CHECK: PASS (Xray v26.3.27 A/B)
SOCKS_TO_B_FREEDOM: PASS (83 response bytes)
SOCKS5_UDP_ASSOCIATE: PASS (1 relays)
XRAY_VLESS_REVERSE_MKCP_OVER_SOCKS5_UDP: PASS
The B mock is local-only; real Cloudflare WARP/GFW route NOT verified.
```

通过这个实验可以确认**无需另写 QUIC/KCP/TCP 代理**。它不能代替 B 真实 WARP 和中国电信 NAT1 实测。

## 第二步：真实 A / B 分机部署验证（手动 endpoint）

### 2.1 在 A Windows 初始化一次

在 **A** 的项目根目录执行（输出目录会生成私钥，必须保密；不要提交或上传）：

```powershell
python -m pip install -r poc/xray26327/requirements.txt
python poc/xray26327/demo.py generate --output poc/xray26327/_private --endpoint 127.0.0.1:39999 --b-ca-path /opt/mytrn-poc/a-cert.pem
```

`--endpoint 127.0.0.1:39999` 只是**生成初始 B 配置时的占位值**，严禁直接拿它在 B 上做实网连接。实际 A 的公网 endpoint 要以接下来 STUN 的输出为准。

生成文件：

```text
poc/xray26327/_private/
  a.json          A 的 Xray 配置
  b.json          B 的 Xray 配置，需要修改真正的 STUN endpoint
  gate.json       A 的 Python 单 UDP 39999 入口配置
  a-cert.pem      A 公钥证书（B 应持有一份）
  a-key.pem       A 私钥（只留在 A，绝不能发到 B）
```

注意：A 的 Xray TLS 证书路径在 JSON 中使用生成时的**绝对路径**；请把最终输出目录放在真正运行的位置，不要随意移动。

### 2.2 启动 A 的 UDP gate + 专用 Xray

确认 A 光猫映射 `UDP 39999 -> A LAN IP:39999` 正常，目标端口未被别的进程占用；**不要改变原来的控制面 v2rayN 10810**。

```powershell
python poc/xray26327/demo.py gate --config poc/xray26327/_private/gate.json --xray "C:\\tools\\xray\\xray.exe"
```

该命令会启动**独立的 A Xray 进程**，并使用 Python 进程独占 UDP 39999：

```text
A UDP ingress=('0.0.0.0', 39999) -> Xray=('127.0.0.1', 40001)
STUN_MAPPING: <实际公网IP>:<实际公网端口>
```

这两个 UDP 端口的用途不一样：`39999` 必须做路由器映射且同 socket STUN；`40001` 只给 A 本地 Xray 使用，无需映射公网。A 的浏览器代理入口是另一个**TCP** 端口 `127.0.0.1:10808`。

### 2.3 给 B Linux 准备专用配置，不碰现有 x-ui

把 A 的 `b.json`、`a-cert.pem` 两个文件单独拷贝到 B 的 `/opt/mytrn-poc/`（需要你自己安全传输）。**不要拷贝 `a-key.pem`。**

在 **B** 上编辑 `b.json` 的目标地址为 STUN 打印的公网 endpoint（改动其它配置不会自动改变 A 的证书指纹）：

```bash
python3 demo.py set-endpoint --config /opt/mytrn-poc/b.json --endpoint <A公网IP>:<A公网端口>
```

`demo.py` 可以直接从仓库拷贝到 B 后执行。如果尚未复制 Python demo，也可仅修改 `b.json` 的 `b-reverse-dial.settings.address/port`；这是实验阶段的手动控制面替代。

确认 `b.json` 中：

```json
"sockopt": { "dialerProxy": "warp-socks5" }
```

以及：

```json
"tlsSettings": {
  "serverName": "mytrn-a.test",
  "allowInsecure": false,
  "disableSystemRoot": true,
  "certificates": [{"certificateFile": "/opt/mytrn-poc/a-cert.pem", "usage": "verify"}]
}
```

然后通过**专用 Xray 26.3.27** 进程运行，不从 x-ui 面板覆盖现有配置：

```bash
/path/to/xray version
cd /opt/mytrn-poc
/path/to/xray run -test -config b.json
/path/to/xray run -config b.json
```

B 的 PoC Xray 无公网入站，只经现有 WARP SOCKS5 `127.0.0.1:40000` 发起到 A 的 UDP 连接。若你需要观察是否真走 WARP，可对照 A 的 UDP gate 接收来源与 B 的 Xray `dialerProxy` 日志；确认不是 B VPS 原始公网 IP 直连。

### 2.4 真实代理验收（在 A Windows）

B 启动并完成反向连接后，回到 **A**：

```powershell
curl.exe --proxy socks5h://127.0.0.1:10808 https://ifconfig.me
curl.exe --proxy socks5h://127.0.0.1:10808 https://github.com/ -I
```

通过标准：A 代理能拿到外网响应，公网出口属于 B VPS 的预期网络（因为 B 默认由 `freedom` 出站），并且当关闭 B 专用 Xray 后请求应失败，而非 A 不经代理直连。这是比“STUN PASS / mKCP 已握手”更重要的业务验收。

## 版本与安全限制

- **严格要求 Xray 26.3.27**。用户 fork 的 `v26.3.27` tag 与官方发布同 commit `d2758a0`；本地用官方 Windows 26.3.27 SHA256 校验过的二进制实测。
- 此 Python PoC 并未实现生产级 UDP peer 身份验证、严格速率限制或可靠的 NAT peer 切换逻辑，**只适合短时实验，不可长期将 `39999` 无监控暴露公网运行**。由 Xray TLS/VLESS 验证业务身份不意味着 UDP gate 本身能抵御任意 UDP DoS。
- PoC TLS 证书**有效期仅 30 天**，过期需要重新生成并同步 B 所信任的证书；不可使用 `allowInsecure: true` 绕过。
- 当前未实现 A 动态 endpoint 的低频 CF/VLESS 注册与自动重拨。完整版本实现目标是**保留 Xray 内核，仅把这一小层 UDP/STUN/控制面/进程管理迁移 Go**。
- `x-ui` 自带的 mKCP Portal fixture 当前选择 VMess，不等同于此 PoC 的 VLESS reverse；二者不可将配置片段混用。迁移时决定如何与 x-ui 的已有进程安全共存。
- 无论本地 PoC 成功与否，**中国电信 NAT1 ↔ B 的真实 WARP UDP 可用性仍须现场验证**。

## 自动化测试

不需要 Xray 二进制即可运行 STUN 同 socket、网关不透明数据报转发、配置生成、证书信任与 endpoint 更新的单元测试：

```bash
python -m pytest -q poc/xray26327/test_demo.py
```

指定 Xray 26.3.27 可执行文件后，增加真实 A/B Xray+模拟 WARP SOCKS5 UDP 回显端到端测试：

```powershell
$env:MYTRN_XRAY_BIN="C:\\tools\\xray\\xray.exe"
python -m pytest -q poc/xray26327/test_demo.py
```

此测试只验证底层功能，不会调用你的 B 上已运行的 x-ui，也不访问真实境外网络。
