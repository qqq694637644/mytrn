# mytrn — Xray-core 反向代理上网项目

**唯一业务目标：境内 A 的应用通过境外 VPS B 访问互联网。**

- **底层连接**：B → 本机 WARP SOCKS5 UDP → 境内 A 的电信 NAT 公网映射 → A 的 UDP 39999。
- **用户上网**：A 本地 SOCKS5 → Xray 原生 VLESS reverse/mKCP/TLS → B 的 `freedom` → 境外网站。
- **控制面**：A 复用既有 v2rayN → CF/VLESS → B 链路，低频上报 STUN 映射变化；与用户的正常上网数据分离。

完整架构与验收标准见 [PLAN.md](PLAN.md)。

## 当前进度

当前是**技术验证阶段**，不是已完成的正式代理软件。

- 已以用户指定的 **Xray-core v26.3.27** 源码审查 mKCP `DialSystem`、`sockopt.dialerProxy` 与 SOCKS5 UDP ASSOCIATE 路径。
- 已用**真实 Xray 26.3.27** 进程完成本机 PoC：A SOCKS5 → VLESS 原生 reverse → mKCP/TLS → 模拟 WARP 的 SOCKS5 UDP relay → A UDP gateway → B `freedom`，成功返回 HTTP 响应。
- 已增加独立 STUN/UDP gateway 验证，同一个对外 UDP socket 做 STUN 与不透明 mKCP 报文收发。
- **还没有**在 B 的真实 Cloudflare WARP 与中国电信 NAT1 网络上运行本次 Xray PoC；当前也**没有**实现自动 endpoint 注册或 Go 版正式应用。

### 现在应该使用的代码

**[poc/xray26327/README.md](poc/xray26327/README.md)**：完整 Python PoC 运行命令、A/B 配置步骤、测试、安全边界及现有 x-ui 共存要求。

快速运行本地内核链路验证：

```bash
python -m pip install -r poc/xray26327/requirements.txt
python poc/xray26327/demo.py selftest --xray /path/to/xray-v26.3.27
```

Windows 将 `/path/to/xray-v26.3.27` 替换成 `C:\\...\\xray.exe`。

### 不要部署的旧实现

`mytrn/agent.py`、`mytrn/tunnel.py`、根目录旧 `config.*.example.json` 和 `tests/test_mvp.py` 目前仍来自**已废弃的 Python QUIC + B 本地端口访问 A 内网服务**方案。它们的测试即使全部通过，也**不代表**本项目的 A→B→外网上网目标已实现。

按 `PLAN.md`，在 Python Xray PoC 经真实 B WARP/A NAT 验证之后，应把必要的 UDP/STUN/低频控制面/Web UI 编排迁移到 Go，并**整体删除这些旧实现和测试**。Xray-core 仍独立负责 VLESS、mKCP、SOCKS5 和业务 TCP 连接管理，不重新实现协议。

B 上现有的 [x-ui](https://github.com/qqq694637644/x-ui) 和其已运行的 CF/VLESS/WARP 环境**不由 PoC 修改**。PoC 仅使用独立 Xray 进程和单独配置目录。
