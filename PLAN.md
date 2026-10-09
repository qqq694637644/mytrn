# mytrn — Xray-core 反向代理上网架构与实施计划

> **状态：Python Agent 已在 PR #1 实现并通过本机真实 Xray 26.3.27 集成测试；新增自动编排尚需 A/B 跨境实网复核。** 本文件是项目唯一有效的实施依据。旧 Python QUIC/B→A 内网转发代码和测试已整体删除，不留兼容层；后续在 Python 真实环境验收后，仅将 mytrn 编排层迁移 Go，始终复用 Xray-core。

## 1. 唯一业务目标

**让中国境内 A 的浏览器和应用通过境外 VPS B 访问互联网，解决 A 无法直接访问被 GFW 限制的境外资源的问题。**

已知约束：B 公网 IP 可能被 GFW 阻断，A 无法稳定直连 B；但 B 本机 WARP SOCKS5 可通过 UDP 主动访问 A 经 STUN 发现的公网 NAT 映射。因此使用**B 主动建立隧道，A 借用 B 的互联网出口**的反向模型。

必须始终区分两种方向：

- **物理隧道建立方向**：`B → WARP SOCKS5 UDP → A 的公网 UDP endpoint`。B 是发起方，A 是接收方。
- **用户上网请求方向**：`A 浏览器 → A 本地 SOCKS5 → 已建立的反向隧道 → B freedom → 目标互联网服务`。应答沿原路返回 A。

**这不是让 B 访问 A 的内网服务，也不是让 B 开一个公网端口供 A 主动连接。** 成功标准是 A 真实通过 B 出口访问外网，而非仅仅 STUN、UDP、mKCP 或 VLESS 握手成功。

### 完整业务路径

```text
                           中国 A / Windows
   浏览器 / curl / 应用
          |
          | SOCKS5（使用目标域名，避免本地 DNS 泄漏）
          v
   A Xray SOCKS5 127.0.0.1:10808
          |
          | 路由到本机 VLESS reverse-out（反向出口）
          v
   A Xray VLESS/mKCP + TLS 入站（仅 127.0.0.1:40001）
          ^
          | UDP 双向本地转发（mytrn 只转发数据报，不解 mKCP/VLESS）
          v
   A mytrn UDP 入口 0.0.0.0:39999  <---- STUN（同一 UDP socket）
          ^
          | A 路由器 UDP 39999 -> A LAN IP:39999
          | 电信上层 NAT1 公网 IP:PORT（由 STUN 实测）
          |
          | Cloudflare/WARP UDP 出口
          |
   B WARP 本地 SOCKS5 UDP 127.0.0.1:40000
          ^
          | SOCKS5 UDP ASSOCIATE / 经证实可承载 mKCP 数据报
          |
   B Xray VLESS/mKCP + TLS 出站（主动拨入 A）
          |
          | VLESS 原生 reverse-in 接收 A 的代理请求
          v
   B Xray freedom（B 发起目标 TCP 连接并解析目标域名）
          |
          v
   Google / GitHub / 其他境外互联网服务
```

图中箭头在同一条已建立的数据通道内双向传输；**B 的 WARP 只负责“B → A”的隧道承载**。默认的网站出口是 B 的 `freedom`（即 VPS 正常网络），**不是默认让网站流量经 WARP SOCKS5 出口**；两者不能混淆。

## 2. 已确认的环境、已有证据与待证明部分

### A（中国）

- Windows，Python 3.13；内网 IP 固定；先前测试程序固定 UDP `39999`。
- 家庭光猫/路由器长期保留 `UDP 39999 → A 内网 IP:39999` 的端口转发，防火墙由用户手动管理。
- 家用路由器前还有电信上层 NAT。历史 STUN 测到过 `119.98.144.218:55781`，这里的 `55781` 是**运营商侧公网端口**，不能误写成 `39999`；历史值只作说明，运行时不得硬编码。
- 已有 v2rayN `127.0.0.1:10810` 经 VLESS/Cloudflare CDN 能访问 B 的 HTTP 控制面。该通道只用于低频控制，不承载用户网页流量。

### B（境外）

- Linux VPS；公网 IP 可能被 GFW 封锁，但 B 自身可以直接访问互联网。
- B 现有 WARP 是 `socks5://127.0.0.1:40000` **本地 SOCKS5 代理**，不是宿主机默认路由；不得假设安装 WARP 后所有 Xray UDP 都会自动经过 WARP。
- 既有探测已验证 B 的 WARP SOCKS5 `UDP ASSOCIATE` 与 STUN 可用，并验证 `B → WARP UDP → A 的 NAT endpoint → B` 双向收发 `5/5`。

### 已验证的最小架构与仍未完成的实网验证

以下实证以用户指定的 **Xray-core v26.3.27（提交 `d2758a0`）** 为准，测试代码见 [`poc/xray26327/`](poc/xray26327/)：

1. **本机真实 Xray 验证已通过**：B VLESS/mKCP/TLS 出站的 `sockopt.dialerProxy` 使用 Xray SOCKS5 UDP outbound，通过 Python **mock SOCKS5 UDP ASSOCIATE** 双向传输 mKCP 数据报；A/B 都运行真实 Xray 26.3.27 可执行文件，A 本地 SOCKS5 请求经 VLESS 原生反向代理到 B `freedom`，成功获取 HTTP 响应。它证明原生路径在模拟 UDP 代理下可用，**不是**在真实 Cloudflare WARP 已验证。
2. **本机 STUN/UDP 入口验证已通过**：A 由一个 Python UDP socket 进行 STUN 绑定与不透明 UDP 数据报往返，内部 Xray 监听另一回环 UDP 端口。此证明没有覆盖电信 NAT/家庭路由器的映射行为。
3. **仍未验证**：B 现有 `127.0.0.1:40000` **真实 WARP SOCKS5 UDP** 与选定 Xray mKCP 在跨境长 RTT/丢包下的完整业务流、relay 生命周期；A 的实际电信上层 NAT 映射能否持续接收 B 经 WARP 发来的 mKCP 数据报；A 通过 B 真实访问 HTTPS 网站、DNS 泄漏、自动恢复和稳定性。

三者严格区分；不能把本机 mock 或仅仅 `xray run -test` 成功冒充**真实跨境网络可用**。只有第 3 项得到可复现的现场日志之后，才能宣称完成阶段 0 全部门槛并开始 Go 正式编排。

## 3. 架构边界：复用成熟核心，不重造网络协议

### Xray-core 完整负责

- A 的本地 SOCKS5 代理入站和代理请求解析；B 的目标域名解析与 `freedom` 出站。
- VLESS 身份认证、**原生 reverse-in/reverse-out**、路由和多请求连接管理。
- mKCP 的可靠传输、丢包重传、顺序控制、拥塞控制和传输参数。
- mKCP 上的端到端 TLS 加密与证书验证；选定版本双方一致且 `allowInsecure` 必须为 `false`。
- SOCKS5 UDP 链式拨号能被实测支持时，直接由 Xray 完成，不编写自己的 mKCP/KCP、SOCKS5 代理或 TCP-over-UDP 传输层。

### mytrn 仅负责 Xray 无法直接覆盖的编排（Python 首版，后续 Go）

- **A 边界 UDP 入口**：独占 UDP `39999`；用**同一个 socket** 做 STUN，并把 mKCP 数据报双向转给本机 Xray。只识别 STUN 事务、维护 UDP 对端映射，不解析或重写 mKCP/VLESS 内容。
- **动态 endpoint 注册**：A 获得公网 IP:PORT，通过已有 CF/VLESS 控制链向 B 低频上报；B 缓存和持久化 endpoint。
- **Xray 配置生成与生命周期**：Web 配置、严格校验、启动/停止、故障重试、endpoint 变化触发 B 侧 Xray 配置更新和受控重启；不承诺 Xray 不支持的热更新能力。
- **健康状态与验证**：分层显示 STUN、控制面、WARP UDP、Xray 反向隧道和 A 经 B 上网的可用性，记录恢复耗时；不拿“心跳在线”冒充“代理可用”。

**严禁出现的自研内容**：Python QUIC Agent、手写 KCP、TCP stream 帧、TCP 重传/窗口、SOCKS5 CONNECT 解析、业务端口反向映射框架或自造代理协议。这些属于 Xray-core 的责任。

## 4. 原生 VLESS 反向代理的角色配置

需要使用**同一组选定版本 Xray-core**，固定版本和配置生成规范，不采用跨版本猜字段的方式。Xray 官方当前模型：

| A：中国，被动接收 B | B：美国，主动连接 A |
| --- | --- |
| `socks` inbound：本地 `127.0.0.1:10808`，供 A 用户访问外网 | `vless` outbound：目标为 A 动态公网 IP:PORT，`method: mkcp` |
| `vless` inbound：本机 `127.0.0.1:40001`，mKCP/TLS；供 B 的反向连接接入 | outbound 上配置 `reverse: {tag: "reverse-in"}`；自动建立反向通道 |
| VLESS 入站用户配置 `reverse: {tag: "reverse-out"}` | `routing`: 把 `reverse-in` 收到的请求送到 B 的 `freedom` |
| `routing`: 只把 A 本地 SOCKS5 的业务请求送往 `reverse-out` | `freedom`：从 B 访问外部网站；按域名策略在 B 侧 DNS 解析 |

关键点：A 是 VLESS/mKCP **服务端**，B 是 VLESS/mKCP **拨号端**；但真正代理上网的源头是 **A 本地用户**。不得沿用旧计划里的“B 本地 TCP 端口 → A 内网目标服务”。

- VLESS 和 mKCP 为上下层，不是两次独立拨号；**`TLS over mKCP` 是可用的 Xray 组合**。由 Xray 自行完成端到端加密、证书检查与 UUID 身份认证；禁止裸 VLESS 或以 WARP 代替端到端加密。
- 独立生成强随机 UUID、TLS 密钥/证书；B 校验 A 证书（受信 CA 或事先固定的证书），证书变化不自动无条件信任。
- **v26.3.27 Windows 特性**：该版本的 `transport/internet/tls/config_windows.go` 在默认设置下不会把自定义自签 CA 放入根证书池。本 PoC 的 B TLS 配置明确使用 `disableSystemRoot: true` 并加载 A 的自签 CA，仍保持 `allowInsecure: false`；本机真实 Xray 已证实此设置可完成 TLS 握手。不允许为了绕过证书失败而关闭验证。
- **TLS 服务端身份与动态 IP 解耦**：B 的拨号目标 IP:PORT 随 STUN 更新，但配置的 TLS `serverName` 与被验证的 A 证书身份必须稳定，不能把每次变化的公网 IP 当作证书名称，也不能为绕过证书错误关闭验证。
- A 的 SOCKS5 默认只监听 loopback。B `freedom` 不应放任来自无关入站的未知请求成为开放代理；为反向通道明确路由与出口策略，避免路由环路。
- **用户 DNS 必须有明确方案**：A 应用优先发送域名到 SOCKS5（如 `socks5h`）；B 侧解析和连接目标。第一版验收包含 DNS 泄漏检测；A 自身 STUN/控制链解析属运行基础设施流量，与用户浏览请求区别对待。
- 第一版先完成 **SOCKS5 TCP CONNECT + HTTPS** 的真实上网，不把不经过代理的应用 UDP/QUIC、TUN 或全局透明代理能力写成已完成。将来是否支持 SOCKS5 UDP / XUDP 必须另做验证。

## 5. A 的单端口 UDP/STUN 边界设计

必须让**真正面向电信 NAT 的端口**和**STUN 探测源端口**相同：

```text
               电信 NAT 公网 IP:PORT
                         |
      家用路由器 UDP 39999 -> A UDP 39999
                         |
              mytrn UDP ingress（独占）
                  /                  \
       STUN request/response       mKCP 数据报
            本地处理                    |
                               127.0.0.1:40001
                                 A Xray mKCP
```

- A 端 **mytrn 持有唯一 `0.0.0.0:39999` UDP socket**，Xray mKCP inbound 仅绑定 `127.0.0.1:40001`；不得尝试让独立 STUN/Xray 进程都绑 39999，也不得拿另一个本地端口的 STUN 结果冒充 39999 的映射。
- STUN 从该 socket 发起，响应须按消息结构、transaction ID 与预期 STUN 服务器来源校验后识别；剩余报文作为不透明 UDP payload 处理，不做内容猜测。
- 对 B 的实际 WARP UDP 来源建立**临时、可过期的双向映射**：从外部来源收到的数据转给内部 Xray；Xray 的回复通过原 `39999` socket 发回对应的外部来源。保持 KCP 所见的本地代理 peer 地址稳定，避免不同来源互相串流；对端切换可重新建表/会话。
- 保持 UDP 数据报边界，不拼接、不拆成 TCP 字节流、不改写 mKCP 帧；检查 Windows 多 socket、MTU、超时、映射表淘汰、异常输入与进程关闭后的资源释放。
- STUN 只表明**对 STUN 服务器的观测映射**。电信上层是否 endpoint-independent mapping 不能仅凭“NAT1”标签断言；必须实际用 B 的 WARP 出口向该地址打包，确认同一映射可达。
- A 的原有光猫/路由器 `39999 -> 39999` 规则保留不变，不要求再映射 `40001`。Xray 的 `40001` 不能对公网开放。

## 6. B 的 WARP UDP 承载：先证明，再落实现有内核接法

**第一优先选项**：由 B Xray 的 VLESS/mKCP 出站使用 `streamSettings.sockopt.dialerProxy` 指向现有 SOCKS5 outbound（上游为 `127.0.0.1:40000`），使所有发往 A endpoint 的 mKCP UDP 经 WARP 代理，而不是 B 主机公网 IP 直发。

**Xray 26.3.27 的本机集成已验证此选项可行**：A/B 真实 Xray 通过模拟 SOCKS5 UDP relay 完成 mKCP/TLS/VLESS reverse 及 A SOCKS5 → B freedom HTTP 请求。但与真实 B WARP 的组合仍为独立门槛；需用真实 WARP 出口来源、业务响应和重连日志确认，不可只凭模拟结果宣称 WARP 实网通过。

**决策门槛**：

1. 使用固定的 Xray-core 版本在本机模拟 SOCKS5 UDP 和真实 B WARP SOCKS5 分别验证上述组合。
2. 若 Xray 原生 SOCKS5 链式拨号的 mKCP UDP 路径实测正常，**不增加自研 B UDP 中转**。
3. 若原生路径被证实不兼容，仅评估增加一个**只承载不透明 UDP 数据报的 B 本地 SOCKS5 UDP 适配器**：Xray mKCP 发往本地适配端口，适配器负责 SOCKS5 `UDP ASSOCIATE`、数据报封装/解封装和对端地址；**仍由 Xray 负责一切代理、VLESS/mKCP 和可靠性**。适配器必须有自己的集成测试和必要性证据后才能纳入实现。
4. 若两种不改变核心责任划分的方式均不可行，则此项标记为技术阻塞，回到架构决策；**不能偷偷让 B 直连被封 IP，也不能改成 A 主动拨 B、换 Python QUIC 或引入第三台 VPS 来“让测试通过”。**

## 7. 低频控制面与动态 endpoint 生命周期

控制面继续复用 **A v2rayN → VLESS/Cloudflare CDN → B** 的既有可用链路，和 B 的 WARP 数据面严格隔离。控制面失败不应阻塞当前健康的已建立数据连接。

```text
A 启动/断线恢复：同 UDP :39999 进行 STUN
    -> 获得 public_ip:public_port
    -> HTTP POST JSON /control/mapping（通过 A 的 v2rayN SOCKS5）
    -> B 验证 token、版本、节点 ID/时间戳等
    -> 持久化最新有效 endpoint
    -> endpoint 真正变化时渲染 B Xray 配置并受控重启拨号进程
    -> B 经 WARP SOCKS5 UDP 主动重新连接 A
```

- **只支持一个 A 和一个 B**；单节点身份与控制密钥独立于 Xray VLESS UUID/TLS 证书。HTTP 控制 API 仅供该节点使用；强随机 token 放 HTTP header，配置与日志不泄漏秘密。
- 启动时注册；定期 STUN 检测（初始建议 15–30 秒，连续两次确认变化）；只在 endpoint 变化时触发立即更新。必要时低频 refresh 确保 B 状态可恢复，正常不进行几秒一次的 HTTP 轮询。
- B **只有在 endpoint 实际变化时**重新生成 Xray 客户端目标并受控重启相关实例；相同 endpoint 的 refresh 不应打断已建立的代理连接。不得假定 Xray 能无中断热改 mKCP 目标。
- B 持久化最近一次**经认证**的 endpoint，B 重启后可先使用它尝试拨号；失败后继续等待 A 的新注册。A 网络变化、STUN 暂时失败、控制链断线时保留最后已知状态但标记可能过期，不把单次失败当成映射变更。
- 关键路径故障重试应有退避和日志；**目标是 endpoint 变化后几分钟内恢复实际 A→外网访问**，实际指标以端到端探测测量，不以“配置已更新”计时结束。
- 控制面与本机 Web UI 不向公网默认开放。若现有 CDN/VLESS 后端只能经特定 B 地址访问控制端口，应明确最小暴露范围并验证防火墙，而不是为方便一律绑定 `0.0.0.0`。

## 8. 进程部署与 Web 管理

### 实例边界

- 原有 A 的 v2rayN 和 B 的 CF/VLESS 既有节点负责**控制链**，不能为了部署 mytrn 去覆盖或破坏它们的配置。
- B 现有 WARP SOCKS5 服务保持独立，其代理地址可配置。
- A/B 的 mytrn 分别管理**自己的专用 Xray-core 实例**，避免覆盖既有 Xray 节点端口、配置或重启其服务；Xray 可执行文件路径、配置目录、日志目录和启动参数明确设置。
- Windows/Linux 均以当前前台 CLI 开始运行；暂不做系统服务、守护进程安装、自动更改 Windows 防火墙或路由器规则。

### Web UI（两端都需要）

- 默认只监听 `127.0.0.1`，管理权限需要随机 token 或等价本地鉴权；远程使用 SSH 端口转发等安全方式。用户配置入口是 Web UI，不要求日常编辑底层 Xray JSON。
- **A 页面**：本机 SOCKS5 端口、UDP `39999`、内部 Xray 端口、STUN、控制链代理与地址、TLS 身份、当前 NAT endpoint、注册/反向通道/代理状态。
- **B 页面**：WARP SOCKS5 地址、控制监听、对应的 Xray 实例、当前 A endpoint、Xray reverse/freedom 状态与重拨信息。
- 用**角色化、严格校验的 mytrn 配置模型**渲染两端 Xray JSON；不要让普通用户输入相互矛盾的 Xray 原始选项。预览配置、语法验证、原子保存、失败不覆盖可用配置；用户确认应用后显式受控重启 mytrn 管理的 Xray 进程。
- 运行状态至少拆为：`STUN_OK`、`CONTROL_REGISTERED`、`WARP_UDP_OK`、`XRAY_REVERSE_READY`、`PROXY_E2E_OK`。只能把通过真实 SOCKS5→外网测试的状态称为代理可用；不可仅凭进程存活或 QUIC/KCP 握手显示“已连通外网”。
- 不提交真实配置、证书私钥、令牌、状态文件和日志到 Git；测试用参数与生产配置隔离，未知字段直接报错。不引入旧 Agent 配置的自动转换层。

## 9. 安全与网络故障边界

- A 的公网 UDP 入口可被任意来源探测：Xray 入站必须进行 VLESS/TLS 身份校验；UDP 入口不应替代协议认证，且要限制无效流量的资源消耗。
- WARP 加密范围不等于 A/B 两端的端到端安全；因此必须启用 Xray TLS（或经明确验证的内核等价安全机制，本版选用 TLS），禁止将 `allowInsecure` 设为 true 作为通过测试的手段。
- A SOCKS5 只给本机使用；B `freedom` 应是反向业务专用出口且受路由约束，防止意外开放代理、内网探测和循环转发。
- 目标域名尽可能由 B 解析，测试 DNS 泄漏；A 本机 STUN 和控制面自身必需的 DNS 解析不代表浏览器 DNS 泄漏。
- mKCP over WARP 可能有更高开销及 MTU 限制，选定参数前要做丢包、长 RTT、最大报文尺寸和 HTTPS 大文件测试；不以“WARP 已提供重传”作为理由忽略 UDP 丢包。
- 出错时能清楚区分：A 路由器映射、电信上层 NAT、STUN、CF/VLESS 控制链、B WARP SOCKS5 UDP、Xray mKCP/TLS、VLESS reverse、B `freedom`/DNS、A 本地 SOCKS5。任何一层验证失败都要定位该层，不能自动切换错误方向来掩盖故障。

## 10. 实施顺序与通过标准（架构门槛优先）

### 阶段 0 — 技术可行性实证（先做，不先造 Web 框架）

1. 锁定 Windows/Linux **同版本** Xray-core；验证 `xray run -test` 和官方 `reverse`、`mkcp`、`tls` 配置。
2. 单独验证 Xray 的 **VLESS reverse**：在实验网络 B 主动接 A，A SOCKS5 `socks5h` 请求最终由 B `freedom` 出网；只测试正确的用户流向。
3. 单独验证 B 的 **mKCP → WARP SOCKS5 UDP**：实际检查 `dialerProxy` 是否完整适配 UDP；不通过则按第 6 节先出证据再决策薄适配器。
4. 单独验证 A 的 **UDP 39999 STUN + 不透明 mKCP 转发**：STUN 映射与真实 Xray 数据来自同一个对外端口，并确认 WARP 出口确实可访问该公网映射。
5. **门槛：**四项均可复现，才进行完整应用/界面开发；无法验证不标记通过。

### 阶段 1 — Python Agent：自动注册与真实代理上网

- **已实现（Python）**：A UDP 同端口 STUN/不透明 mKCP 网关；A 经 SOCKS5/VLESS/CF 的 HTTP POST 低频注册；B 保存 endpoint/首次固定 A 证书；A/B 用严格配置生成 v26.3.27 Xray JSON 并独立监督子进程；A/B 本地 Web JSON 配置与状态，A 网页按钮可实测代理外网出口。
- **已通过本机集成**：真实 Xray v26.3.27、模拟 WARP SOCKS5 UDP、模拟控制链 SOCKS5 TCP、STUN、A 本地 SOCKS5 经 B freedom 访问本地 HTTP、B Agent/子进程重启、NAT 映射变化和 STUN 间歇性超时。Windows UDP 错误处理也已覆盖。
- **下一步必须在用户真实 A/B 部署这套完整 Python Agent**（不是仅 PoC），核验低频控制、配置、B 独立 Xray 自动重拨、HTTPS 网页数据从 B 出网。不重造任何业务代理协议。
- 在真实 A 机器配置 `SOCKS5 127.0.0.1:10808`，验证：

  ```bash
  curl --proxy socks5h://127.0.0.1:10808 https://ifconfig.me
  curl --proxy socks5h://127.0.0.1:10808 https://www.google.com/
  curl --proxy socks5h://127.0.0.1:10808 https://github.com/
  ```

- **必须证实**这三个请求从 B 发出，外部站点看到的出口属于 B 的预期境外网络，且浏览器请求不会在 A 本地直接绕过代理。再做 DNS 和 HTTPS 大响应验证。

### 阶段 2 — 真实网络恢复、长稳与 Python 版本验收

- A 公网 IP/端口变化后：由 STUN 发现、控制链上报、B 更新 Xray 目标并重拨，最终 A SOCKS5 恢复上网。
- 验证 B WARP SOCKS5 relay 重启、B Xray 进程重启、A agent 重启、A 断网恢复、B 缓存旧 endpoint 的行为。
- Web 编辑、严格配置校验、保存/重启、状态和 A 主动外网探测已在 Python 中实现；后续以实网日志检验用户可用性，按实测修正必要的编排错误。
- **恢复验收**：目标为映射变化后几分钟内恢复真实 HTTPS 请求，记录发现、上报、重拨和请求成功各阶段时间。

### 阶段 3 — 长稳通过后迁移 Go

- 至少 6 小时及 24 小时实网运行，记录成功率、重连次数、RTT、吞吐、内存、DNS 泄漏与异常恢复。
- Windows/Linux CI 验证配置渲染、严格校验、STUN/UDP 入口和控制 API；可以用模拟 WARP SOCKS5 但**必须附加真实跨境链路的验收记录**，不得拿模拟测试代替。
- Python 真实网络验收通过之后，**只用 Go 重写 UDP/STUN、控制面、Web UI、配置生成与 Xray 进程管理**；用相同证书/端口和端到端测试作行为等价验证，继续使用同版本 Xray-core。不得重造 VLESS/mKCP/TLS/代理协议。
- 只有架构、测试、README、示例配置及真实行为一致，并且满足 A→B→外网目标，PR 才具备合并条件。

## 11. PR #1 当前代码状态与迁移规则

- 同一 PR 已**删除**旧 `mytrn/tunnel.py`、`mytrn/network.py`、`mytrn/agent.py` 及其过时 QUIC 测试，改由 `mytrn/udp.py`、`control.py`、`xray.py`、`web.py`、`app.py` 构成薄 Python 编排层；已有 PoC 保留以复现内核方案。
- README 和 A/B 配置示例同步更新为 Python + Xray 的 A→B→外网唯一方向；未为旧配置、旧协议引入兼容模式。
- 不更改已有可用的 CF/VLESS 控制链和 WARP SOCKS5 运行方式；不为通过测试引入第三方 C 服务器、新 VPN、强制 A 主动连被封 B 公网 IP，或用户未要求的全局透明代理。
- **用户真实 A/B 上的 Python 自动控制/恢复及长稳尚未验收，PR #1 保持 OPEN、不得合并。**

## 12. 参考依据

- Xray 官方：[VLESS 反向代理示例](https://xtls.github.io/document/level-2/vless_reverse.html)；[VLESS 入站](https://xtls.github.io/config/inbounds/vless.html)；[VLESS 出站](https://xtls.github.io/config/outbounds/vless.html)。
- Xray 官方：[mKCP](https://xtls.github.io/config/transports/mkcp.html)；[传输与 TLS 组合](https://xtls.github.io/config/transport.html)；[Sockopt `dialerProxy`](https://xtls.github.io/config/transports/sockopt.html)。
- Xray 源码：[mKCP 拨号器](https://github.com/XTLS/Xray-core/blob/main/transport/internet/kcp/dialer.go)；[底层拨号器](https://github.com/XTLS/Xray-core/blob/main/transport/internet/dialer.go)。
- [Xray-core issue #6046](https://github.com/XTLS/Xray-core/issues/6046)：说明 mKCP 与 `dialerProxy` 存在版本和实现相关问题；因此本计划把 B→WARP UDP 的组合列为**需实测**，不根据源码推断上线成功。
