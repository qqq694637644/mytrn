# mytrn 项目计划

## 1. 项目目标

实现一个不租第三方公网控制节点的跨境 UDP 数据通道原型。

核心方案：

```text
控制面：A -> v2rayN SOCKS5 -> VLESS -> Cloudflare CDN -> B
数据面：B -> WARP SOCKS5 UDP -> Cloudflare/WARP 出口 -> A 公网 NAT endpoint
```

控制面只做低频注册、endpoint 变更通知和故障恢复；数据面长期运行，负责 ping/pong、后续 payload 和存活检测。

## 2. 当前已验证事实

已通过实测验证：

```text
CONTROL-PLANE: PASS
STUN-FULLCONE-BOOTSTRAP: PASS / REPORTED
WARP-SOCKS5-UDP-ASSOCIATE: PASS
Bidirectional WARP/SOCKS5 replies: 5/5
WARP-SOCKS5-DATA-PLANE: PASS
OVERALL: PASS
```

A 端观察到数据面来源为 Cloudflare/WARP 出口：

```text
104.28.227.105:29876
```

这说明 B 端通过 `127.0.0.1:40000` WARP SOCKS5 的 UDP ASSOCIATE 发出的 UDP 包，能够命中 A 的公网 NAT endpoint，并且 A 的回复能够回到 B。

## 3. 网络模型

### A 端：境内 NAT 节点

A 是内网机器，固定监听本地 UDP 端口，例如：

```text
A local UDP: 39999
```

家里光猫/路由器配置端口映射：

```text
光猫/路由器 UDP 39999 -> A 内网 IP:39999
```

光猫/路由器前面还有电信上层 NAT1 / full-cone NAT。A 使用同一个 UDP socket 访问 STUN 后，得到 B 端真正应该连接的公网 endpoint，例如：

```text
119.98.144.218:55781
```

注意：`39999` 是 A 内网和家里路由器侧的端口；B 端真正要打的是 STUN 观测到的公网 endpoint，例如 `119.98.144.218:55781`。

### B 端：境外 VPS

B 的公网 IP 可能被 GFW 直接限制，但 A 可以通过 CF/VLESS 控制链访问 B 的 HTTP 控制端。

B 本机存在 WARP SOCKS5 代理：

```text
socks5://127.0.0.1:40000
```

该代理已验证支持 SOCKS5 `UDP ASSOCIATE`，并能通过 WARP 访问公网 STUN。

## 4. 目标架构

```text
                 A 内网机器
              UDP local :39999
                    │
                    │ 路由器端口映射
                    ▼
          光猫/路由器 UDP 39999
                    │
                    │ 电信 NAT1 / full-cone
                    ▼
          A public endpoint: IP:PORT
                    ▲
                    │
                    │ 数据面
                    │
B agent -> WARP SOCKS5 UDP -> Cloudflare/WARP egress

控制面：
A agent -> v2rayN SOCKS5 -> VLESS -> CF CDN -> B control HTTP
```

## 5. 设计原则

1. **控制面低频化**
   - A 启动时注册一次。
   - endpoint 变化时重新注册。
   - 可选每 10~30 分钟 refresh 一次，防止 B 重启后丢失状态。
   - 不做高频 status poll。

2. **数据面常驻化**
   - B 通过 WARP SOCKS5 UDP 向 A 当前 endpoint 发 ping/payload。
   - A 回复实际 packet source。
   - 数据面负责 RTT、丢包、连续失败次数和存活状态。

3. **公网 endpoint 以 STUN 实测为准**
   - A 固定绑定本地 UDP 端口。
   - A 使用同一个 socket 访问 STUN。
   - 只有 STUN endpoint 变化时才触发控制面上报。

4. **不租第三方 C 节点**
   - 不引入独立公网 rendezvous VPS。
   - 现有 CF/VLESS 到 B 的链路承担最小控制面职责。

5. **失败可定位**
   - 区分控制面失败、STUN 失败、WARP SOCKS5 UDP 失败、A endpoint 失效、路由器端口映射失败。

## 6. A agent 计划

A agent 职责：

```text
1. 固定绑定 UDP local-port，例如 39999。
2. 使用同一个 socket 做 STUN。
3. 获取公网 endpoint，例如 119.98.144.218:55781。
4. 通过 CF/VLESS 控制面注册给 B。
5. 周期性 STUN 检查 endpoint 是否变化。
6. endpoint 未变时不访问控制面。
7. endpoint 变化时重新注册。
8. 接收 B 的 UDP 数据面包并回复。
```

建议参数：

```text
--key <shared-secret>
--local-port 39999
--stun stun.cloudflare.com:3478
--control-socks5 socks5://127.0.0.1:10810
--control-host <B-control-host>
--control-port 18080
--stun-check-interval 30
--register-refresh-interval 1800
--endpoint-change-confirm 2
```

endpoint 变化确认逻辑：

```text
1. 每 30 秒做一次 STUN check。
2. 如果新 endpoint 与当前注册 endpoint 不同，记录为候选 endpoint。
3. 连续 2 次得到同一个新 endpoint 后，确认变更。
4. 通过控制面向 B 重新注册。
```

## 7. B agent 计划

B agent 职责：

```text
1. 启动 HTTP 控制面，等待 A 注册 endpoint。
2. 保存当前 A endpoint。
3. 连接本机 WARP SOCKS5：socks5://127.0.0.1:40000。
4. 使用 SOCKS5 UDP ASSOCIATE 建立 UDP relay。
5. 向 A endpoint 发送 ping/payload。
6. 接收 A 回复，统计 RTT、丢包和连续失败次数。
7. endpoint 失效时进入 degraded 状态，继续等待 A 重新注册。
```

建议参数：

```text
--key <shared-secret>
--control-bind 0.0.0.0
--control-port 18080
--warp-socks5 socks5://127.0.0.1:40000
--ping-interval 5
--probe-timeout 5
--max-failures 3
```

B 状态机：

```text
WAIT_ENDPOINT
  等待 A 注册 endpoint

DATA_ACTIVE
  通过 WARP SOCKS5 UDP 与 A ping/pong 或传输 payload

DATA_DEGRADED
  连续 ping 超时，旧 endpoint 可能失效
  继续低频探测旧 endpoint，同时等待 A 新注册

RECONNECTED
  收到新 endpoint 或旧 endpoint 恢复，回到 DATA_ACTIVE
```

## 8. 控制面 API 草案

### `GET /register`

A 启动时调用，声明节点在线。

```text
key=<shared-secret>
node=<node-id>
```

### `GET /mapping`

A 上报或更新公网 UDP endpoint。

```text
key=<shared-secret>
node=<node-id>
nat_ip=<public-ip>
nat_port=<public-port>
local_port=<local-udp-port>
reason=startup|changed|refresh
```

### `GET /status`

仅调试使用，生产模式建议关闭或限制访问。

返回示例：

```json
{
  "node": "a-node-1",
  "endpoint": "119.98.144.218:55781",
  "data_state": "DATA_ACTIVE",
  "last_register": "...",
  "last_data_seen": "...",
  "rtt_ms": {
    "min": 120,
    "avg": 180,
    "max": 300
  }
}
```

## 9. 数据面包格式草案

探测阶段继续使用文本包，便于调试：

```text
PING <key> <seq> <timestamp_ns>
PONG <key> <seq> <timestamp_ns> <observed_src_ip> <observed_src_port>
```

后续改为二进制帧：

```text
magic       4 bytes
version     1 byte
type        1 byte
flags       2 bytes
session_id  8 bytes
seq         8 bytes
timestamp   8 bytes
payload_len 2 bytes
payload     N bytes
auth_tag    16 bytes
```

包类型：

```text
0x01 PING
0x02 PONG
0x03 DATA
0x04 ACK
0x05 CLOSE
```

## 10. 安全计划

探测阶段可以使用共享 `key` 匹配。长期运行需要增强：

```text
1. 控制面使用长随机 token。
2. 数据面使用 session key。
3. 数据包加入 HMAC，防止伪造。
4. 加入 timestamp / nonce，降低重放风险。
5. B control bind 到 0.0.0.0 时必须使用强 token。
6. /status 默认关闭或仅本机访问。
7. 日志不打印 token、密钥或完整敏感配置。
```

## 11. 验证计划

### 11.1 已完成

```text
A -> CF/VLESS -> B 控制面：通过
A STUN 获取公网 endpoint：通过
B WARP SOCKS5 UDP ASSOCIATE：通过
B 通过 WARP SOCKS5 UDP 命中 A endpoint：通过
A 观察到 Cloudflare/WARP 出口来源：通过
双向 UDP probe 5/5：通过
```

### 11.2 下一步

1. **低频控制面验证**
   - A 注册一次后不再频繁 poll。
   - B 仅通过数据面 ping/pong 判断存活。

2. **endpoint 变化验证**
   - 重启路由器或重新拨号。
   - A 检测 STUN endpoint 变化。
   - A 自动通过控制面重新注册。
   - B 自动切换到新 endpoint。

3. **长稳验证**
   - 连续运行 6 小时和 24 小时。
   - 记录 endpoint 变化次数、丢包率、RTT、重连次数。

4. **故障恢复验证**
   - 重启 B agent。
   - 重启 A agent。
   - 重启 WARP SOCKS5 服务。
   - 临时断开 A 网络后恢复。

## 12. 实施阶段

### Phase 1：探测脚本整理

- 保留已验证的 STUN、控制面注册、WARP SOCKS5 UDP ASSOCIATE 逻辑。
- 去掉 A 高频 control poll。
- 统一参数和日志输出。

### Phase 2：agent MVP

交付：

```text
agent_a.py
agent_b.py
config.example.yaml
```

能力：

```text
A：启动注册、STUN 检测、endpoint 变化上报、UDP PONG
B：控制面接收 endpoint、WARP SOCKS5 UDP PING、状态机
```

### Phase 3：稳定性与恢复

- endpoint 变化确认机制。
- B 数据面超时降级。
- A 低频 refresh。
- WARP SOCKS5 UDP relay 自动重建。
- 日志轮转和基础 metrics。

### Phase 4：真实数据封装

- 将 PING/PONG 扩展为 DATA 帧。
- 设计 session、seq、ack、重传或 FEC。
- 评估接入 SOCKS/TUN/UDP forward。

## 13. 风险与待确认事项

```text
1. 电信 NAT1 公网 endpoint 是否长期稳定。
2. 光猫/路由器端口映射重启后是否保留。
3. A 内网 IP 是否固定，建议 DHCP 绑定。
4. WARP SOCKS5 UDP ASSOCIATE relay 是否会超时。
5. 美国 VPS 到中国链路 RTT 高是正常现象，需要长稳数据判断实际可用性。
6. B control 暴露到 0.0.0.0 时需要更强鉴权。
```

## 14. 推荐默认参数

```text
A local UDP port:              39999
STUN server:                   stun.cloudflare.com:3478
STUN check interval:           30s
STUN change confirm count:     2
Control refresh interval:      1800s
B WARP SOCKS5:                 socks5://127.0.0.1:40000
B ping interval:                5s
B probe timeout:                5s
B max consecutive failures:     3
```

## 15. 当前结论

当前测试结果支持继续推进该方案：

```text
CF/VLESS = 低频控制面
STUN = A endpoint 发现与变化检测
WARP SOCKS5 UDP = B 到 A 的长期数据面
路由器端口映射 = A 内网入口放行
```

下一步应从探测脚本进入长期 agent MVP，实现：

```text
启动注册一次
endpoint 变化才上报
数据面 ping/pong 保活
控制面低频 refresh
```
