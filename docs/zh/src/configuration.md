# 配置

`PunchConfig` 装着所有旋钮。默认值适配用公共 STUN 服务器跑一场普通会话，`Puncher::new` 会拒绝永远跑不完的配置。

## 字段

| 字段 | 默认 | 含义 |
|---|---|---|
| `stun_servers` | 四个公共服务器 | STUN 服务器，`host:port` 形式。可信的易对称拟合需要至少四个不同目的地。 |
| `probe_timeout` | 3 s | 一个 STUN 服务器的应答时限，超时探测就放弃它。 |
| `assistant_sockets` | 16 | SymProbe 里对称侧打开的套接字数。 |
| `predictive_sockets` | 8 | PredictiveExchange 里每侧打开的套接字数。 |
| `max_sockets` | 256 | 单场会话每个地址族可开套接字数的硬上限。 |
| `packets_per_sec` | 400 | 所有池内套接字合计的发送速率上限。 |
| `packet_budget` | 4096 | 单场会话可发的数据面总包数。 |
| `max_mappings` | 4096 | 活套接字数乘去重目的地数的上限，即会话的连接跟踪足迹。 |
| `signaling_retry` | 500 ms | 信令帧的重传节奏。 |
| `exchange_timeout` | 10 s | Exchange 阶段预算，从本阶段开始起算。 |
| `negotiate_timeout` | 10 s | Negotiate 预算，从会话开始起算。 |
| `punch_timeout` | 15 s | Punch 与 Confirm 两阶段共享的时间。 |
| `confirm_retry` | 200 ms | 握手包的重传节奏。 |
| `grace` | 2 s | 已确认一侧在交付前继续应答重复握手包的时长。 |
| `direct_window` | 1 s | Direct 段的时间，从 `punch_timeout` 里扣除。 |
| `target_success` | 0.5 | 脉冲定尺寸瞄准的成功率。 |
| `min_success` | 0.1 | 估算低于此值时协商直接报 `Unpunchable`。 |
| `overall_deadline` | 60 s | 整场会话的硬性时钟上限。 |
| `ipv6` | true | 是否在 IPv6 上探测和打洞。 |
| `tick` | 50 ms | 引擎心跳节奏。 |

## 校验规则

`PunchConfig::validate` 拒绝：

- 空的 STUN 列表
- 套接字数、速率、预算或映射数为零
- 套接字数越界，含 `max_sockets` 超过 4096
- 任何零时长
- 成功率目标超出 0.0 到 1.0
- `min_success` 大于 `target_success`

## 调参笔记

各阶段是叠加的：Probe 最多跑 `probe_timeout`，Exchange 从自己的起点起算拿 `exchange_timeout`，Negotiate 从会话起点起算拿 `negotiate_timeout`，Punch 加 Confirm 共享 `punch_timeout`。所有截止时间都在 `overall_deadline` 之内，慢网络需要更多余量时先调它。

压缩计时器让测试变快。模拟器套件把 `tick`、`confirm_retry`、`grace` 和各预算缩小一个量级，会话逻辑保持原样。
