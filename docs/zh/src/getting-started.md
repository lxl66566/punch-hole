# 快速上手

这一章跑通一场完整会话。整个库的常设前提是宿主已经有到对端的传输通道。

把 crate 加进 `Cargo.toml`：

```toml
[dependencies]
punch-hole = "0.1"
```

## 一屏看完的 API

```rust,no_run
use std::sync::Arc;

use punch_hole::{PunchConfig, PunchError, Puncher};

async fn run_initiator_side() -> Result<(), PunchError> {
    let puncher = Puncher::new(PunchConfig::default())?;

    // 每次尝试一座桥。宿主用自己的传输通道泵 host_end：
    // to_peer 里的帧发给对端，对端回来的帧塞进 from_peer。
    let (host_end, lib_end) = punch_hole::signaling::bridge(64);

    // 驱动 Probe、Exchange、Negotiate、Punch、Confirm、Handover。
    let punched = puncher.with_signaling(lib_end).initiator().await?;

    // 从这里起业务层接管胜出套接字。tokio 套接字没有 Clone，
    // 所以放进 Arc 共享，宿主空闲时用心跳保住 NAT 映射。
    let socket = Arc::new(punched.socket);
    let _guard = punch_hole::keepalive::spawn(
        Arc::clone(&socket),
        punched.peer_addr,
        punched.report.nonce,
    );

    Ok(())
}
```

应答方跑同一份代码，把 `.initiator()` 换成 `.responder()`。两个调用返回同样的 `Punched`。

## 信令桥

`signaling::bridge(capacity)` 返回宿主端和库端，底下是两个 tokio 通道。

- `HostEnd::to_peer` 收到宿主要发给对端的帧。
- `HostEnd::from_peer` 接收从对端到达的帧。

帧是不透明的 `Bytes`。有消息泵的宿主用一个短 spawn 把两端接进自己的循环，基于请求响应 RPC 的宿主在自己的 handler 里转发。一座桥恰好服务一次尝试。并行尝试的宿主自己加信封，路由到各自的桥。

信道应当保序。帧重传覆盖丢包，所以有损信道照样能跑完一场会话。乱序帧应由宿主恢复顺序，垃圾帧会被跳过而不是致命错误，共享信道里混进的杂包结束不了会话。版本不匹配会终止会话，它之后没有任何有意义的交换可做。

## 角色

两个角色跑同一份代码，得到同样的结果。需要单一决策者的决定归发起方：抽 nonce、套用策略矩阵、安排脉冲起点。应答方把计划钳到自己的上限然后确认。角色在两端都想先说话时有意义，按应用里已有的连接建立顺序挑一边即可。

## 读结果

```rust
pub struct Punched<S = tokio::net::UdpSocket> {
    pub socket: S,
    pub peer_addr: SocketAddr,
    pub report: PunchReport,
}
```

套接字保持未连接状态，收发模式由宿主决定。`peer_addr` 是确认过的对端数据面地址。报告里有双方 NAT 类别、所用策略、脉冲类策略的成功率估算、发包计数和各阶段耗时，日志和中继决策都从这里取材。

## 宿主职责清单

库只覆盖一次尝试，清单在尝试之外：

- **先认证再转发。** 数据面给每个包打 128 位 nonce，信令面则信任宿主信道交付的一切。在帧进入 `from_peer` 之前，宿主要在自己的传输层完成对端认证和重放拒绝。
- **按序投递帧。** 重传兜住丢包，保序是桥唯一要求的性质。
- **编排重试。** 一场会话是一次尝试。对难对称 NAT 的脉冲式攻击可能要跑第二次，循环归宿主写。
- **让缓存保持新鲜。** `with_cached_nat` 拿宿主给什么就信什么。网络会变，缓存新旧由宿主判断。

## 示例程序

`examples/punch-demo.rs` 在真实套接字上跑完整会话，自带一个极简配对中继。开三个终端，其中两端放在不同网络里：

```sh
# 终端 1，放在双方都能访问的机器上
cargo run --example punch-demo -- relay 0.0.0.0:9000

# 终端 2
cargo run --example punch-demo -- punch --role initiator --relay <relay-host>:9000

# 终端 3，在终端 2 启动后 30 秒内
cargo run --example punch-demo -- punch --role responder --relay <relay-host>:9000
```

每端打印自己的 NAT 类别、选中的策略和各阶段耗时，然后在打洞出来的套接字上交换一个业务数据报。示例中继不做认证，请留在可信网络里运行。
