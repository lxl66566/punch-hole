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

use punch_hole::{PunchConfig, PunchFailure, Puncher};

async fn run_initiator_side() -> Result<(), PunchFailure> {
    let puncher = Puncher::new(PunchConfig::default())?;

    // 每次尝试一座桥。宿主用自己的传输通道泵 host_end：
    // to_peer 里的帧发给对端，对端回来的帧塞进 from_peer。
    let (host_end, lib_end) = punch_hole::signaling::bridge(64);

    // 驱动 Probe、Exchange、Negotiate、Punch、Confirm、Handover。
    let punched = puncher.with_signaling(lib_end).initiator().await?;

    // 从这里起业务层接管胜出套接字。tokio 套接字没有 Clone，
    // 所以放进 Arc 共享，宿主空闲时用心跳保住 NAT 映射。
    let socket = Arc::new(punched.socket);
    let _guard = punch_hole::keepalive::spawn_io(
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

两端同时以发起方启动会当场结束尝试：各自把对端的 `Offer` 读成自己的角色被占，以 `PeerAborted(Internal)` 终止。拨号之前就分好角色。没有天然主叫方的场景，用两端 Exchange 之后都拿到的数据推导——反射 IPv4 地址较小的一端做发起方，相等时以较小的本地地址再分——或者让其中一端碰撞后改以应答方重试：碰撞本身就是两侧传输都通的证明。

## 第二次尝试

一场会话是一次尝试，第二次尝试是一场带着全新状态的全新会话：

- 一座新桥、一场新会话。nonce 每次尝试重新抽取，新尝试绝不复用旧的。
- 分类过期就重新取。`Puncher::probe()` 单独跑 Probe 阶段，取值喂给 `with_cached_nat`；网络没变时，失败会话的最后一条 `SessionEvent::Probe` 也能用。
- 要有理由期待不同的结果。概率型脱靶每次尝试重画覆盖端口集，重试有一次全新机会；`Unpunchable` 判定没有——模型已经把这对 NAT 评到 `min_success` 以下，重试只是烧预算。
- 尝试之间退避。上一次尝试留下的 NAT 映射和 conntrack 表项几秒内老化，落在存活期内的重试会继承它们的噪声。
- 双方都抢发起方时换角色。一端改做应答方，或双双退回上面的 tie-break。

## 读结果

```rust
pub struct Punched<S = tokio::net::UdpSocket> {
    pub socket: S,
    pub peer_addr: SocketAddr,
    pub report: PunchReport,
}
```

套接字保持未连接状态，收发模式由宿主决定。`peer_addr` 是确认过的对端数据面地址。报告里有双方 NAT 类别、本地反射地址、引擎刷新查询用的 STUN 服务器、每个对称侧的端口空间估算、所用策略、脉冲类策略的成功率估算、发包计数和各阶段耗时，日志、遥测和中继决策都从这里取材。

交付可能比握手晚出最多 `grace`。被对端 `SynAck` 确认过的一侧会持续应答重复的握手包，直到对端的收尾 `Ack` 到达或 grace 窗口关闭，这样单个包的丢失不需要重试兜底。预期胜出套接字比握手晚出至多 `grace`，窗口大小按这条尾延迟的价值调。

## 失败与进度

失败的会话返回 `PunchFailure`，而不是裸错误：

```rust
pub struct PunchFailure {
    pub error: PunchError,
    pub diagnostics: SessionDiagnostics,
}
```

`error` 指明失败所在的阶段，匹配方式照旧。`Io` 永远装着真实的 OS 错误；库自己得出的状态——比如没有任何 STUN 目的地、池的全部绑定失败、刷新重试耗尽——各占一个专属变体，匹配时能把套接字故障和会话自身的结论分开。`diagnostics` 带着会话到此为止已经知道的事：收集到的本地与对端 `NatInfo`、谈定的 `StrategySummary`、尝试 nonce，以及每个已完成阶段的耗时。每个字段随对应阶段完成而出现，所以光看哪些字段有值就知道失败属于哪个阶段。会话开始之前的错误，比如 `Puncher::new` 拒绝配置，转换过来时诊断为空。

进度不靠轮询。`Puncher::with_events(sender)` 把每个完成的阶段按 Probe、Exchange、Negotiate 的顺序各发一条 `SessionEvent` 到一条 `mpsc` 通道。发送是尽力而为：通道满或已关闭只会丢掉该事件，绝不拖住会话，所以不需要专门的任务去收。

取消就是 drop。丢弃会话 future 在下一个 await 点取消尝试，socket 池在退出路径上关掉尝试开过的所有套接字，被取消的尝试不留任何套接字。没有单独的取消调用。

## 宿主职责清单

库只覆盖一次尝试，清单在尝试之外：

- **先认证再转发。** 数据面给每个包打 128 位 nonce，信令面则信任宿主信道交付的一切。在帧进入 `from_peer` 之前，宿主要在自己的传输层完成对端认证和重放拒绝。
- **按序投递帧。** 重传兜住丢包，保序是桥唯一要求的性质。
- **编排重试。** 一场会话是一次尝试。对难对称 NAT 的脉冲式攻击可能要跑第二次，循环归宿主写。[第二次尝试](#第二次尝试)列了清单。
- **让缓存保持新鲜。** `with_cached_nat` 拿宿主给什么就信什么。网络会变，缓存新旧由宿主判断；`Puncher::probe()` 单独跑一次分类，取一份新值。

## 示例程序

`crates/punch-hole-demo` 构建出 `punch-demo` 二进制：在真实套接字上跑完整会话，自带一个极简配对中继。一个二进制覆盖全部三种角色，构建一次拷到每台机器即可：

```sh
cargo build --release -p punch-hole-demo
# 产物在 target/release/punch-demo，Windows 下是 punch-demo.exe
```

开三个终端，其中两端放在不同网络里：

```sh
# 终端 1，放在双方都能访问的机器上
punch-demo relay 0.0.0.0:9000

# 终端 2
punch-demo client --relay <relay-host>:9000

# 终端 3，在终端 2 启动后 30 秒内
punch-demo server --relay <relay-host>:9000
```

两端都等待另一端 30 秒加入，`--exchange-timeout <s>` 可以改这个秒数。中继在未配对的 slot 加入 60 秒后释放它，在一对 slot 双方都静默 60 秒后释放这一对；因此无人值守、每次尝试后重启的一端应等得更久，并且两次启动至少间隔 60 秒，更早到达的注册会与过期 slot 配成一对。

client 以发起方身份打洞，server 以应答方身份打洞。每端随会话推进逐阶段打印：本端 NAT 类别、对端 NAT 类别、协商出的策略，路径打通后再打印各阶段耗时。随后两端在打洞出来的套接字上聊天：输入的每一行都是发给对端的一个数据报，`/quit` 或输入结束即关闭。示例中继不做认证，请留在可信网络里运行。
