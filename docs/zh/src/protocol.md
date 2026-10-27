# 协议规范

协议跑在两个信任等级不同的平面上。这一章规定编码、帧、握手和安全姿态。结构体定义与 `src/msg/mod.rs` 保持一致。

## 平面与角色

**信令平面**是宿主提供的信道，承载不透明字节帧。信道应当保序，帧重传覆盖丢包。

**数据平面**是两个 NAT 之间的裸 UDP。上面跑小包，网络随意丢和乱序，任何第三方都可以往里写。

每次尝试有两个角色。需要单一决策者的决定归发起方：抽 nonce、挑策略、定脉冲时间表。应答方确认并跟随。两个角色跑同一份库代码。

一座信令桥恰好服务一次尝试。并行尝试的宿主自己加信封，把帧路由到各自的桥。

## 编码

帧和包都是 serde 结构体，用 postcard 编码。宿主想要带类型的访问可以解码成自己的格式，默认线上格式保持紧凑。

```text
signaling: [version: u8][postcard SigFrame]
data:      [magic: 0x70][version: u8][postcard DataPacket]
```

两个平面处理垃圾的方式不同。信令帧解码失败会被跳过，接收继续，共享宿主信道里混进的杂包结束不了会话。数据包解码失败直接静默丢弃，数据面生来就是敌意环境。任何一面的版本不匹配都会终止会话，它之后没有任何有意义的交换可做。

时长以毫秒整数传输。API 收 `Duration`，在边界处转换。

## 版本策略

两端必须跑同一个 `VERSION`，当前是 2。枚举变体跨版本只增不减，postcard 用变体下标编码，重排或删除变体都要升版本。

## 共享值

```rust
/// 发起方抽取的随机 16 字节。给一次尝试的所有包打标签。
pub type Nonce = [u8; 16];

pub enum NatClass {
    /// 反射 IPv4 地址与本地地址一致。
    Public,
    /// 每个内部套接字一个外部端口，与目的地无关。
    Cone,
    /// 每个目的地一个新端口，按固定步长分配。
    EasySym { step: i16 },
    /// 每个目的地一个新端口，分配不可预测。
    HardSym,
}

pub enum FilterClass {
    EndpointIndependent,
    AddressDependent,
    AddressPortDependent,
    /// 过滤行为未经测量。探测结果恒为此值。
    Unknown,
}

pub enum StrategyId {
    ConeExchange,
    SymProbe,
    PredictiveExchange,
    BirthdayBurst,
}

pub enum AbortReason {
    Unpunchable,
    BudgetExhausted,
    Internal,
}
```

`NatInfo` 是一端在探测阶段收集的关于自己的证据：

```rust
pub struct NatInfo {
    pub v4: Option<V4Nat>,
    pub v6: Option<V6Nat>,
}

pub struct V4Nat {
    pub class: NatClass,
    /// 主反射地址。
    pub reflexive: SocketAddrV4,
    /// 在 NAT 上观测到的外部端口，按发送顺序。上限 64 条。
    pub alloc_seq: Vec<u16>,
    /// 入站过滤证据。探测不测过滤，值恒为 `Unknown`。
    pub filtering: FilterClass,
}

pub struct V6Nat {
    /// 探测阶段收集的全局地址。上限 8 条。
    pub addrs: Vec<SocketAddrV6>,
}
```

两端用同一个预测器在本地拟合对端的 `alloc_seq`。线上只传观测，预测留在本地。

## 信令帧

```rust
pub struct SigFrame {
    /// 发送方自己单调时钟上的毫秒数。
    pub ts: u64,
    /// 被应答帧的 ts 字段，没有应答对象时为 0。
    pub echo: u64,
    pub body: Frame,
}

pub enum Frame {
    Hello(NatInfo),
    Offer(Offer),
    Accept,
    /// 发送方 socket-0 的新鲜端口，打洞涉及的每个地址族一个槽位，
    /// 计划里缺席的族填 None。
    PortUpdate { v4: Option<u16>, v6: Option<u16> },
    /// 发送方已在自己的胜出套接字上完成握手。
    Confirmed { socket: u16 },
    Abort(AbortReason),
}

pub struct Offer {
    pub nonce: Nonce,
    pub strategy: StrategyId,
    /// 发起方将打开的套接字数。
    pub local_sockets: u16,
    /// 应答方应打开的套接字数。
    pub peer_sockets: u16,
    /// 脉冲启动延迟毫秒数，从应答方发出 Accept 起算。
    pub start_delay_ms: u32,
}
```

**Hello** 携带发送方的 `NatInfo`。两端在 Exchange 期间发出并重复，直到对端的 `Hello` 到达。

**Offer** 携带发起方从两份 `NatInfo` 推出的计划。nonce 从此成为这次尝试在数据面上的身份。

**Accept** 确认计划。应答方从自己发出 `Accept` 的那一刻起算 `start_delay_ms`，两端的时钟都锚定在这个共同事件上。

**PortUpdate** 报出发送方打洞套接字的新鲜外部端口，每个族一个槽位。探测得到的反射地址属于已关闭的探测套接字，瞄准固定端口的执行段都要等这一帧。公网或 IPv6 发送方直接读本地地址，锥形映射的发送方在打洞套接字上重新查询 STUN。这一帧按信令重传节奏重发，直到发送方的握手完成。

**Confirmed** 宣布发送方已在数据面完成握手，并报出自己的胜出套接字下标。它让对端提前结束脉冲阶段，也结束发送侧的宽限应答。

**Abort** 告诉对端自己停了以及原因。对端立刻以 `PeerAborted(reason)` 失败，省掉等截止时间的功夫。

帧处理是幂等的。重复帧被忽略，已完成阶段的帧被忽略。唯一的例外：一侧自己就是发起方时又收到 `Offer`，说明两端都认领了发起方，会话在两端同时终止。

## 数据面的数据包

```rust
pub enum DataPacket {
    Syn { nonce: Nonce, socket: u16 },
    SynAck { nonce: Nonce, socket: u16 },
    Ack { nonce: Nonce },
    Keepalive { nonce: Nonce },
}
```

每个包都带尝试 nonce，接收路径先验 nonce 再做任何握手动作，同两台主机之间旧尝试的残留包就此出局。`socket` 字段是发送方的池内下标，报告用它说明对端哪个套接字胜出。

确认握手在胜出通路上直接进行：

```text
Initiator socket k                    Responder socket m
   |---- Syn {nonce, k} -------------->|   反复发
   |<--- SynAck {nonce, m} ------------|   反复发
   |---- Ack {nonce} ----------------->|   发到 Confirmed 或宽限结束
```

`Syn` 证明发起方到应答方。`SynAck` 证明反方向，它一到发起方就算确认。最后的 `Ack` 再次证明正方向，应答方随之确认。`Syn` 和 `SynAck` 按确认重传节奏重发，发起方确认之后宽限应答者继续回答迟到的 `SynAck`，还在等的对端永远拿得到回应。

两端各自在自己确认的那一刻关闭落选套接字。

**Keepalive** 在交付后保住 NAT 映射。宿主丢弃首字节为 `0x70` 且长度小于 64 字节的数据报。

## 信令平面的丢包处理

`Hello`、`Offer`、`Accept` 按信令重传计时器（默认 500 毫秒）重发，直到各自阶段完成。`PortUpdate` 按同一计时器重发到发送方握手完成。帧都是幂等的，可靠信道的宿主每个帧投递一次即可。`Confirmed` 由宽限到期兜底，`Abort` 是尽力而为，两者都无需重传。

## 时间戳与脉冲对齐

`ts` 来自各端自己的单调时钟，跨主机无意义。一端发送带 `ts` 的帧，在对端的 `echo` 里读到这个值，与本地接收时刻相减，就得到一次信令 RTT 测量。发起方取两端 RTT 估计的较大者加 300 毫秒余量作为 `start_delay_ms`，两端从应答方发出 `Accept` 这个共同事件起算延迟。

## 上限与计时器

| 上限 | 值 |
|---|---|
| 信令帧 | 1024 B |
| 数据包 | 64 B |
| `alloc_seq` 条数 | 64 |
| IPv6 地址条数 | 8 |
| 池内下标 | u16 |

| 计时器 | 默认 |
|---|---|
| 信令重传 | 500 ms |
| 确认重传 | 200 ms |
| 宽限期 | 2 s |
| 心跳间隔 | 10 s |

## 安全姿态

nonce 把外来包和旧包挡在一次尝试之外。能猜中 128 位 nonce 的攻击者可以注入握手包，这等价于制造噪声。

协议自身不带认证和加密。保护好信令信道是宿主的职责：先把对端认证好、拒绝重放、保持信道机密，再喂给桥。能读到信令帧的人就握有 nonce，可以伪造该次尝试的握手包，所以信令机密性是数据面安全的一部分。

包很小，每条速率都有上限，协议不构成任何放大面。路径上的攻击者可以丢包拒绝任何 UDP 流的服务，重传掩盖短暂丢包，持续丢包让尝试死在自己的阶段截止时间上。
