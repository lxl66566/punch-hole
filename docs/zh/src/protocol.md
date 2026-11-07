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

两个 postcard 性质对宿主有意义。编码不是规范形：varint 字段允许超长形式，值相等不保证字节相等，宿主不要按原始字节相等去做帧的去重或对账。解码拒绝尾部字节，合法编码后跟多余字节会失败，不会给出第二种解释。

时长以毫秒整数传输。API 收 `Duration`，在边界处转换。

## 版本策略

两端必须跑同一个 `VERSION`，当前是 5。枚举变体跨版本只增不减，postcard 用变体下标编码，新增、重排或删除变体都要升版本。

新增变体同样必须升版本。postcard 无法区分未知变体下标与损坏字节，旧端收到携带更新变体的帧只会看到一次普通的解码失败：在信令平面上这一帧被跳过，对端直到阶段超时也不知道版本不一致。版本纪律是这一平面唯一的防线。数据面在解包体之前先查版本字节，第一个版本不符的包就会让会话立即以 `VersionMismatch` 失败。

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
    /// 过滤行为未经测量：没有服务器通告 OTHER-ADDRESS，
    /// 或者发现探测丢失。
    Unknown,
}

pub enum StrategyId {
    ConeExchange,
    SymProbe,
    PredictiveExchange,
    BirthdayBurst,
    PredictiveBurst,
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
    /// 宿主在探测路径上的本机接口地址，供同一 NAT 后两台主机的
    /// Local 段使用。上限 8 条。
    pub local: Vec<Ipv4Addr>,
}

pub struct V4Nat {
    pub class: NatClass,
    /// 主反射地址。
    pub reflexive: SocketAddrV4,
    /// 在 NAT 上观测到的外部端口，按发送顺序。上限 64 条。
    pub alloc_seq: Vec<u16>,
    /// 应答了探测的目的地中不同的服务器 IP 数。单 IP 扇出在地址相关
    /// NAT 上只跨越一个映射，据此读出的锥形只代表该映射的行为。
    pub distinct_probe_ips: u8,
    /// 入站过滤证据，来自 RFC 5780 改址请求测试——扇出前对一台
    /// 支持发现的服务器运行。没有探测服务器通告 OTHER-ADDRESS 时为
    /// `Unknown`。
    pub filtering: FilterClass,
    /// 探测发往自身反射地址的数据报是否环回（RFC 4787 §6）；它同时
    /// 证明映射是端点无关的：按目的地分配的映射过不了这个自环。
    pub hairpin: bool,
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
    /// 发送方自己单调时钟上的毫秒数，从 1 起算，保证 echo 总能指到真实帧。
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

**PortUpdate** 报出发送方打洞套接字的新鲜外部端口，每个族一个槽位。探测得到的反射地址属于已关闭的探测套接字，瞄准固定端口的执行段都要等这一帧。公网或 IPv6 发送方直接读本地地址，锥形映射的发送方在打洞套接字上重新查询 STUN。步长可信的对称发送方没有对端可以瞄准的单一端口，它的 V4 槽位因此是另一种读法：该端口标记发送方当前的分配位置，带预测的对端把拟合窗口平移到它上面。两种读法都以协商出的策略为键，帧形保持不变。这一帧按信令重传节奏重发，直到发送方的握手完成。

**Confirmed** 宣布发送方已在数据面完成握手，并报出自己的胜出套接字下标。这帧只是通报：对端选哪个套接字由它自己的握手证据决定，从未从交换中学到对端套接字的一侧才为报告采纳通报的下标。下文的仲裁可能在首次宣布之后替换胜者，所以一侧可能带着更靠后的下标把这一帧发不止一次。

**Abort** 告诉对端自己停了以及原因。对端立刻以 `PeerAborted(reason)` 失败，省掉等截止时间的功夫。

帧处理是幂等的。重复帧被忽略，已完成阶段的帧被忽略。唯一的例外：一侧自己就是发起方时又收到 `Offer`，说明两端都认领了发起方，会话在两端同时终止。

## 数据面的数据包

```rust
pub enum DataPacket {
    Syn { nonce: Nonce, socket: u16 },
    SynAck { nonce: Nonce, socket: u16 },
    Ack { nonce: Nonce, socket: u16 },
    Keepalive { nonce: Nonce },
}
```

每个包都带尝试 nonce，接收路径先验 nonce 再做任何握手动作，同两台主机之间旧尝试的残留包就此出局。`socket` 字段是发送方自己的池内下标：`Syn` 和 `SynAck` 说明包从哪个套接字发出，`Ack` 说明是哪个套接字完成了这次交换，报告据此点名对端哪个套接字胜出。

确认握手在胜出通路上直接进行：

```text
Initiator socket k                    Responder socket m
   |---- Syn {nonce, k} -------------->|   反复发
   |<--- SynAck {nonce, m} ------------|   反复发
   |---- Ack {nonce, k} --------------->|   宽限窗口内反复发
```

`Syn` 证明一个方向，`SynAck` 证明反方向，收到被瞄准的 `SynAck` 的一侧把自己的接收套接字确认进该次交换。`Ack` 点名它所结束的交换的两端：落地地址已经选出接收方，`socket` 字段选出发送方，一个包就标识了整个套接字对。Ack 只在应答过其所属主机的 `Syn` 的套接字上才算数，所以扫过对端多个套接字也只确认真正跑过握手的通路。

乱序链路会并行跑多条这样的交换，两端最先看到完成的可能各不相同，于是两端可能各自确认了不同的套接字对。此时由仲裁定夺：每一侧把手里握着的对和有效 Ack 提供的对放进同一个规范键里排序——发起方的套接字在前，这个顺序两端仅凭角色就能算出一致——键小者胜。宽限期里的 `Ack` 重发把各自当前的对源源传给对端，所以无论证据以什么顺序到达，仲裁都把两端收敛到同一个套接字对上；收到重复确认自己手里这个对的 Ack 就是双方达成一致的凭据，等待就此提前结束——否则由宽限窗口兜底。落选套接字只在各自会话结束时关闭。

**Keepalive** 在交付后保住 NAT 映射。宿主丢弃首字节为 `0x70` 且长度不超过 64 字节的数据报；`msg::is_protocol_packet` 实现了这个判定。

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

nonce 把外来包和旧包挡在一次尝试之外。能猜中 128 位 nonce 的攻击者可以注入握手包；确认路径仍然要求 `SynAck` 来自对端自己的地址、`Ack` 落在应答过该源的套接字上，所以来自无关主机的注入等价于制造噪声。

协议自身不带认证和加密。保护好信令信道是宿主的职责：先把对端认证好、拒绝重放、保持信道机密，再喂给桥。能读到信令帧的人就握有 nonce，可以伪造该次尝试的握手包，所以信令机密性是数据面安全的一部分。

包很小，每条速率都有上限，协议不构成任何放大面。路径上的攻击者可以丢包拒绝任何 UDP 流的服务，重传掩盖短暂丢包，持续丢包让尝试死在自己的阶段截止时间上。
