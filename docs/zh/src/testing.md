# 测试体系

测试套件在毫秒级跑完一整场打洞会话，并把抖动当作缺陷对待。这一章讲测试分层、两个测试专用网络层和 CI 策略。

## 测试分层

| 层 | 证明的事 | 速度 |
|---|---|---|
| 单元测试 | 纯值上的算法层 | 毫秒 |
| 模拟器集成 | 完整协议对确定性虚拟网络 | 毫秒级墙钟 |
| 回环 NAT 实验室 | 模拟 NAT 后面的真实套接字路径 | 真实时间，秒级 |
| 真实套接字冒烟 | 回环上的平台套接字规则 | 真实时间 |

单元测试覆盖分类决策、预测拟合、碰撞模型、定尺寸和胜者选举，全部在纯值上运行。

## 套接字接缝

真实的 NAT 翻译在回环上拦不住，裸 UDP 套接字直接发到目的地。接缝建在套接字创建的地方：`UdpIo` 和 `UdpFactory` 描述一个 UDP 套接字和它的工厂，tokio 工厂是默认值，模拟器插进自己的实现。`test-util` 特性暴露接缝、模拟器和 NAT 实验室。

## 模拟器

`sim::Net` 持有一个路由任务和一张地址表。主机、NAT 和 STUN 服务器都挂在上面，每个虚拟套接字经路由收发，路由施加翻译、过滤、丢包和延迟。

```rust,ignore
let net = sim::Net::seeded("cone_cone_success");  // 用测试名做种子
let stun = net.stun_server();
let host = net.host(&sim::NatSpec::cone_apdf());  // 挂在 NAT 后面
```

`NatSpec` 组合一个映射策略和一个过滤类别。映射策略有 `Cone`、`Sequential { step }`、`AddressSequential { step }` 和 `Random`，预设 `cone_eif()`、`cone_apdf()`、`sequential(step)`、`address_sequential(step)`、`random(range)` 覆盖常见形态。对称预设默认地址相关过滤，即 CGNAT 的常见形态。

路由暴露观测钩子供断言使用：转发与丢弃计数、活跃映射表、峰值映射数，以及一个有界的等映射清空函数。设置 `SIM_TRACE` 环境变量会打印每个转发包，定位故障很快。

确定性来自两件事。所有随机数走同一个以测试名为种子的 `StdRng`，所有测试跑在 `#[tokio::test(start_paused = true)]` 下，一整场会话在墙钟的毫秒内结束。

## 回环 NAT 实验室

`src/natlab.rs` 里的实验室是跑在真实 OS 套接字上的用户态 NAT 转发器。客户端套接字是普通回环套接字，每个出站数据报穿过一个施加 `NatSpec` 映射与过滤策略的网关任务，每个实验室独占 `127.0.0.0/8` 里的一个地址，同进程内的实验室互不干扰。

实验室覆盖模拟器够不到的事：

- 真实套接字路径：OS 绑定、缓冲区大小、描述符生命周期
- Windows 的重置行为：回环 ICMP 端口不可达在稍后的接收上表现为 `ConnectionReset`
- 真实 STUN 数据报往返
- 真实的分配压力与时序，映射创建跟随真实数据报到达

套接字关闭经 Bye 帧释放映射，选举和交付语义因此可观测。实验室跑真实时间，真实套接字没有暂停的时钟。

## 测试套件

| 套件 | 覆盖 |
|---|---|
| `sim_contract.rs` | 信令契约：桥关闭、双发起方、版本不匹配、垃圾帧、有损与重复帧、超大 Offer |
| `sim_probe.rs` | 模拟器上的分类：锥形、易对称、难对称、公网、超时、缓存、扇出顺序 |
| `sim_strategy.rs` | 每策略一个套件，含 64 种子的蒙特卡洛运行，校验生日攻击实测命中率与模型估算 |
| `sim_resource.rs` | 限速、预算与连接跟踪耗尽、每条退出路径的清理、丢弃 future |
| `natlab_matrix.rs` | 同一套策略矩阵跑在两个 NAT 实验室的真实套接字上，外加映射卫生 |
| `real_smoke.rs` | LocalStun 辅助器、回环直连、IPv6 会话用例、Windows 独立端口规则、胜者交付 |
| `decoder_corpus.rs` | 数千个变异缓冲区过两个解码器，无 panic 无挂起 |

矩阵策略用例同时跑在模拟 NAT 和真实 NAT 上：锥形对锥形、易对称预测对、难对称对端口过滤锥形的喷洒、两个难对称之间的生日脉冲。

## 模糊测试

三个 `cargo-fuzz` 目标解码任意字节：`fuzz_sig_frame` 和 `fuzz_data_packet` 覆盖线上编解码，`fuzz_stun` 覆盖 STUN 应答解析器。三者断言同一契约：任何输入要么产出合法消息，要么产出错误，绝不 panic 或挂起。

CI 不跑模糊器。`decoder_corpus.rs` 用固定语料在每次运行里覆盖同一性质。Windows 上模糊目标需要 MSVC AddressSanitizer 运行时在 `PATH` 里。

## CI 策略

CI 用 `cargo-nextest` 跑 Linux、Windows、macOS 三平台，另有固定在 MSRV 上的 cargo check 任务。模拟器测试由构造保证确定性、按测试名做种子，失败用同一种子复现，抖动按缺陷分诊而不是重试了事。
