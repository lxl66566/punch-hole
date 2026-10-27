punch-hole 是一个信令无关的 UDP 打洞原语库。一场会话给两端的 NAT 做探测分类，经宿主自备的信令与对端协商策略并执行，最后交付一个裸的 `tokio::net::UdpSocket`。库内没有信令实现 / 身份系统 / 中继。

完整文档在 `docs/` 下的 mdbook 中，英文源在 `docs/en/src/`，中文源在 `docs/zh/src/`。协议或行为变更必须在同一次提交里同时更新两棵章节树。

`test-util` 特性解锁模拟器与 NAT 实验室。CI 恒以 `--all-features` 运行。

## 不可破坏的性质

改动必须保持以下性质：

- 信令无关（BYOS）：信令留在库外，宿主传输不透明帧并负责对端发现。
- 零身份系统：角色只有发起方与应答方，唯一凭证是每次尝试的 nonce。需要 PeerId 的功能一律超出范围。
- 裸 socket 交付：胜出者是裸 `tokio::net::UdpSocket`，其余 socket 在会话返回前全部关闭，无论成败。
- 快速失败：每个阶段有截止时间且都在 `overall_deadline` 之下，失败返回指明阶段的 `PunchError`，资源立即释放。
- 资源有界：所有出站包走 socket 池的三道关：限速、包预算、连接跟踪上限。新策略想多发包，必须经现有的模型函数定尺寸。

## 线上协议变更

`src/msg/mod.rs` 是唯一事实源。枚举变体只增不减，布局变更必须升 `VERSION`。改动要同步 `docs/en/src/protocol.md` 与 `docs/zh/src/protocol.md`，消息形状变化还要同步解码语料测试与 fuzz 目标。
