# cares (中文文档)

C++26 异步 DNS 解析库。

## 核心架构

1. **快速路径**：IPv4/IPv6 字面量、`/etc/hosts` 与 `DnsCache` 在零堆分配、零内核调用下返回 `EndpointList`。`DnsCache` 是直接表：从 `HostHash` 起对对象内的 4 个槽做线性探测。窗口满时丢弃已过期项；若都未过期，则丢弃最早入表的存活项。快速路径命中时内联触发 `EndpointsCallback`，并返回已完成的 `QueryHandle`。对该句柄调用 `CancelQuery` 返回 `false`。
2. **Proactor 驱动的 `c-ares`**：缓存未命中时，`ChannelCore`（`ares_dns_record_t`）与 `PollTable`（一次性 `POLL_ADD` / `POLL_REMOVE`）接入调用方持有的 `uring::Proactor`。`ResolverConfig::subsystem_id` 选择完成事件路由（默认 `kPollSubsystemId = 2`）。
3. **共享 Proactor**：`ClaimProactor` 在 `subsystem_id` 不是 0、1 或 255，且该环上尚未占用该 id 时接纳解析器（每线程最多 16 个占用）。同一 Proactor 上的第二个解析器，只有在包含新来者在内的每个存活占用都已设置 `ForeignBatchObserver` 时才会被接纳。先绑定第一个观察者，再创建第二个。`BindForeignRouter(nullptr)` 清除观察者。观察者收到的 span 只在 `DispatchBatch` 期间有效。未路由的外部批次返回 `kInvalid`。`DrainOwnIdle` 把 `kNoEntry` 和 `kTimedOut` 视为空闲环。`CancelQuery(handle)` 抑制在途查询的回调投递。
4. **双栈定时器**：每个 `Resolver` 保持有界的 `TimerArm` 槽。已经到期或不晚于目标时间的存活臂保持武装。更晚的臂被取消，另一槽武装新的截止时间。
5. **工具链**：需要 C++26 反射（GCC 为 `-freflection`，Clang 为 `-freflection-latest` 加 libc++），并使用 `-fno-exceptions` 与 `-fno-rtti`。

持久保存的回调使用 `cares::Delegate<Signature>`，它是 `uarch::Callback<Signature>` 的别名。通过 `uarch::bind` 绑定函数或左值对象；对象必须比回调活得更久。超过寄存器传输上限的结果通过消费型右值引用传递。

## 构建与验证

需要 CMake >= 4.0。依赖通过 vcpkg manifest mode 从配置的 registry 或 overlay ports 解析。

```bash
./cares build --preset clang-glibc-release
./cares test  --preset clang-glibc-release
./cares verify
```
