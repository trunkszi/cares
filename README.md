# cares

C++26 header-first asynchronous DNS resolver.

## Architecture

1. **Fast path**: IPv4/IPv6 literals, `/etc/hosts`, and `DnsCache` return an `EndpointList` with no heap allocation and no kernel call. `DnsCache` is a direct table: lookup starts at `HostHash` and linearly probes a window of 4 slots stored in the cache object. A full window drops an expired entry, or the oldest live entry when none has expired. A fast-path hit invokes `EndpointsCallback` inline and returns a completed `QueryHandle`. `CancelQuery` on that handle returns `false`.
2. **Proactor-driven `c-ares`**: A cache miss uses `ChannelCore` (`ares_dns_record_t`) and `PollTable` (one-shot `POLL_ADD` / `POLL_REMOVE`) on a caller-owned `uring::Proactor`. `ResolverConfig::subsystem_id` selects the completion route (default `kPollSubsystemId = 2`).
3. **Shared Proactor**: `ClaimProactor` admits a resolver when `subsystem_id` is not 0, 1, or 255 and is not already claimed on that ring (at most 16 claims per thread). A second resolver on the same proactor is admitted only when every live claim, including the newcomer, already has a `ForeignBatchObserver`. Bind the first observer before creating the second. `BindForeignRouter(nullptr)` clears it. The observer span is valid only during `DispatchBatch`. An unrouted foreign batch returns `kInvalid`. `DrainOwnIdle` treats `kNoEntry` and `kTimedOut` as an idle ring. `CancelQuery(handle)` suppresses delivery of an in-flight query.
4. **Dual-stack timers**: Each `Resolver` keeps bounded `TimerArm` slots. A live arm whose deadline is already at or before the wanted time stays armed. A longer arm is cancelled and the other slot takes the new deadline.
5. **Toolchain**: C++26 reflection is required (`-freflection` for GCC, `-freflection-latest` with libc++ for Clang), together with `-fno-exceptions` and `-fno-rtti`.

Stored callbacks use `cares::Delegate<Signature>`, an alias of `uarch::Callback<Signature>`. Bind functions and lvalue objects with `uarch::bind`; the object must outlive the callback. Results larger than the register transport limit are delivered through consuming rvalue references.

## Build & Verify

CMake >= 4.0. Dependencies resolve through vcpkg manifest mode using the configured registry or overlay ports.

```bash
./cares build --preset clang-glibc-release
./cares test  --preset clang-glibc-release
./cares verify
```
