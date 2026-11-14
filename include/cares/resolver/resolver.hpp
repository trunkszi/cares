/**
 * @file resolver.hpp
 * @brief Proactor DNS resolver. `ResolveEndpoints` returns `Result<EndpointList>` by value.
 */
#pragma once

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#include <cares/channel/channel_core.hpp>
#include <cares/channel/library_guard.hpp>
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
#include <ares.h>

#include <array>
#include <cares/channel/options.hpp>
#include <cares/resolver/resolver_detail.hpp>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <uring/uring.hpp>
#include <utility>

namespace cares {

template <std::size_t MaxInflight = 64, std::size_t MaxSockets = 16, std::size_t MaxCacheEntries = 256,
          std::size_t MaxStaticHosts = 64>
class Resolver {
  static_assert(MaxInflight > 0 && MaxInflight <= 64);
  static_assert(MaxSockets > 0 && MaxSockets <= 64);

 public:
  static constexpr std::uint8_t kSubsystemId = kPollSubsystemId;

  [[nodiscard]] static consteval uring::caps::RequiredCaps RequiredCaps() noexcept {
    return uring::caps::RequiredCaps::For<uring::abi::kOpPollAdd, uring::abi::kOpPollRemove, uring::abi::kOpTimeout,
                                          uring::abi::kOpTimeoutRemove>();
  }

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
  [[nodiscard, gnu::noinline]] static Result<Resolver> FromSystem(uring::Proactor& proactor, ResolverConfig cfg = {}) noexcept {
    auto resolver = InitBase(proactor, cfg);
    if (!resolver) return std::unexpected(resolver.error());
    auto core = ChannelCore<MaxInflight>::FromSystem(uarch::bind<&Resolver::OnSocketState>(*resolver));
    if (!core) return std::unexpected(core.error());
    return FinalizeInit(std::move(*resolver), std::move(*core), {});
  }

  [[nodiscard, gnu::noinline]] static Result<Resolver> Create(uring::Proactor& proactor, const ChannelOptions& options,
                                                              ResolverConfig cfg = {}) noexcept {
    auto resolver = InitBase(proactor, cfg);
    if (!resolver) return std::unexpected(resolver.error());
    auto core = ChannelCore<MaxInflight>::Create(options, uarch::bind<&Resolver::OnSocketState>(*resolver));
    if (!core) return std::unexpected(core.error());
    return FinalizeInit(std::move(*resolver), std::move(*core), options.hosts_path.as_string_view());
  }

  Resolver(const Resolver&) = delete ("resolver owns one proactor claim");
  Resolver& operator=(const Resolver&) = delete ("resolver owns one proactor claim");
  Resolver(Resolver&& other) noexcept
      : polls_(other.config_.subsystem_id), cache_(other.config_.cache_config), config_(other.config_) {
    if (other.proactor_ != nullptr) Steal(&other);
  }
  Resolver& operator=(Resolver&& other) noexcept {
    if (this != &other) {
      Quiesce();
      detail::ReleaseProactor(proactor_, config_.subsystem_id);
      proactor_ = nullptr;
      if (other.proactor_ != nullptr)
        Steal(&other);
      else {
        pool_.reset();
        core_.SetSocketObserver({});
        core_ = {};
        foreign_ready_ = false;
      }
    }
    return *this;
  }
  ~Resolver() noexcept {
    Quiesce();
    core_.SetSocketObserver({});
    detail::ReleaseProactor(proactor_, config_.subsystem_id);
  }

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

  [[nodiscard]] Result<QueryHandle> SubmitEndpoints(std::string_view target, std::uint16_t default_port,
                                                    EndpointsCallback cb) noexcept {
    if (proactor_ == nullptr || pool_ == nullptr) return std::unexpected(Error::InvalidArgument());
    const auto parsed = ParseEndpoint(target, default_port);
    if (!parsed) return std::unexpected(parsed.error());
    if (auto fast = TryFast(*parsed); fast) {
      if (!*fast) return std::unexpected(fast->error());
      if (cb) cb(std::move(*fast));
      return QueryHandle::Pack(0xffffu, 1, detail::kFastMark);
    }
    if (parsed->host.size() >= 256) return std::unexpected(Error::BadName());
    const auto bit = pool_->free_bits.lowest_one();
    if (!bit.has_value() || *bit >= pool_->nodes.size()) return std::unexpected(Error::CapacityExhausted());
    pool_->free_bits = pool_->free_bits.clear(*bit);
    const auto slot = static_cast<std::uint16_t>(*bit);
    auto& node = pool_->nodes[slot];
    const bool want_v4 = config_.family != IpFamily::Ipv6;
    const bool want_v6 = config_.family != IpFamily::Ipv4;
    const auto next_state = detail::InitNodeWord(node.state, slot, want_v4, want_v6);
    const auto gen = detail::NodeGeneration(next_state);
    node = EndpointNode{.owner = this, .state = next_state, .port = parsed->port, .callback = cb};
    node.host_len = static_cast<std::uint8_t>(parsed->host.size());
    for (std::uint8_t i = 0; i < node.host_len; ++i) node.host[i] = parsed->host[i];
    const auto name = std::string_view{node.host.data(), node.host_len};
    if (want_v4) {
      auto sub = core_.SubmitSearch(name, DnsClass::IN, DnsType::A, uarch::bind<&EndpointNode::OnV4>(node));
      if (!sub) {
        ReleaseNode(&node);
        return std::unexpected(sub.error());
      }
      node.v4 = *sub;
    }
    if (want_v6) {
      auto sub = core_.SubmitSearch(name, DnsClass::IN, DnsType::AAAA, uarch::bind<&EndpointNode::OnV6>(node));
      if (!sub) {
        node.state = detail::MarkNodeSuppress(node.state);
        if (want_v4) static_cast<void>(core_.CancelQuery(node.v4));
        if (detail::NodeLive(node.state)) ReleaseNode(&node);
        return std::unexpected(sub.error());
      }
      node.v6 = *sub;
    }
    return QueryHandle::Pack(slot, gen, detail::kJobMark);
  }

  [[nodiscard]] Result<EndpointList> ResolveEndpoints(std::string_view target, std::uint16_t default_port = 0,
                                                      std::uint32_t timeout_ms = 5000) noexcept {
    detail::EndpointWait wait;
    auto submitted = SubmitEndpoints(target, default_port, uarch::bind<&detail::EndpointWait::On>(wait));
    if (!submitted) return std::unexpected(submitted.error());
    if (!wait.done) {
      if (auto pumped = Pump(&wait.done, *submitted, timeout_ms); !pumped) return std::unexpected(pumped.error());
    }
    if (!wait.value) static_cast<void>(CancelQuery(*submitted));
    return std::move(wait.value);
  }

  [[nodiscard]] Result<QueryHandle> SubmitDnsRec(const DnsRecordRef& query_rec, DnsRecCallback cb) noexcept {
    return core_.SubmitDnsRec(query_rec, cb);
  }
  [[nodiscard]] Result<QueryHandle> SubmitQuery(std::string_view name, DnsClass qclass, DnsType qtype,
                                                DnsRecCallback cb) noexcept {
    return core_.SubmitQuery(name, qclass, qtype, cb);
  }
  [[nodiscard]] Result<QueryHandle> SubmitHostByName(std::string_view name, int family, HostCallback cb) noexcept {
    return core_.SubmitHostByName(name, family, cb);
  }
  [[nodiscard]] Result<QueryHandle> SubmitAddressInfo(std::string_view name, std::string_view service, IpFamily family,
                                                      AddrInfoCallback cb) noexcept {
    return core_.SubmitAddressInfo(name, service, family, cb);
  }
  template <typename RecordT>
  [[nodiscard]] Result<RecordT> Resolve(std::string_view qname, DnsType qtype, std::uint32_t timeout_ms = 5000) noexcept {
    auto wire = ResolveWire(qname, qtype, timeout_ms);
    if (!wire) return std::unexpected(wire.error());
    return detail::ExtractFromWire<RecordT>(wire->AsRef());
  }
  [[nodiscard]] Result<DnsRecord> ResolveWire(std::string_view qname, DnsType qtype, std::uint32_t timeout_ms = 5000) noexcept {
    detail::WireWait wait;
    auto submitted = core_.SubmitQuery(qname, DnsClass::IN, qtype, uarch::bind<&detail::WireWait::On>(wait));
    if (!submitted) return std::unexpected(submitted.error());
    if (!wait.done) {
      if (auto pumped = Pump(&wait.done, *submitted, timeout_ms); !pumped) return std::unexpected(pumped.error());
    }
    if (!wait.value) static_cast<void>(CancelQuery(*submitted));
    return std::move(wait.value);
  }
  [[nodiscard]] bool CancelQuery(QueryHandle handle) noexcept {
    if (handle.Qid() == detail::kFastMark) return false;
    if (handle.Qid() == detail::kJobMark) {
      auto* node = FindJob(handle);
      if (node == nullptr) return false;
      node->state = detail::MarkNodeSuppress(node->state);
      bool cancelled = false;
      if (detail::NodeWantV4(node->state) && !detail::NodeV4Done(node->state)) {
        cancelled = core_.CancelQuery(node->v4) || cancelled;
      }
      if (detail::NodeWantV6(node->state) && !detail::NodeV6Done(node->state)) {
        cancelled = core_.CancelQuery(node->v6) || cancelled;
      }
      if (detail::NodeLive(node->state)) ReleaseNode(node);
      return cancelled;
    }
    return core_.CancelQuery(handle);
  }
  void CancelAll() noexcept {
    if (pool_ != nullptr) {
      for (auto& node : pool_->nodes)
        if (node.owner == this && detail::NodeLive(node.state)) node.state = detail::MarkNodeSuppress(node.state);
    }
    core_.CancelAll();
    if (pool_ != nullptr) {
      for (auto& node : pool_->nodes)
        if (node.owner == this && detail::NodeLive(node.state)) ReleaseNode(&node);
    }
  }
  void StepDriver() noexcept {
    if (proactor_ == nullptr || stepping_) return;
    detail::StepGate gate{&stepping_};
    if (phase_ == DriverPhase::Faulted) {
      PublishCallbacks();
      return;
    }
    phase_ = DriverPhase::HarvestReadySockets;
    Harvest();
    if (phase_ != DriverPhase::Faulted) {
      phase_ = DriverPhase::FlushSocketSubmissions;
      if (FlushSockets() && phase_ != DriverPhase::Faulted) {
        phase_ = DriverPhase::ReconcileTimer;
        ReconcileTimer();
      }
      if (phase_ != DriverPhase::Faulted) phase_ = DriverPhase::Idle;
    }
    PublishCallbacks();
  }
  void InvalidateCache(std::string_view host) noexcept { cache_.Invalidate(host); }
  [[nodiscard]] Result<void> InsertStaticHost(std::string_view host, IpAddress ip) noexcept { return hosts_.Insert(host, ip); }
  [[nodiscard]] std::size_t ActiveQueryCount() const noexcept { return core_.ActiveQueryCount(); }
  [[nodiscard]] constexpr DriverPhase Phase() const noexcept { return phase_; }
  [[nodiscard]] constexpr std::uint8_t SubsystemId() const noexcept { return config_.subsystem_id; }
  [[nodiscard]] constexpr bool CanRoute(std::uint8_t id) const noexcept { return id == config_.subsystem_id; }
  /** @brief Replaces the observer for foreign-subsystem completion runs. */
  void SetForeignBatchObserver(ForeignBatchObserver observer) noexcept {
    config_.foreign_observer = observer;
    foreign_ready_ = static_cast<bool>(observer);
  }
  /** @brief Observer currently bound for foreign-subsystem completion runs. */
  [[nodiscard]] ForeignBatchObserver ForeignObserver() const noexcept { return config_.foreign_observer; }
  /** @brief Binds `Router::OnForeignDeliveries`, or clears the observer when `router` is null. */
  template <typename Router>
  void BindForeignRouter(Router* router) noexcept {
    if (router == nullptr)
      config_.foreign_observer = {};
    else
      config_.foreign_observer = uarch::bind<&Router::OnForeignDeliveries>(*router);
    foreign_ready_ = static_cast<bool>(config_.foreign_observer);
  }

  void OnCompletions(std::span<const uring::Delivery> deliveries) noexcept {
    for (const auto& delivery : deliveries) {
      const auto token = delivery.completion.token;
      const auto result = delivery.completion.result;
      if (pool_ != nullptr) {
        const auto outcome = detail::MatchTimerCqe(pool_->timers, token, result);
        if (outcome.fired) timer_fired_ = true;
        if (outcome.matched) continue;
      }
      ready_count_ = detail::HandlePollCqe(std::span{arms_}, &polls_, std::span{ready_}, ready_count_, token, result);
    }
  }

 private:
  struct EndpointNode {
    Resolver* owner{nullptr};
    DualStackWord state{};
    QueryHandle v4{};
    QueryHandle v6{};
    std::uint16_t port{0};
    std::uint32_t min_ttl{0xffffffffu};
    Error error{};
    EndpointList endpoints{};
    std::array<IpAddress, 16> addresses{};
    std::uint8_t address_count{0};
    std::array<char, 256> host{};
    std::uint8_t host_len{0};
    EndpointsCallback callback{};
    void OnV4(Result<DnsRecordRef> result) noexcept {
      if (owner != nullptr) owner->Finish(this, true, result);
    }
    void OnV6(Result<DnsRecordRef> result) noexcept {
      if (owner != nullptr) owner->Finish(this, false, result);
    }
  };

  struct EndpointPool {
    std::array<EndpointNode, MaxInflight> nodes{};
    uarch::Bitmap64 free_bits{detail::InitialFreeMask<MaxInflight>()};
    std::array<detail::TimerArm, 2> timers{};
    std::array<detail::PendingCallback, MaxInflight> pending{};
    [[nodiscard]] bool HasLiveKernelArms(std::span<const detail::PollArm> polls) const noexcept {
      return detail::AnyArmBusy(polls, timers);
    }
  };

  struct Dispatcher {
    Resolver* resolver{nullptr};
    [[nodiscard]] constexpr bool CanRoute(std::uint8_t id) const noexcept {
      return resolver != nullptr && resolver->CanRoute(id);
    }
    [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
      bool had_unrouted = false;
      while (!deliveries.empty()) {
        const auto id = uring::Subsystem(deliveries.front().completion.token);
        std::size_t count = 1;
        while (count < deliveries.size() && uring::Subsystem(deliveries[count].completion.token) == id) ++count;
        if (CanRoute(id))
          resolver->OnCompletions(deliveries.first(count));
        else if (resolver != nullptr && resolver->config_.foreign_observer) {
          // Drive already reaped this run; kNoEntry cannot put the CQEs back.
          resolver->config_.foreign_observer(deliveries.first(count));
        } else
          had_unrouted = true;
        deliveries = deliveries.subspan(count);
      }
      if (had_unrouted) return std::unexpected(uring::UringErrorCode::kInvalid);
      return {};
    }
  };

  explicit Resolver(LibraryGuard guard, uring::Proactor& proactor, ResolverConfig cfg,
                    std::unique_ptr<EndpointPool> pool) noexcept
      : guard_(std::move(guard)),
        proactor_(&proactor),
        polls_(cfg.subsystem_id),
        cache_(cfg.cache_config),
        config_(cfg),
        pool_(std::move(pool)) {}

  [[nodiscard]] static Result<Resolver> InitBase(uring::Proactor& proactor, ResolverConfig cfg) noexcept {
    if (!detail::SubsystemOk(cfg.subsystem_id)) return std::unexpected(Error::InvalidArgument());
    auto guard = LibraryGuard::Acquire();
    if (!guard) return std::unexpected(guard.error());
    if (auto gate = LibraryGuard::EnsureThreadingDisabled(); !gate) return std::unexpected(gate.error());
    Resolver resolver{std::move(*guard), proactor, cfg, std::make_unique<EndpointPool>()};
    resolver.polls_.SetSubsystemId(cfg.subsystem_id);
    resolver.foreign_ready_ = static_cast<bool>(cfg.foreign_observer);
    if (!detail::ClaimProactor(resolver.proactor_, cfg.subsystem_id, &resolver.foreign_ready_)) {
      resolver.proactor_ = nullptr;
      return std::unexpected(Error::InvalidArgument());
    }
    return resolver;
  }

  [[nodiscard]] static Result<Resolver> FinalizeInit(Resolver resolver, ChannelCore<MaxInflight> core,
                                                     std::string_view hosts_path) noexcept {
    resolver.core_ = std::move(core);
    resolver.Rebind();
    if (resolver.config_.enable_hosts) {
      const bool default_path = hosts_path.empty();
      const auto path = default_path ? std::string_view{"/etc/hosts"} : hosts_path;
      if (auto loaded = resolver.hosts_.LoadHostsFile(path);
          !loaded && !detail::HostsOverflowOptional(loaded.error(), default_path)) {
        return std::unexpected(loaded.error());
      }
    }
    return resolver;
  }

  void Steal(Resolver* other) noexcept {
    if (other == nullptr || other->proactor_ == nullptr) return;
    other->Quiesce();
    detail::ReleaseProactor(other->proactor_, other->config_.subsystem_id);
    guard_ = std::move(other->guard_);
    proactor_ = std::exchange(other->proactor_, nullptr);
    core_.SetSocketObserver({});
    core_ = std::move(other->core_);
    polls_ = std::move(other->polls_);
    hosts_ = std::move(other->hosts_);
    cache_ = std::move(other->cache_);
    config_ = other->config_;
    pool_ = std::move(other->pool_);
    arms_ = other->arms_;
    other->arms_.fill(detail::PollArm{});
    other->foreign_ready_ = false;
    ready_count_ = pending_count_ = 0;
    timer_fired_ = false;
    stepping_ = false;
    phase_ = DriverPhase::Idle;
    foreign_ready_ = static_cast<bool>(config_.foreign_observer);
    polls_.SetSubsystemId(config_.subsystem_id);
    if (!detail::ClaimProactor(proactor_, config_.subsystem_id, &foreign_ready_)) {
      proactor_ = nullptr;
      pool_.reset();
      core_.SetSocketObserver({});
      core_ = {};
      foreign_ready_ = false;
      return;
    }
    Rebind();
  }

  void Rebind() noexcept {
    core_.SetSocketObserver(uarch::bind<&Resolver::OnSocketState>(*this));
    if (pool_ != nullptr) {
      for (auto& node : pool_->nodes)
        if (detail::NodeLive(node.state)) node.owner = this;
    }
  }

  void Quiesce() noexcept {
    if (proactor_ == nullptr || phase_ == DriverPhase::DrainingCancel) return;
    phase_ = DriverPhase::DrainingCancel;
    CancelAll();
    for (auto& arm : arms_)
      if (arm.poll_live) RequestCancelArm(&arm);
    RemoveTimer();
    WaitOwnIdle();
    if (phase_ == DriverPhase::Faulted && pool_ != nullptr && pool_->HasLiveKernelArms(arms_))
      detail::LeakPinnedObject(pool_);
    else if (phase_ != DriverPhase::Faulted)
      phase_ = DriverPhase::Idle;
  }
  void OnSocketState(int fd, SocketInterest interest) noexcept {
    if (interest == SocketInterest::None) DisarmFd(fd);
    auto slot = polls_.OnSocketState(fd, interest);
    if (slot && *slot < arms_.size()) arms_[*slot].fd = fd;
  }

  void Harvest() noexcept {
    if (std::exchange(timer_fired_, false)) core_.ProcessTimeouts();
    if (ready_count_ == 0) return;
    const auto count = std::exchange(ready_count_, 0);
    if (!core_.ProcessBatch(std::span<const ares_fd_events_t>{ready_.data(), count})) phase_ = DriverPhase::Faulted;
  }
  [[nodiscard]] Result<void> FlushSockets() noexcept {
    if (proactor_ == nullptr) return {};
    RetryPendingCancels();
    auto flushed =
        detail::FlushPollSlots(proactor_, config_.subsystem_id, &polls_, std::span{arms_}, core_.ActiveQueryCount() != 0);
    if (!flushed) return std::unexpected(flushed.error());
    return {};
  }
  void ReconcileTimer() noexcept {
    if (proactor_ == nullptr || pool_ == nullptr) return;
    RetryPendingCancels();
    static_cast<void>(detail::ReconcileTimers(proactor_, config_.subsystem_id, pool_->timers, core_.NextTimeout(0),
                                              core_.ActiveQueryCount() != 0));
  }
  void RemoveTimer() noexcept {
    if (pool_ != nullptr)
      for (auto& timer : pool_->timers)
        if (timer.timeout_live) RequestCancelTimer(&timer);
  }
  void DisarmFd(int fd) noexcept {
    for (auto& arm : arms_)
      if (arm.fd == fd && arm.poll_live) RequestCancelArm(&arm);
  }
  void RequestCancelArm(detail::PollArm* arm) noexcept {
    static_cast<void>(detail::RequestCancelPollArm(proactor_, config_.subsystem_id, arm));
  }
  void RequestCancelTimer(detail::TimerArm* timer) noexcept {
    static_cast<void>(detail::RequestCancelTimerArm(proactor_, config_.subsystem_id, timer));
  }
  void RetryPendingCancels() noexcept {
    if (pool_ != nullptr) {
      static_cast<void>(detail::RetryCancels(proactor_, config_.subsystem_id, arms_, pool_->timers));
    }
  }
  [[nodiscard]] bool OwnBusy() const noexcept { return pool_ != nullptr && detail::AnyArmBusy(arms_, pool_->timers); }
  void WaitOwnIdle() noexcept {
    if (proactor_ != nullptr && pool_ != nullptr &&
        !detail::DrainOwnIdle(proactor_, config_.subsystem_id, arms_, pool_->timers, Dispatcher{this})) {
      phase_ = DriverPhase::Faulted;
    }
  }
  void PublishCallbacks() noexcept {
    if (pending_count_ != 0 && pool_ != nullptr) {
      detail::PublishPending<MaxInflight>(pool_->pending, std::exchange(pending_count_, 0));
    }
  }
  void Finish(EndpointNode* node, bool v4, Result<DnsRecordRef> result) noexcept {
    if (node == nullptr || node->owner != this) return;
    node->state = detail::MarkNodeDone(node->state, v4);
    if (!detail::NodeSuppress(node->state)) {
      if (result)
        detail::RememberAnswers(node, *result, config_.family);
      else {
        node->state = detail::MarkNodeError(node->state);
        node->error = detail::PreferFamilyError(node->error, result.error());
      }
    }
    if (!detail::NodeAllDone(node->state)) return;
    if (!detail::NodeSuppress(node->state)) {
      StoreCache(*node);
      auto callback = node->callback;
      Result<EndpointList> out = node->endpoints.empty()
                                     ? std::unexpected(detail::NodeSawError(node->state) ? node->error : Error::NotFound())
                                     : Result<EndpointList>{node->endpoints};
      ReleaseNode(node);
      Enqueue(callback, std::move(out));
      return;
    }
    ReleaseNode(node);
  }
  void Enqueue(EndpointsCallback callback, Result<EndpointList> result) noexcept {
    if (!callback) return;
    if (pool_ == nullptr || pending_count_ >= pool_->pending.size())
      callback(std::move(result));
    else
      pool_->pending[pending_count_++] = detail::PendingCallback{callback, std::move(result)};
  }

  void ReleaseNode(EndpointNode* node) noexcept {
    if (node == nullptr || pool_ == nullptr) return;
    const auto slot = detail::NodeSlot(node->state);
    node->owner = nullptr;
    node->callback = {};
    node->state = detail::RetireNodeWord(node->state);
    if (slot < pool_->nodes.size()) pool_->free_bits = pool_->free_bits.set(slot);
  }

  [[nodiscard]] EndpointNode* FindJob(QueryHandle handle) noexcept {
    if (pool_ == nullptr || handle.Qid() != detail::kJobMark || handle.Slot() >= pool_->nodes.size()) return nullptr;
    auto& node = pool_->nodes[handle.Slot()];
    if (!detail::NodeLive(node.state) || node.owner != this || detail::NodeGeneration(node.state) != handle.Generation()) {
      return nullptr;
    }
    return &node;
  }
  [[nodiscard]] std::optional<Result<EndpointList>> TryFast(const ParsedEndpoint& parsed) noexcept {
    return detail::LookupFastPath(parsed, config_.family, config_.enable_cache, hosts_, &cache_);
  }
  void StoreCache(const EndpointNode& node) noexcept { detail::StoreNodeInCache(node, config_.enable_cache, &cache_); }

  void FailHandle(QueryHandle handle) noexcept {
    static_cast<void>(CancelQuery(handle));
    StepDriver();
  }

  [[nodiscard]] Result<void> Pump(const bool* done, QueryHandle handle, std::uint32_t timeout_ms) noexcept {
    if (proactor_ == nullptr || done == nullptr) {
      static_cast<void>(CancelQuery(handle));
      return std::unexpected(Error::InvalidArgument());
    }
    if (stepping_) return detail::RejectReentrant(CancelQuery(handle));
    Dispatcher dispatcher{this};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{timeout_ms};
    while (!*done) {
      if (std::chrono::steady_clock::now() >= deadline) {
        FailHandle(handle);
        return std::unexpected(Error::Timeout());
      }
      StepDriver();
      if (*done) break;
      if (phase_ == DriverPhase::Faulted) {
        FailHandle(handle);
        phase_ = DriverPhase::Faulted;
        return std::unexpected(Error::FromUring(uring::UringErrorCode::kInvalid));
      }
      auto remain = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - std::chrono::steady_clock::now());
      if (remain.count() < 0) remain = std::chrono::nanoseconds{0};
      auto waited = proactor_->WaitCompletions(1, remain, dispatcher);
      if (!waited && waited.error() == uring::UringErrorCode::kBusy) waited = proactor_->Tick(dispatcher);
      if (!waited && waited.error() != uring::UringErrorCode::kTimedOut && waited.error() != uring::UringErrorCode::kNoEntry) {
        FailHandle(handle);
        return std::unexpected(Error::FromUring(waited.error()));
      }
    }
    if (core_.ActiveQueryCount() == 0) WaitOwnIdle();
    return {};
  }

  LibraryGuard guard_;
  uring::Proactor* proactor_{nullptr};
  PollTable<MaxSockets> polls_{};
  ChannelCore<MaxInflight> core_{};
  StaticHostTable<MaxStaticHosts> hosts_{};
  DnsCache<MaxCacheEntries> cache_;
  ResolverConfig config_{};
  std::unique_ptr<EndpointPool> pool_{};
  DriverPhase phase_{DriverPhase::Idle};
  bool timer_fired_{false};
  bool stepping_{false};
  bool foreign_ready_{false};
  std::array<detail::PollArm, MaxSockets> arms_{};
  std::array<ares_fd_events_t, MaxSockets> ready_{};
  std::uint16_t ready_count_{0};
  std::uint16_t pending_count_{0};
};

using DefaultResolver = Resolver<>;

}  // namespace cares
