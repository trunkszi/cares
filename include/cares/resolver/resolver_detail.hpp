/** @file
 *  @brief Internal state words, cancellation tracking, and answer deduplication for `cares::Resolver`.
 */
#pragma once

#include <ares.h>
#include <ares_dns_record.h>

#include <algorithm>
#include <array>
#include <cares/channel/callback_table.hpp>
#include <cares/channel/socket_bridge.hpp>
#include <cares/channel/timer_state.hpp>
#include <cares/error/ares_error.hpp>
#include <cares/record/dns_record.hpp>
#include <cares/record/record_extract.hpp>
#include <cares/resolver/dns_cache.hpp>
#include <cares/resolver/poll_table.hpp>
#include <cares/resolver/proactor_claim.hpp>
#include <cares/types/dns_types.hpp>
#include <cares/types/endpoint.hpp>
#include <cares/types/host_types.hpp>
#include <cares/types/query_handle.hpp>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <uarch/uarch.hpp>
#include <uring/uring.hpp>
#include <utility>

namespace cares {

/** @brief Receives CQE runs whose subsystem id this resolver does not own. */
using ForeignBatchObserver = Delegate<void(std::span<const uring::Delivery>)>;

/** @brief Configuration for `cares::Resolver`. */
struct ResolverConfig {
  IpFamily family{IpFamily::DualStack};
  bool enable_hosts{true};
  bool enable_cache{true};
  DnsCacheConfig cache_config{};
  std::uint8_t subsystem_id{kPollSubsystemId};
  ForeignBatchObserver foreign_observer{};
};

/** @brief Deterministic 3-stage driver phase plus cancellation drain and fault states. */
enum class DriverPhase : std::uint8_t {
  Idle = 0,
  HarvestReadySockets = 1,
  FlushSocketSubmissions = 2,
  ReconcileTimer = 3,
  DrainingCancel = 4,
  Faulted = 5,
};

using EndpointsCallback = Delegate<void(Result<EndpointList>)>;

/**
 * @brief Reflected 64-bit state word for dual-stack (`A` + `AAAA`) endpoint jobs.
 * Flags sit in bits 0..6 for `imm32` single-instruction masks; generation occupies bits 32..63.
 */
struct DualStackWordSpec {
  using Word = std::uint64_t;
  bool live[[= uarch::bits::Flag{0}]];
  bool want_v4[[= uarch::bits::Flag{1}]];
  bool want_v6[[= uarch::bits::Flag{2}]];
  bool v4_done[[= uarch::bits::Flag{3}]];
  bool v6_done[[= uarch::bits::Flag{4}]];
  bool suppress[[= uarch::bits::Flag{5}]];
  bool saw_error[[= uarch::bits::Flag{6}]];
  std::uint16_t slot[[= uarch::bits::Field{16, 16}]];
  std::uint32_t generation[[= uarch::bits::Field{32, 32}]];
};
using DualStackWord = uarch::BitWord<DualStackWordSpec>;
static_assert(sizeof(DualStackWord) == 8);
static_assert(uarch::NoPadding<DualStackWord> && uarch::RegisterPassable<DualStackWord>);

namespace detail {

inline constexpr std::uint32_t kJobMark = 0x80000000u;
inline constexpr std::uint32_t kFastMark = 0x40000000u;
inline constexpr std::uint32_t kPollIn = 0x0001u;
inline constexpr std::uint32_t kPollOut = 0x0004u;

[[nodiscard]] inline constexpr SocketInterest DesiredInterest(PollSlotWord word) noexcept {
  return word.get<^^PollSlotSpec::desired>();
}

[[nodiscard]] inline constexpr std::uint32_t PollEventsFor(SocketInterest desired) noexcept {
  std::uint32_t events = 0;
  if (desired == SocketInterest::Read || desired == SocketInterest::ReadWrite) events |= kPollIn;
  if (desired == SocketInterest::Write || desired == SocketInterest::ReadWrite) events |= kPollOut;
  return events;
}

[[nodiscard]] inline constexpr bool NodeLive(DualStackWord word) noexcept { return word.test<^^DualStackWordSpec::live>(); }
[[nodiscard]] inline constexpr bool NodeWantV4(DualStackWord word) noexcept {
  return word.test<^^DualStackWordSpec::want_v4>();
}
[[nodiscard]] inline constexpr bool NodeWantV6(DualStackWord word) noexcept {
  return word.test<^^DualStackWordSpec::want_v6>();
}
[[nodiscard]] inline constexpr bool NodeV4Done(DualStackWord word) noexcept {
  return word.test<^^DualStackWordSpec::v4_done>();
}
[[nodiscard]] inline constexpr bool NodeV6Done(DualStackWord word) noexcept {
  return word.test<^^DualStackWordSpec::v6_done>();
}
[[nodiscard]] inline constexpr bool NodeSuppress(DualStackWord word) noexcept {
  return word.test<^^DualStackWordSpec::suppress>();
}
[[nodiscard]] inline constexpr bool NodeSawError(DualStackWord word) noexcept {
  return word.test<^^DualStackWordSpec::saw_error>();
}
[[nodiscard]] inline constexpr std::uint16_t NodeSlot(DualStackWord word) noexcept {
  return word.get<^^DualStackWordSpec::slot>();
}
/// Issued generations are 1..0xFFFE. Zero stays reserved, and 0xFFFE retires back to 1.
[[nodiscard]] inline constexpr std::uint32_t NodeEpoch(DualStackWord word) noexcept {
  const auto gen = word.get<^^DualStackWordSpec::generation>();
  if (gen == 0 || gen > 0xFFFEu) return 1u;
  return gen;
}

[[nodiscard]] inline constexpr std::uint16_t NodeGeneration(DualStackWord word) noexcept {
  return static_cast<std::uint16_t>(NodeEpoch(word));
}

[[nodiscard]] inline constexpr DualStackWord BumpNodeGeneration(DualStackWord word) noexcept {
  const auto gen = word.get<^^DualStackWordSpec::generation>();
  const std::uint32_t next = (gen == 0 || gen >= 0xFFFEu) ? 1u : gen + 1u;
  return word.with<^^DualStackWordSpec::generation>(next);
}

[[nodiscard]] inline constexpr DualStackWord InitNodeWord(DualStackWord prev, std::uint16_t slot, bool want_v4,
                                                          bool want_v6) noexcept {
  const std::uint32_t gen = NodeEpoch(prev);
  DualStackWord word{};
  word = word.with<^^DualStackWordSpec::live>(true);
  word = word.with<^^DualStackWordSpec::want_v4>(want_v4);
  word = word.with<^^DualStackWordSpec::want_v6>(want_v6);
  word = word.with<^^DualStackWordSpec::slot>(slot);
  word = word.with<^^DualStackWordSpec::generation>(gen);
  return word;
}

[[nodiscard]] inline constexpr DualStackWord MarkNodeDone(DualStackWord word, bool v4) noexcept {
  if (v4) return word.with<^^DualStackWordSpec::v4_done>(true);
  return word.with<^^DualStackWordSpec::v6_done>(true);
}

[[nodiscard]] inline constexpr DualStackWord MarkNodeError(DualStackWord word) noexcept {
  return word.with<^^DualStackWordSpec::saw_error>(true);
}

[[nodiscard]] inline constexpr DualStackWord MarkNodeSuppress(DualStackWord word) noexcept {
  return word.with<^^DualStackWordSpec::suppress>(true);
}

[[nodiscard]] inline constexpr DualStackWord RetireNodeWord(DualStackWord word) noexcept {
  word = BumpNodeGeneration(word);
  word = word.with<^^DualStackWordSpec::live>(false);
  word = word.with<^^DualStackWordSpec::want_v4>(false);
  word = word.with<^^DualStackWordSpec::want_v6>(false);
  word = word.with<^^DualStackWordSpec::v4_done>(false);
  word = word.with<^^DualStackWordSpec::v6_done>(false);
  word = word.with<^^DualStackWordSpec::suppress>(false);
  word = word.with<^^DualStackWordSpec::saw_error>(false);
  return word;
}

[[nodiscard]] inline constexpr bool NodeAllDone(DualStackWord word) noexcept {
  return (!NodeWantV4(word) || NodeV4Done(word)) && (!NodeWantV6(word) || NodeV6Done(word));
}

[[nodiscard]] inline constexpr bool FamilyAccepts(IpFamily family, const IpAddress& ip) noexcept {
  if (family == IpFamily::Ipv4) return ip.IsV4();
  if (family == IpFamily::Ipv6) return ip.IsV6();
  return ip.IsV4() || ip.IsV6();
}

[[nodiscard]] inline std::uint64_t NowNs() noexcept {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

[[nodiscard]] inline constexpr bool SameToken(uring::UserDataToken lhs, uring::UserDataToken rhs) noexcept {
  return lhs.raw() == rhs.raw();
}

[[nodiscard]] inline constexpr uring::abi::KernelTimespec FillTimespec(std::uint64_t relative_ns) noexcept {
  const auto ns = relative_ns == 0 ? std::uint64_t{1} : relative_ns;
  constexpr auto kSecDiv = uarch::divisor_u64<1000000000ULL>();
  return uring::abi::KernelTimespec{
      .tv_sec = static_cast<std::int64_t>(kSecDiv.div(ns)),
      .tv_nsec = static_cast<std::int64_t>(kSecDiv.rem(ns)),
  };
}

struct PollArm {
  int fd{-1};
  bool poll_live{false};
  bool remove_live{false};
  bool cancel_requested{false};
  bool cancel_retry{false};
  SocketInterest armed_interest{SocketInterest::None};
  std::uint32_t generation{0};
  uring::UserDataToken poll{};
  uring::UserDataToken remove{};
};

struct TimerArm {
  uring::abi::KernelTimespec spec{};
  uring::UserDataToken timeout_token{};
  uring::UserDataToken remove_token{};
  std::uint64_t armed_ns{0};
  bool timeout_live{false};
  bool remove_live{false};
  bool cancel_requested{false};
  bool cancel_retry{false};
};

struct PendingCallback {
  EndpointsCallback callback{};
  Result<EndpointList> result{std::unexpected(Error::NotFound())};
};

struct EndpointWait {
  Result<EndpointList> value{std::unexpected(Error::Timeout())};
  bool done{false};
  void On(Result<EndpointList> result) noexcept {
    value = std::move(result);
    done = true;
  }
};

struct WireWait {
  Result<DnsRecord> value{std::unexpected(Error::Timeout())};
  bool done{false};
  void On(Result<DnsRecordRef> result) noexcept {
    if (!result) {
      value = std::unexpected(result.error());
    } else if (auto owned = result->ToOwned(); owned) {
      value = std::move(*owned);
    } else {
      value = std::unexpected(owned.error());
    }
    done = true;
  }
};

[[nodiscard]] inline bool RequestCancelPollArm(uring::Proactor* proactor, std::uint8_t sub_id, PollArm* arm) noexcept {
  if (arm == nullptr || !arm->poll_live) {
    if (arm != nullptr) arm->cancel_requested = arm->cancel_retry = false;
    return true;
  }
  arm->cancel_requested = true;
  if (arm->remove_live) return true;
  if (proactor == nullptr) {
    arm->cancel_retry = true;
    return false;
  }
  auto token = proactor->ArmOneShot(sub_id, uring::ops::PreparePollRemove(arm->poll));
  if (token) {
    arm->remove = *token;
    arm->remove_live = true;
    arm->cancel_retry = false;
    return true;
  }
  arm->cancel_retry = true;
  return false;
}

[[nodiscard]] inline bool RequestCancelTimerArm(uring::Proactor* proactor, std::uint8_t sub_id, TimerArm* timer) noexcept {
  if (timer == nullptr || !timer->timeout_live) {
    if (timer != nullptr) timer->cancel_requested = timer->cancel_retry = false;
    return true;
  }
  timer->cancel_requested = true;
  if (timer->remove_live) return true;
  if (proactor == nullptr) {
    timer->cancel_retry = true;
    return false;
  }
  auto token = proactor->ArmOneShot(sub_id, uring::ops::PrepareTimeoutRemove(timer->timeout_token));
  if (token) {
    timer->remove_token = *token;
    timer->remove_live = true;
    timer->cancel_retry = false;
    return true;
  }
  timer->cancel_retry = true;
  return false;
}

struct TimerCqeOutcome {
  bool matched{false};
  bool fired{false};
};

[[nodiscard]] inline TimerCqeOutcome MatchTimerCqe(std::span<TimerArm, 2> timers, uring::UserDataToken token,
                                                   std::int32_t result) noexcept {
  for (auto& timer : timers) {
    if (timer.timeout_live && timer.timeout_token.raw() != 0 && SameToken(token, timer.timeout_token)) {
      const bool fired = !timer.cancel_requested && result != -ECANCELED;
      timer.timeout_live = false;
      timer.cancel_requested = false;
      timer.cancel_retry = false;
      return {.matched = true, .fired = fired};
    }
    if (timer.remove_live && timer.remove_token.raw() != 0 && SameToken(token, timer.remove_token)) {
      timer.remove_live = false;
      return {.matched = true, .fired = false};
    }
  }
  return {};
}

[[nodiscard]] inline bool ReconcileTimers(uring::Proactor* proactor, std::uint8_t sub_id, std::span<TimerArm, 2> timers,
                                          TimerDeadline next, bool active_queries) noexcept {
  if (!next.armed || !active_queries) {
    bool ok = true;
    for (auto& timer : timers) {
      if (timer.timeout_live && !RequestCancelTimerArm(proactor, sub_id, &timer)) ok = false;
    }
    return ok;
  }
  const auto want = next.relative_ns == 0 ? std::uint64_t{1} : next.relative_ns;
  for (const auto& timer : timers) {
    if (timer.timeout_live && !timer.cancel_requested && timer.armed_ns != 0 && timer.armed_ns <= want) return true;
  }
  for (auto& timer : timers) {
    if (timer.timeout_live && !timer.cancel_requested && timer.armed_ns > want) {
      if (!RequestCancelTimerArm(proactor, sub_id, &timer)) return false;
    }
  }
  for (auto& timer : timers) {
    if (timer.timeout_live || timer.remove_live || timer.cancel_retry) continue;
    timer.spec = FillTimespec(next.relative_ns);
    auto token = proactor->ArmOneShot(sub_id, uring::ops::PrepareTimeout(&timer.spec, 0));
    if (!token) return false;
    timer.timeout_token = *token;
    timer.timeout_live = true;
    timer.cancel_requested = false;
    timer.cancel_retry = false;
    timer.armed_ns = want;
    return true;
  }
  return true;
}

[[nodiscard]] inline bool RetryCancels(uring::Proactor* proactor, std::uint8_t sub_id, std::span<PollArm> arms,
                                       std::span<TimerArm, 2> timers) noexcept {
  bool ok = true;
  for (auto& arm : arms) {
    if (arm.poll_live && arm.cancel_retry && !arm.remove_live) {
      if (!RequestCancelPollArm(proactor, sub_id, &arm)) ok = false;
    }
  }
  for (auto& timer : timers) {
    if (timer.timeout_live && timer.cancel_retry && !timer.remove_live) {
      if (!RequestCancelTimerArm(proactor, sub_id, &timer)) ok = false;
    }
  }
  return ok;
}

[[nodiscard]] inline bool AnyArmBusy(std::span<const PollArm> arms, std::span<const TimerArm, 2> timers) noexcept {
  return std::ranges::any_of(
             timers,
             [](const auto& timer) noexcept { return timer.timeout_live || timer.remove_live || timer.cancel_retry; }) ||
         std::ranges::any_of(arms,
                             [](const auto& arm) noexcept { return arm.poll_live || arm.remove_live || arm.cancel_retry; });
}

template <std::size_t MaxSockets>
[[nodiscard]] inline Result<bool> FlushPollSlots(uring::Proactor* proactor, std::uint8_t sub_id, PollTable<MaxSockets>* polls,
                                                 std::span<PollArm, MaxSockets> arms, bool active_queries) noexcept {
  bool cancel_ok = true;
  if (!active_queries) {
    for (auto& arm : arms) {
      if (arm.poll_live && !arm.cancel_requested) {
        if (!RequestCancelPollArm(proactor, sub_id, &arm)) cancel_ok = false;
      }
    }
    return cancel_ok;
  }
  auto mask = polls->ActiveMask() | polls->DirtyMask();
  while (const auto bit = mask.lowest_one()) {
    if (*bit >= arms.size()) break;
    mask = mask.clear(*bit);
    const auto slot = static_cast<std::uint16_t>(*bit);
    const auto word = polls->SlotAt(slot);
    auto& arm = arms[slot];
    const bool in_use = InUse(word);
    const auto desired = DesiredInterest(word);
    const auto gen = Generation(word);
    if (!in_use || desired == SocketInterest::None) {
      if (arm.poll_live && !arm.cancel_requested) {
        if (!RequestCancelPollArm(proactor, sub_id, &arm)) cancel_ok = false;
      }
      continue;
    }
    if (arm.poll_live) {
      if (!arm.cancel_requested && (arm.generation != gen || arm.armed_interest != desired)) {
        if (!RequestCancelPollArm(proactor, sub_id, &arm)) cancel_ok = false;
      }
      continue;
    }
    if (arm.remove_live) continue;
    const std::uint32_t events = PollEventsFor(desired);
    if (events == 0) continue;
    const auto fd = static_cast<std::int32_t>(FdBits(word));
    auto token = proactor->ArmOneShot(sub_id, uring::ops::PreparePollAdd(fd, events));
    if (!token) return std::unexpected(Error::FromUring(token.error()));
    arm.poll = *token;
    arm.poll_live = true;
    arm.cancel_requested = false;
    arm.cancel_retry = false;
    arm.fd = static_cast<int>(fd);
    arm.armed_interest = desired;
    arm.generation = gen;
    polls->MarkArmed(slot, desired);
  }
  return cancel_ok;
}

template <std::size_t MaxInflight>
inline void PublishPending(std::span<PendingCallback, MaxInflight> pending, std::uint16_t count) noexcept {
  uarch::inplace_vector<PendingCallback, MaxInflight> local{};
  for (std::uint16_t i = 0; i < count; ++i) {
    static_cast<void>(local.try_push_back(std::move(pending[i])));
    pending[i] = {};
  }
  for (auto& item : local) {
    if (item.callback) item.callback(std::move(item.result));
  }
}

template <typename DispatcherT>
[[nodiscard]] inline bool DrainOwnIdle(uring::Proactor* proactor, std::uint8_t sub_id, std::span<PollArm> arms,
                                       std::span<TimerArm, 2> timers, DispatcherT dispatcher) noexcept {
  if (proactor == nullptr) return true;
  bool ok = true;
  for (auto& arm : arms) {
    if (arm.poll_live && !arm.cancel_requested && !RequestCancelPollArm(proactor, sub_id, &arm)) ok = false;
  }
  for (auto& timer : timers) {
    if (timer.timeout_live && !RequestCancelTimerArm(proactor, sub_id, &timer)) ok = false;
  }
  if (!AnyArmBusy(arms, timers)) return ok;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{250};
  while (AnyArmBusy(arms, timers)) {
    if (!RetryCancels(proactor, sub_id, arms, timers)) ok = false;
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return false;
    auto wait_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now);
    if (wait_ns > std::chrono::milliseconds{5}) wait_ns = std::chrono::milliseconds{5};
    auto res = proactor->WaitCompletions(1, wait_ns, dispatcher);
    if (!res && res.error() == uring::UringErrorCode::kBusy) res = proactor->Tick(dispatcher);
    if (!res && res.error() != uring::UringErrorCode::kTimedOut && res.error() != uring::UringErrorCode::kNoEntry) {
      return false;
    }
  }
  return ok;
}

template <std::size_t MaxInflight>
[[nodiscard]] inline constexpr uarch::Bitmap64 InitialFreeMask() noexcept {
  static_assert(MaxInflight > 0 && MaxInflight <= 64);
  if constexpr (MaxInflight == 64) {
    return uarch::Bitmap64::all();
  } else {
    return uarch::Bitmap64::from_raw((std::uint64_t{1} << MaxInflight) - 1u);
  }
}

}  // namespace detail

}  // namespace cares

#include <cares/resolver/resolver_answer.hpp>
