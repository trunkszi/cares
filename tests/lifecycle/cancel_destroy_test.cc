#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <uring/uring.hpp>

#include "../e2e/local_dns_fixture.hpp"

namespace {

struct Counter {
  int hits{0};
  bool ok{false};
  void On(cares::Result<cares::EndpointList> res) noexcept {
    ++hits;
    ok = res.has_value() && !res->empty();
  }
};

struct RawCounter {
  int hits{0};
  bool ok{false};
  void On(cares::Result<cares::DnsRecordRef> res) noexcept {
    ++hits;
    ok = res.has_value() && res->IsValid();
  }
};

int Fail(const char* what) {
  std::fprintf(stderr, "FAIL %s\n", what);
  return 1;
}

int CancelBeforeCallback() {
  cares::test::LocalDns dns(cares::test::DnsMode::Drop);
  if (dns.Port() == 0) return Fail("bind");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 1000, 1), cares::test::Ipv4Config());
  if (!made) return Fail("resolver");
  Counter counter;
  auto handle = made->SubmitEndpoints("app.example", 53, uarch::bind<&Counter::On>(counter));
  if (!handle) return Fail("submit");
  made->StepDriver();
  uring::SingleDispatcher<cares::Resolver<>> dispatcher{*made};
  static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{40}, dispatcher));
  if (!made->CancelQuery(*handle)) return Fail("cancel");
  if (made->CancelQuery(*handle)) return Fail("double cancel");
  made->StepDriver();
  static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{40}, dispatcher));
  if (counter.hits != 0) return Fail("callback ran");
  return 0;
}

int DestroyWhileInFlight() {
  cares::test::LocalDns dns(cares::test::DnsMode::Drop);
  if (dns.Port() == 0) return Fail("bind");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring");
  {
    auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 1000, 1), cares::test::Ipv4Config());
    if (!made) return Fail("resolver");
    Counter counter;
    auto handle = made->SubmitEndpoints("app.example", 53, uarch::bind<&Counter::On>(counter));
    if (!handle) return Fail("submit");
    made->StepDriver();
    uring::SingleDispatcher<cares::Resolver<>> dispatcher{*made};
    static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{40}, dispatcher));
    if (counter.hits != 0) return Fail("early callback");
  }
  return 0;
}

int CancelOnEarlyExitPaths() {
  cares::test::LocalDns dns(cares::test::DnsMode::Answer);
  if (dns.Port() == 0) return Fail("bind early");
  dns.SetDropReplies(true);
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring early");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 180, 3), cares::test::Ipv4Config());
  if (!made) return Fail("resolver early");
  uring::SingleDispatcher<cares::Resolver<>> dispatcher{*made};

  // 1. Fast-path sentinel handle must not cancel an active slot-0 raw query.
  RawCounter raw_counter;
  auto raw_h =
      made->SubmitQuery("slot0.example", cares::DnsClass::IN, cares::DnsType::A, uarch::bind<&RawCounter::On>(raw_counter));
  if (!raw_h) return Fail("submit raw");
  Counter fast_counter;
  auto fast_h = made->SubmitEndpoints("127.0.0.1:8080", 80, uarch::bind<&Counter::On>(fast_counter));
  if (!fast_h || fast_counter.hits != 1) return Fail("fast hit");
  if (made->CancelQuery(cares::QueryHandle{})) return Fail("invalid handle cancel");
  if (made->CancelQuery(*fast_h)) return Fail("fast handle cancel");
  if (!made->CancelQuery(*raw_h)) return Fail("raw handle cancel");
  if (raw_counter.hits != 0) return Fail("raw callback ran");

  // 2. ResolveEndpoints / ResolveWire / Resolve<T> early-exit on caller deadline shorter than c-ares timeout.
  const auto t0 = std::chrono::steady_clock::now();
  auto ep_res = made->ResolveEndpoints("early.example", 80, 50);
  const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
  if (ep_res || ep_res.error() != cares::Error::Timeout() || elapsed_ms >= 800) return Fail("early endpoint timeout");
  if (made->ActiveQueryCount() == 0u) return Fail("expected cancelled slot still active after endpoint timeout");

  auto wire_res = made->ResolveWire("early-wire.example", cares::DnsType::A, 40);
  if (wire_res || wire_res.error() != cares::Error::Timeout()) return Fail("early wire timeout");
  if (made->ActiveQueryCount() == 0u) return Fail("expected cancelled slot still active after wire timeout");

  auto typed_res = made->Resolve<cares::ARecord>("early-typed.example", cares::DnsType::A, 40);
  if (typed_res || typed_res.error() != cares::Error::Timeout()) return Fail("early typed timeout");
  if (made->ActiveQueryCount() == 0u) return Fail("expected cancelled slot still active after typed timeout");

  // Resume replies so c-ares retries complete and naturally reclaim all cancelled slots without invoking expired delegates.
  dns.SetDropReplies(false);
  const auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{900};
  while (made->ActiveQueryCount() != 0u && std::chrono::steady_clock::now() < drain_deadline) {
    made->StepDriver();
    if (made->ActiveQueryCount() == 0u) break;
    static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{25}, dispatcher));
  }
  if (raw_counter.hits != 0) return Fail("cancelled raw callback ran during natural drain");
  if (made->ActiveQueryCount() != 0u) return Fail("active after natural retry drain");
  return 0;
}

struct ForeignCollector {
  int hits{0};
  std::uint8_t id{0};
  void OnForeignDeliveries(std::span<const uring::Delivery> deliveries) noexcept {
    hits += static_cast<int>(deliveries.size());
    if (!deliveries.empty()) id = uring::Subsystem(deliveries.front().completion.token);
  }
};

struct AcceptAll {
  [[nodiscard]] static uring::Result<void> DispatchBatch(std::span<const uring::Delivery>) noexcept { return {}; }
};

int SharedProactorForeignCqeSurvivesResolverQuiesce() {
  cares::test::LocalDns dns(cares::test::DnsMode::Drop);
  if (dns.Port() == 0) return Fail("bind foreign");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring foreign");
  ForeignCollector collector;
  uring::abi::KernelTimespec timeout{0, 1'000'000};
  {
    auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 2000, 1), cares::test::Ipv4Config());
    if (!made) return Fail("resolver foreign");
    made->BindForeignRouter(&collector);
    if (!made->ForeignObserver()) return Fail("observer unbound");
    Counter counter;
    auto handle = made->SubmitEndpoints("foreign.example", 53, uarch::bind<&Counter::On>(counter));
    if (!handle) return Fail("submit foreign");
    made->StepDriver();
    if (made->ActiveQueryCount() == 0) return Fail("query idle");
    auto armed = ring->ArmOneShot(static_cast<std::uint8_t>(3), uring::ops::PrepareTimeout(&timeout, 0));
    if (!armed) return Fail("arm foreign");
    // DrainOwnIdle returns once cares arms are idle, so the foreign CQE must already sit in the CQ.
    if (!ring->Backend().SubmitAndWait(1) || ring->Backend().Cq().Available() == 0) return Fail("foreign cqe not queued");
  }
  if (collector.hits != 1 || collector.id != 3) {
    if (ring->InFlight() != 0) {
      AcceptAll drain;
      static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{50}, drain));
    }
    return Fail("foreign cqe lost");
  }
  if (ring->InFlight() != 0) return Fail("foreign op still in flight");
  return 0;
}

int BlockingTimeoutDoesNotCancelConcurrentAsyncQuery() {
  cares::test::LocalDns dns(cares::test::DnsMode::Answer);
  if (dns.Port() == 0) return Fail("bind concurrent");
  dns.SetDropReplies(true);
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring concurrent");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 160, 4), cares::test::Ipv4Config());
  if (!made) return Fail("resolver concurrent");
  uring::SingleDispatcher<cares::Resolver<>> dispatcher{*made};

  // 1. Async B waits for retry while cancelled A's natural wire reply arrives first.
  Counter b_counter;
  auto b_h = made->SubmitEndpoints("b-pending.example", 80, uarch::bind<&Counter::On>(b_counter));
  if (!b_h) return Fail("submit B");
  made->StepDriver();
  static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{30}, dispatcher));

  dns.SetDropReplies(false);
  Counter a_counter;
  auto a_h = made->SubmitEndpoints("a-cancelled.example", 80, uarch::bind<&Counter::On>(a_counter));
  if (!a_h) return Fail("submit A");
  made->StepDriver();
  if (!made->CancelQuery(*a_h)) return Fail("cancel A");

  const auto deadline1 = std::chrono::steady_clock::now() + std::chrono::milliseconds{900};
  while (b_counter.hits == 0 && std::chrono::steady_clock::now() < deadline1) {
    made->StepDriver();
    if (b_counter.hits != 0) break;
    static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{25}, dispatcher));
  }
  if (a_counter.hits != 0) return Fail("cancelled A callback fired");
  if (b_counter.hits != 1 || !b_counter.ok) return Fail("pending B was killed after cancelled A reply arrived");
  if (made->ActiveQueryCount() != 0u) return Fail("active after B completion");

  // 2. Blocking deadline timeout while concurrent async query is waiting for retry.
  dns.SetDropReplies(true);
  Counter async_counter;
  auto async_h = made->SubmitEndpoints("survive.example", 80, uarch::bind<&Counter::On>(async_counter));
  if (!async_h) return Fail("submit concurrent async");
  made->StepDriver();
  static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{20}, dispatcher));

  auto timed_out = made->ResolveEndpoints("short-deadline.example", 80, 35);
  if (timed_out || timed_out.error() != cares::Error::Timeout()) return Fail("short deadline did not timeout");
  if (async_counter.hits != 0) return Fail("concurrent async fired while replies dropped");
  if (made->ActiveQueryCount() == 0u) return Fail("concurrent async query was cancelled by blocking timeout");

  dns.SetDropReplies(false);
  const auto deadline2 = std::chrono::steady_clock::now() + std::chrono::milliseconds{900};
  while ((async_counter.hits == 0 || made->ActiveQueryCount() != 0u) && std::chrono::steady_clock::now() < deadline2) {
    made->StepDriver();
    if (async_counter.hits != 0 && made->ActiveQueryCount() == 0u) break;
    static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{25}, dispatcher));
  }
  if (async_counter.hits != 1 || !async_counter.ok) return Fail("concurrent async query did not complete");
  if (made->ActiveQueryCount() != 0u) return Fail("active after concurrent async completion");

  // 3. Raw async SubmitQuery stays live across a blocking ResolveEndpoints timeout.
  dns.SetDropReplies(true);
  RawCounter raw_concurrent;
  auto raw_h = made->SubmitQuery("raw-concurrent.example", cares::DnsClass::IN, cares::DnsType::A,
                                 uarch::bind<&RawCounter::On>(raw_concurrent));
  if (!raw_h) return Fail("submit raw concurrent");
  made->StepDriver();
  static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{20}, dispatcher));

  auto blocking_res = made->ResolveEndpoints("blocking-timeout.example", 80, 40);
  if (blocking_res || blocking_res.error() != cares::Error::Timeout()) return Fail("blocking timeout failed");
  if (raw_concurrent.hits != 0) return Fail("raw concurrent fired early or was cancelled");

  dns.SetDropReplies(false);
  const auto deadline3 = std::chrono::steady_clock::now() + std::chrono::milliseconds{900};
  while ((raw_concurrent.hits == 0 || made->ActiveQueryCount() != 0u) && std::chrono::steady_clock::now() < deadline3) {
    made->StepDriver();
    if (raw_concurrent.hits != 0 && made->ActiveQueryCount() == 0u) break;
    static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{25}, dispatcher));
  }
  if (raw_concurrent.hits != 1 || !raw_concurrent.ok) return Fail("raw concurrent query did not complete");
  if (made->ActiveQueryCount() != 0u) return Fail("active after raw concurrent completion");
  return 0;
}

int DestroyDuringReentrantDrive() {
  cares::test::LocalDns dns(cares::test::DnsMode::Drop);
  if (dns.Port() == 0) return Fail("bind reenter");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring reenter");
  auto created = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 1500, 1), cares::test::Ipv4Config());
  if (!created) return Fail("resolver reenter");
  std::optional<cares::Resolver<>> made{std::move(*created)};
  Counter counter;
  auto handle = made->SubmitEndpoints("reenter.example", 53, uarch::bind<&Counter::On>(counter));
  if (!handle) return Fail("submit reenter");
  made->StepDriver();
  uring::abi::KernelTimespec poke{0, 1'000'000};
  if (!ring->ArmOneShot(static_cast<std::uint8_t>(3), uring::ops::PrepareTimeout(&poke, 0))) return Fail("poke arm");
  struct ReenterDestroy {
    std::optional<cares::Resolver<>>* slot{nullptr};
    int hits{0};
    [[nodiscard]] uring::Result<void> DispatchBatch(std::span<const uring::Delivery> deliveries) noexcept {
      ++hits;
      if (slot != nullptr && slot->has_value()) {
        (*slot)->OnCompletions(deliveries);
        slot->reset();
      }
      return {};
    }
  } killer;
  killer.slot = &made;
  auto waited = ring->WaitCompletions(1, std::chrono::milliseconds{200}, killer);
  if (!waited && waited.error() != uring::UringErrorCode::kTimedOut && waited.error() != uring::UringErrorCode::kNoEntry) {
    return Fail("reenter wait");
  }
  if (killer.hits == 0 || made.has_value()) return Fail("resolver survived reentrant drive");
  AcceptAll drain;
  const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds{400};
  while (ring->InFlight() != 0 && std::chrono::steady_clock::now() < end) {
    static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{25}, drain));
  }
  return 0;
}

}  // namespace

int main() {
  if (const int failed = CancelBeforeCallback(); failed != 0) return failed;
  if (const int failed = DestroyDuringReentrantDrive(); failed != 0) return failed;
  if (const int failed = DestroyWhileInFlight(); failed != 0) return failed;
  if (const int failed = CancelOnEarlyExitPaths(); failed != 0) return failed;
  if (const int failed = SharedProactorForeignCqeSurvivesResolverQuiesce(); failed != 0) return failed;
  return BlockingTimeoutDoesNotCancelConcurrentAsyncQuery();
}
