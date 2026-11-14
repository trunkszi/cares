#include <ares.h>

#include <cares/channel/socket_bridge.hpp>
#include <cares/types/endpoint.hpp>
#include <concepts>
#include <cstdio>
#include <uarch/core/flow/delegate.hpp>

namespace {

int g_failed = 0;

void Check(bool ok, const char* name) {
  if (!ok) {
    std::fprintf(stderr, "FAIL %s\n", name);
    ++g_failed;
  }
}

static_assert(cares::InterestFromFlags(0, 0) == cares::SocketInterest::None);
static_assert(cares::InterestFromFlags(1, 0) == cares::SocketInterest::Read);
static_assert(cares::InterestFromFlags(0, 2) == cares::SocketInterest::Write);
static_assert(cares::InterestFromFlags(1, 1) == cares::SocketInterest::ReadWrite);

constexpr cares::SocketStateTransition FirstRead() {
  cares::SocketBridge bridge;
  return bridge.Apply(7, 1, 0);
}

static_assert(FirstRead().fd == 7);
static_assert(FirstRead().previous == cares::SocketInterest::None);
static_assert(FirstRead().next == cares::SocketInterest::Read);
static_assert(FirstRead().tracked);

struct Observer {
  int calls{0};
  int fd{-1};
  cares::SocketInterest interest{cares::SocketInterest::None};
  void OnState(int socket_fd, cares::SocketInterest next) noexcept {
    ++calls;
    fd = socket_fd;
    interest = next;
  }
};

int AddInts(int left, int right) noexcept { return left + right; }

struct BiasedAdd {
  int bias{0};
  [[nodiscard]] int Apply(int left, int right) const noexcept { return left + right + bias; }
};

void DelegateReturnsInt() {
  const auto added = uarch::bind<&AddInts>();
  Check(static_cast<bool>(added) && added(2, 3) == 5, "from_fn");
  BiasedAdd biased{10};
  const auto bound = uarch::bind<&BiasedAdd::Apply>(biased);
  Check(bound(2, 3) == 15, "bind");
  Check(bound.context() == &biased && bound.stub() != nullptr, "parts");
  auto raw = cares::Delegate<int(int, int)>::from_raw(
      [](void* context, int left, int right) noexcept { return static_cast<BiasedAdd*>(context)->Apply(left, right); },
      &biased);
  Check(raw(7, 8) == 25 && raw.context() == &biased && raw.stub() != nullptr, "raw_binding");
  auto callable = [bias = 20](int left, int right) noexcept { return bias + left + right; };
  auto stateful = cares::Delegate<int(int, int)>::from_raw(
      [](void* context, int left, int right) noexcept { return (*static_cast<decltype(callable)*>(context))(left, right); },
      &callable);
  Check(stateful(2, 3) == 25, "stateful_binding");
  static_assert(std::same_as<cares::Delegate<void(int)>, uarch::Callback<void(int)>>);
  static_assert(alignof(cares::Delegate<void(int)>) == 8 && uarch::NoPadding<cares::Delegate<void(int)>>);
  static_assert(sizeof(cares::Delegate<int(int, int)>) == 16);
  static_assert(uarch::GprPair<cares::Delegate<void(int)>>);
}

void LargeResultUsesCallerStorage() {
  using Result = cares::Result<cares::EndpointList>;
  struct Capture {
    const Result* address{};
    bool successful{};
  } capture;
  auto callback = cares::Delegate<void(Result)>::from_raw(
      [](void* context, Result&& value) noexcept {
        auto& state = *static_cast<Capture*>(context);
        state.address = &value;
        state.successful = value.has_value();
      },
      &capture);
  Result result{std::in_place};
  const Result* const expected_address = &result;
  callback(std::move(result));
  Check(capture.address == expected_address && capture.successful, "consuming_reference");
}

void InterestFromFlags() {
  Check(cares::InterestFromFlags(0, 0) == cares::SocketInterest::None, "none");
  Check(cares::InterestFromFlags(4, 0) == cares::SocketInterest::Read, "read");
  Check(cares::InterestFromFlags(0, 9) == cares::SocketInterest::Write, "write");
  Check(cares::InterestFromFlags(4, 9) == cares::SocketInterest::ReadWrite, "both");
}

void TrampolineInvokesObserver() {
  cares::SocketBridge bridge;
  Observer observer;
  bridge.SetObserver(uarch::bind<&Observer::OnState>(observer));
  Check(bridge.HasObserver(), "bound");
  ares_sock_state_cb callback = cares::SocketStateTrampoline;
  Check(callback != nullptr, "assign");
  ares_options options{};
  bridge.Bind(&options);
  Check(options.sock_state_cb == callback, "installed");
  Check(options.sock_state_cb_data == &bridge, "data");
  callback(options.sock_state_cb_data, 11, 1, 0);
  Check(observer.calls == 1, "called");
  Check(observer.fd == 11, "fd");
  Check(observer.interest == cares::SocketInterest::Read, "interest");
}

void ReadToReadwriteKeepsPrev() {
  cares::SocketBridge bridge;
  const auto first = bridge.Apply(4, 1, 0);
  const auto second = bridge.Apply(4, 1, 1);
  Check(first.next == cares::SocketInterest::Read, "first");
  Check(second.previous == cares::SocketInterest::Read, "previous");
  Check(second.next == cares::SocketInterest::ReadWrite, "next");
  Check(second.tracked, "tracked");
}

void CloseClearsSlotReuses() {
  cares::SocketBridge bridge;
  Check(bridge.Apply(4, 1, 0).tracked, "open");
  const auto closed = bridge.Apply(4, 0, 0);
  Check(closed.tracked, "close_tracked");
  Check(closed.previous == cares::SocketInterest::Read, "close_prev");
  Check(closed.next == cares::SocketInterest::None, "close_next");
  const auto reused = bridge.Apply(99, 0, 1);
  Check(reused.tracked, "reused");
  Check(reused.previous == cares::SocketInterest::None, "reused_prev");
  Check(reused.next == cares::SocketInterest::Write, "reused_next");
  const auto unknown = bridge.Apply(50, 0, 0);
  Check(unknown.tracked && unknown.previous == cares::SocketInterest::None, "unknown_close");
}

void FullTableTrackedFalse() {
  cares::SocketBridge bridge;
  Observer observer;
  bridge.SetObserver(uarch::bind<&Observer::OnState>(observer));
  for (int fd = 1; fd <= 64; ++fd) {
    const auto edge = bridge.Apply(fd, 1, 0);
    Check(edge.tracked, "fit");
    if (!edge.tracked) return;
  }
  cares::SocketStateTrampoline(&bridge, 65, 1, 1);
  Check(observer.calls == 1, "still_notified");
  Check(observer.fd == 65, "overflow_fd");
  Check(observer.interest == cares::SocketInterest::ReadWrite, "overflow_interest");
  const auto missed = bridge.Apply(65, 1, 1);
  Check(!missed.tracked, "untracked");
}

}  // namespace

int main() {
  DelegateReturnsInt();
  LargeResultUsesCallerStorage();
  InterestFromFlags();
  TrampolineInvokesObserver();
  ReadToReadwriteKeepsPrev();
  CloseClearsSlotReuses();
  FullTableTrackedFalse();
  if (g_failed != 0) {
    std::fprintf(stderr, "socket_bridge_test failed %d\n", g_failed);
    return 1;
  }
  std::fprintf(stdout, "ok socket_bridge_test\n");
  return 0;
}
