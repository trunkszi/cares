#include <cares/channel/timer_state.hpp>
#include <cstdint>
#include <cstdio>
#include <limits>

namespace {

int g_failed = 0;

void Check(bool ok, const char* name) {
  if (!ok) {
    std::fprintf(stderr, "FAIL %s\n", name);
    ++g_failed;
  }
}

void MissingTimeoutDisarmed() {
  const auto missing = cares::ComputeTimerDeadline(false, -1, -1);
  Check(!missing.armed && missing.relative_ns == 0, "missing");
  const auto due = cares::ComputeTimerDeadline(true, 0, 0);
  Check(due.armed && due.relative_ns == 0, "due_now");
}

void TimevalToNs() {
  const auto delay = cares::ComputeTimerDeadline(true, 1, 1);
  Check(delay.armed, "armed");
  Check(delay.relative_ns == 1'000'000'000ULL + 1'000ULL, "1s1us");
  const auto two = cares::ComputeTimerDeadline(true, 1, 2);
  Check(two.relative_ns == 1'000'000'000ULL + 2'000ULL, "1s2us");
}

void OverdueClampsToZero() {
  const auto sec = cares::ComputeTimerDeadline(true, -1, 10);
  const auto usec = cares::ComputeTimerDeadline(true, 2, -1);
  Check(sec.armed && sec.relative_ns == 0, "neg_sec");
  Check(usec.armed && usec.relative_ns == 0, "neg_usec");
}

void UsecNormalizes() {
  const auto delay = cares::ComputeTimerDeadline(true, 0, 1'000'001);
  Check(delay.armed, "armed");
  Check(delay.relative_ns == 1'000'000'000ULL + 1'000ULL, "carry");
  const auto ceiling = cares::ComputeTimerDeadline(true, std::numeric_limits<std::int64_t>::max(), 0);
  Check(ceiling.armed && ceiling.relative_ns == std::numeric_limits<std::uint64_t>::max(), "ceiling");
}

void SumSaturates() {
  constexpr std::int64_t kSec = 18446744073LL;
  constexpr std::int64_t kUsec = 709552LL;
  const auto overflow = cares::ComputeTimerDeadline(true, kSec, kUsec);
  Check(overflow.armed && overflow.relative_ns == std::numeric_limits<std::uint64_t>::max(), "sum");
  const auto carry = cares::ComputeTimerDeadline(true, std::numeric_limits<std::int64_t>::max(), 1'000'000);
  Check(carry.armed && carry.relative_ns == std::numeric_limits<std::uint64_t>::max(), "carry_sec");
}

}  // namespace

int main() {
  MissingTimeoutDisarmed();
  TimevalToNs();
  OverdueClampsToZero();
  UsecNormalizes();
  SumSaturates();
  if (g_failed != 0) {
    std::fprintf(stderr, "timer_state_test failed %d\n", g_failed);
    return 1;
  }
  std::fprintf(stdout, "ok timer_state_test\n");
  return 0;
}
