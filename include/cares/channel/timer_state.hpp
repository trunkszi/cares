/** @file @brief Value deadline converted from an `ares_timeout` timeval. */
#pragma once

#include <cstdint>
#include <limits>

namespace cares {

/** @brief Relative wake-up delay. `armed == false` means c-ares reported no timeout. */
struct TimerDeadline {
  bool armed{false};
  std::uint64_t relative_ns{0};

  friend constexpr bool operator==(const TimerDeadline&, const TimerDeadline&) noexcept = default;
};

/**
 * @brief Convert an `ares_timeout` result into a nanosecond delay.
 * @param has_timeout False when `ares_timeout` reported no pending query deadline.
 * @param tv_sec Seconds field of the timeval.
 * @param tv_usec Microseconds field. Values at or above 1000000 are normalized into seconds.
 *
 * A negative field with `has_timeout` is an overdue deadline and stays armed at delay 0.
 * A positive timeval that does not fit in `uint64` nanoseconds stays armed at the maximum
 * delay so the multiply cannot wrap into the past.
 */
[[nodiscard]] constexpr TimerDeadline ComputeTimerDeadline(bool has_timeout, std::int64_t tv_sec,
                                                           std::int64_t tv_usec) noexcept {
  if (!has_timeout) return {};
  if (tv_sec < 0 || tv_usec < 0) return TimerDeadline{.armed = true, .relative_ns = 0};
  constexpr std::int64_t kUsecPerSec = 1'000'000;
  constexpr std::uint64_t kNsPerSec = 1'000'000'000ULL;
  constexpr std::uint64_t kNsPerUsec = 1'000ULL;
  if (tv_usec >= kUsecPerSec) {
    const std::int64_t extra = tv_usec / kUsecPerSec;
    tv_usec %= kUsecPerSec;
    if (tv_sec > std::numeric_limits<std::int64_t>::max() - extra) {
      return TimerDeadline{.armed = true, .relative_ns = std::numeric_limits<std::uint64_t>::max()};
    }
    tv_sec += extra;
  }
  const auto seconds = static_cast<std::uint64_t>(tv_sec);
  if (seconds > std::numeric_limits<std::uint64_t>::max() / kNsPerSec) {
    return TimerDeadline{.armed = true, .relative_ns = std::numeric_limits<std::uint64_t>::max()};
  }
  const std::uint64_t from_sec = seconds * kNsPerSec;
  const std::uint64_t from_usec = static_cast<std::uint64_t>(tv_usec) * kNsPerUsec;
  if (from_sec > std::numeric_limits<std::uint64_t>::max() - from_usec) {
    return TimerDeadline{.armed = true, .relative_ns = std::numeric_limits<std::uint64_t>::max()};
  }
  return TimerDeadline{.armed = true, .relative_ns = from_sec + from_usec};
}

}  // namespace cares
