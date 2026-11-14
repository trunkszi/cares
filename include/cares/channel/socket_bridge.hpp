/** @file @brief c-ares socket-state trampoline and fixed interest cache. */
#pragma once

#include <ares.h>

#include <array>
#include <cstdint>
#include <optional>
#include <uarch/core/flow/delegate.hpp>
#include <uarch/primitives.hpp>
#include <utility>

namespace cares {

template <typename Signature>
using Delegate = uarch::Callback<Signature>;

static_assert(sizeof(Delegate<void(int)>) == 16 && alignof(Delegate<void(int)>) == 8 && uarch::NoPadding<Delegate<void(int)>> &&
              uarch::GprPair<Delegate<void(int)>>);

/** @brief Readiness requested by one c-ares socket-state callback. */
enum class SocketInterest : std::uint8_t {
  None = 0,
  Read = 1,
  Write = 2,
  ReadWrite = 3,
};

using SocketStateObserver = Delegate<void(int fd, SocketInterest interest)>;

inline void SocketStateTrampoline(void* data, ares_socket_t socket_fd, int readable, int writable) noexcept;

/** @brief `uarch::BitWord` flags for the readable and writable bits. */
struct SocketInterestSpec {
  using Word = std::uint64_t;
  bool readable[[= uarch::Flag{0}]];
  bool writable[[= uarch::Flag{1}]];
};

/** @brief One observed socket-state edge, including whether the 64-slot cache stored it. */
struct SocketStateTransition {
  int fd{-1};
  SocketInterest previous{SocketInterest::None};
  SocketInterest next{SocketInterest::None};
  bool tracked{false};

  friend constexpr bool operator==(const SocketStateTransition&, const SocketStateTransition&) noexcept = default;
};

/** @brief Map c-ares readable/writable flags through `uarch::BitWord`. Nonzero means that interest is requested. */
[[nodiscard]] constexpr SocketInterest InterestFromFlags(int readable, int writable) noexcept {
  auto word = uarch::BitWord<SocketInterestSpec>{};
  if (readable != 0) word = word.with_flags<^^SocketInterestSpec::readable>();
  if (writable != 0) word = word.with_flags<^^SocketInterestSpec::writable>();
  const bool wants_read = word.test<^^SocketInterestSpec::readable>();
  const bool wants_write = word.test<^^SocketInterestSpec::writable>();
  if (wants_read && wants_write) return SocketInterest::ReadWrite;
  if (wants_read) return SocketInterest::Read;
  if (wants_write) return SocketInterest::Write;
  return SocketInterest::None;
}

class SocketBridge;

/**
 * @brief Fixed 64-fd interest cache.
 * The cache is one `uint64` mask, so a lookup walks at most 64 set bits.
 * A 65th distinct fd is still reported to the observer with `tracked == false`.
 */
class SocketBridge {
 public:
  static constexpr std::uint32_t kSlotCount = 64;

  SocketBridge() noexcept = default;
  SocketBridge(const SocketBridge&) = delete ("socket bridge is address-stable");
  SocketBridge& operator=(const SocketBridge&) = delete ("socket bridge is address-stable");
  SocketBridge(SocketBridge&&) = delete ("socket bridge is address-stable");
  SocketBridge& operator=(SocketBridge&&) = delete ("socket bridge is address-stable");

  void SetObserver(SocketStateObserver observer) noexcept { observer_ = observer; }
  [[nodiscard]] bool HasObserver() const noexcept { return static_cast<bool>(observer_); }

  /** @brief Install this bridge as the channel socket-state callback. A null options pointer is ignored. */
  void Bind(ares_options* options) noexcept {
    if (options == nullptr) return;
    options->sock_state_cb = &SocketStateTrampoline;
    options->sock_state_cb_data = this;
  }

  /** @brief Record the edge and return the previous interest. Does not invoke the observer. */
  [[nodiscard]] constexpr SocketStateTransition Apply(ares_socket_t socket_fd, int readable, int writable) noexcept {
    SocketStateTransition transition{};
    transition.fd = static_cast<int>(socket_fd);
    transition.next = InterestFromFlags(readable, writable);
    auto scan = occupied_;
    std::optional<std::uint32_t> found;
    while (const auto bit = scan.lowest_one()) {
      scan = scan.clear_lowest_one();
      if (slots_[*bit].fd == transition.fd) {
        found = bit;
        break;
      }
    }
    if (found) {
      auto& slot = slots_[*found];
      transition.previous = slot.interest;
      transition.tracked = true;
      if (transition.next == SocketInterest::None) {
        slot = {};
        occupied_ = occupied_.clear(*found);
      } else {
        slot.interest = transition.next;
      }
      return transition;
    }
    if (transition.next == SocketInterest::None) {
      transition.tracked = true;
      return transition;
    }
    const auto free = occupied_.lowest_zero();
    if (!free || *free >= kSlotCount) return transition;
    slots_[*free].fd = transition.fd;
    slots_[*free].interest = transition.next;
    occupied_ = occupied_.set(*free);
    transition.tracked = true;
    return transition;
  }

  void Notify(int fd, SocketInterest interest) noexcept {
    if (observer_) observer_(fd, interest);
  }

 private:
  struct Slot {
    int fd{-1};
    SocketInterest interest{SocketInterest::None};
  };

  SocketStateObserver observer_{};
  uarch::Bitmap64 occupied_{};
  std::array<Slot, kSlotCount> slots_{};
};

inline void SocketStateTrampoline(void* data, ares_socket_t socket_fd, int readable, int writable) noexcept {
  if (data == nullptr) return;
  auto* bridge = static_cast<SocketBridge*>(data);
  const SocketStateTransition transition = bridge->Apply(socket_fd, readable, writable);
  bridge->Notify(transition.fd, transition.next);
}

static_assert(sizeof(uarch::BitWord<SocketInterestSpec>) == sizeof(std::uint64_t));

}  // namespace cares
