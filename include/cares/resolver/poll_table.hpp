/** @file @brief Preallocated poll slots addressed by one Bitmap64. */
#pragma once

#include <array>
#include <cares/channel/socket_bridge.hpp>
#include <cares/error/ares_error.hpp>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <uarch/uarch.hpp>
#include <uring/core/user_data_token.hpp>
#include <utility>

namespace cares {

/** @brief Lifecycle of one socket poll slot. */
enum class PollPhase : std::uint8_t {
  Idle = 0,
  Armed = 1,
  Rearming = 2,
  Cancelling = 3,
  Closing = 4,
};

/**
 * @brief One poll slot in a single reflected word.
 * `fd_bits` is 16 bits because the descriptor stored for c-ares fits in that field.
 * Generation occupies the top 32 bits, the same place `uring::TokenSpec` keeps it.
 */
struct PollSlotSpec {
  using Word = std::uint64_t;
  std::uint16_t fd_bits[[= uarch::bits::Field{0, 16}]];
  SocketInterest desired[[= uarch::bits::Field{16, 2}]];
  SocketInterest armed[[= uarch::bits::Field{18, 2}]];
  PollPhase phase[[= uarch::bits::Field{20, 3}]];
  bool in_use[[= uarch::bits::Flag{23}]];
  std::uint32_t generation[[= uarch::bits::Field{32, 32}]];
};
using PollSlotWord = uarch::BitWord<PollSlotSpec>;
static_assert(sizeof(PollSlotWord) == 8);
static_assert(uarch::NoPadding<PollSlotWord> && uarch::RegisterPassable<PollSlotWord>);

/**
 * @brief Subsystem byte carried in poll completion tokens.
 * Zero is the proactor internal id, one is the socket-I/O default, and 255 is
 * the mailbox id. The generation stays in bits 32..63, above that subsystem byte.
 */
inline constexpr std::uint8_t kPollSubsystemId = 2;
using PollSlotIndex = std::uint16_t;

namespace detail {

// Field splices stay in non-template functions. Inside a class template, GCC
// treats the same splice as an immediate-escalating expression and rejects a runtime call.
[[nodiscard]] inline constexpr bool InUse(PollSlotWord word) noexcept { return word.test<^^PollSlotSpec::in_use>(); }
[[nodiscard]] inline constexpr std::uint16_t FdBits(PollSlotWord word) noexcept { return word.get<^^PollSlotSpec::fd_bits>(); }
[[nodiscard]] inline constexpr std::uint32_t Generation(PollSlotWord word) noexcept {
  return word.get<^^PollSlotSpec::generation>();
}
[[nodiscard]] inline constexpr SocketInterest Armed(PollSlotWord word) noexcept { return word.get<^^PollSlotSpec::armed>(); }
[[nodiscard]] inline constexpr PollPhase Phase(PollSlotWord word) noexcept { return word.get<^^PollSlotSpec::phase>(); }

[[nodiscard]] inline constexpr PollSlotWord BumpGeneration(PollSlotWord word) noexcept {
  word = word.wrapping_add_top_field<^^PollSlotSpec::generation>(1);
  if (word.get<^^PollSlotSpec::generation>() == 0) word = word.wrapping_add_top_field<^^PollSlotSpec::generation>(1);
  return word;
}

[[nodiscard]] inline constexpr PollSlotWord StoreOpen(PollSlotWord word, std::uint16_t fd, SocketInterest interest) noexcept {
  word = BumpGeneration(word);
  word = word.with<^^PollSlotSpec::fd_bits>(fd);
  word = word.with<^^PollSlotSpec::desired>(interest);
  word = word.with<^^PollSlotSpec::armed>(SocketInterest::None);
  word = word.with<^^PollSlotSpec::phase>(PollPhase::Idle);
  word = word.with<^^PollSlotSpec::in_use>(true);
  return word;
}

[[nodiscard]] inline constexpr PollSlotWord StoreArmed(PollSlotWord word, SocketInterest armed) noexcept {
  word = word.with<^^PollSlotSpec::armed>(armed);
  return word.with<^^PollSlotSpec::phase>(PollPhase::Armed);
}

[[nodiscard]] inline constexpr PollSlotWord StoreClosed(PollSlotWord word) noexcept {
  word = BumpGeneration(word);
  word = word.with<^^PollSlotSpec::phase>(PollPhase::Closing);
  word = word.with<^^PollSlotSpec::in_use>(false);
  word = word.with<^^PollSlotSpec::desired>(SocketInterest::None);
  word = word.with<^^PollSlotSpec::armed>(SocketInterest::None);
  return word.with<^^PollSlotSpec::fd_bits>(static_cast<std::uint16_t>(0));
}

[[nodiscard]] inline constexpr PollSlotWord StoreDesired(PollSlotWord word, SocketInterest interest) noexcept {
  word = word.with<^^PollSlotSpec::desired>(interest);
  if (Phase(word) == PollPhase::Armed && Armed(word) != interest) word = word.with<^^PollSlotSpec::phase>(PollPhase::Rearming);
  return word;
}

// Out of line: inlining this trivial `std::expected` return makes GCC -O3
// treat the inactive union arm as an uninitialized use.
[[nodiscard, gnu::noinline]] inline constexpr Result<std::uint16_t> SlotOk(std::uint16_t slot) noexcept {
  return Result<std::uint16_t>(std::in_place, slot);
}

}  // namespace detail

template <std::size_t MaxSockets = 16>
class PollTable {
  static_assert(MaxSockets > 0 && MaxSockets <= 64);

 public:
  constexpr PollTable() noexcept = default;
  explicit constexpr PollTable(std::uint8_t subsystem_id) noexcept : subsystem_id_(subsystem_id) {}
  constexpr void SetSubsystemId(std::uint8_t subsystem_id) noexcept { subsystem_id_ = subsystem_id; }
  [[nodiscard]] constexpr std::uint8_t SubsystemId() const noexcept { return subsystem_id_; }
  PollTable(const PollTable&) = delete ("PollTable slots are not copyable");
  PollTable& operator=(const PollTable&) = delete ("PollTable slots are not copyable");
  constexpr PollTable(PollTable&&) noexcept = default;
  constexpr PollTable& operator=(PollTable&&) noexcept = default;

  [[nodiscard]] constexpr Result<std::uint16_t> OnSocketState(int fd, SocketInterest interest) noexcept {
    if (uarch::unlikely(fd < 0 || static_cast<unsigned>(fd) > 0xffffu)) {
      uarch::cold_path();
      return std::unexpected(Error::InvalidArgument());
    }
    const auto fd_bits = static_cast<std::uint16_t>(fd);
    auto scan = active_mask_;
    while (const auto bit = scan.lowest_one()) {
      scan = scan.clear(*bit);
      if (*bit >= MaxSockets) break;
      auto word = slots_[*bit];
      if (!detail::InUse(word) || detail::FdBits(word) != fd_bits) continue;
      const auto slot = static_cast<std::uint16_t>(*bit);
      if (interest == SocketInterest::None)
        MarkClosed(slot);
      else
        Retarget(slot, interest);
      return detail::SlotOk(slot);
    }
    if (interest == SocketInterest::None) return std::unexpected(Error::NotFound());
    return Acquire(fd_bits, interest);
  }

  [[nodiscard]] constexpr uarch::Bitmap64 DirtyMask() const noexcept { return dirty_mask_; }
  [[nodiscard]] constexpr uarch::Bitmap64 ActiveMask() const noexcept { return active_mask_; }

  [[nodiscard]] constexpr PollSlotWord SlotAt(std::uint16_t slot) const noexcept {
    if (slot >= MaxSockets) return {};
    return slots_[slot];
  }

  constexpr void MarkArmed(std::uint16_t slot, SocketInterest armed) noexcept {
    if (slot >= MaxSockets || !detail::InUse(slots_[slot])) return;
    slots_[slot] = detail::StoreArmed(slots_[slot], armed);
    dirty_mask_ = dirty_mask_.clear(slot);
  }

  constexpr void MarkClosed(std::uint16_t slot) noexcept {
    if (slot >= MaxSockets || !detail::InUse(slots_[slot])) return;
    slots_[slot] = detail::StoreClosed(slots_[slot]);
    active_mask_ = active_mask_.clear(slot);
    dirty_mask_ = dirty_mask_.clear(slot);
  }

  [[nodiscard]] constexpr std::optional<ares_fd_events_t> OnPollCqe(std::uint16_t slot, std::uint32_t generation,
                                                                    std::int32_t cqe_res) noexcept {
    if (slot >= MaxSockets) return std::nullopt;
    const auto word = slots_[slot];
    if (!detail::InUse(word) || detail::Generation(word) != generation) return std::nullopt;
    const auto revents = cqe_res < 0 ? kPollErr : static_cast<std::uint32_t>(cqe_res);
    ares_fd_events_t event{};
    event.fd = static_cast<ares_socket_t>(detail::FdBits(word));
    if ((revents & (kPollIn | kPollErr | kPollHup | kPollNval)) != 0) {
      event.events |= static_cast<unsigned>(std::to_underlying(ARES_FD_EVENT_READ));
    }
    if ((revents & kPollOut) != 0) event.events |= static_cast<unsigned>(std::to_underlying(ARES_FD_EVENT_WRITE));
    return event;
  }

  constexpr void ClearAll() noexcept {
    slots_.fill(PollSlotWord{});
    active_mask_ = {};
    dirty_mask_ = {};
  }

  /** @brief Token for an in-use slot. Generation sits in bits 32..63 via `uring::MakeToken`. */
  [[nodiscard]] constexpr uring::UserDataToken TokenFor(PollSlotIndex slot, std::uint8_t member = 0) const noexcept {
    return TokenFor(slot, member, subsystem_id_);
  }

  [[nodiscard]] constexpr uring::UserDataToken TokenFor(PollSlotIndex slot, std::uint8_t member,
                                                        std::uint8_t subsystem_id) const noexcept {
    if (slot >= MaxSockets || !detail::InUse(slots_[slot])) return uring::kNullToken;
    return uring::MakeToken(slot, member, subsystem_id, detail::Generation(slots_[slot]));
  }

 private:
  static constexpr std::uint32_t kPollIn = 0x0001u;
  static constexpr std::uint32_t kPollOut = 0x0004u;
  static constexpr std::uint32_t kPollErr = 0x0008u;
  static constexpr std::uint32_t kPollHup = 0x0010u;
  static constexpr std::uint32_t kPollNval = 0x0020u;

  [[nodiscard]] static constexpr uarch::Bitmap64 InvalidMask() noexcept {
    if constexpr (MaxSockets >= 64) return uarch::Bitmap64::empty();
    return ~uarch::Bitmap64::from_raw((std::uint64_t{1} << MaxSockets) - 1u);
  }

  [[nodiscard]] constexpr Result<std::uint16_t> Acquire(std::uint16_t fd_bits, SocketInterest interest) noexcept {
    const auto index = (active_mask_ | InvalidMask()).lowest_zero();
    if (uarch::unlikely(!index.has_value() || *index >= MaxSockets)) {
      uarch::cold_path();
      return std::unexpected(Error::CapacityExhausted());
    }
    const auto slot = static_cast<std::uint16_t>(*index);
    slots_[slot] = detail::StoreOpen(slots_[slot], fd_bits, interest);
    active_mask_ = active_mask_.set(*index);
    dirty_mask_ = dirty_mask_.set(*index);
    return detail::SlotOk(slot);
  }

  constexpr void Retarget(std::uint16_t slot, SocketInterest interest) noexcept {
    slots_[slot] = detail::StoreDesired(slots_[slot], interest);
    dirty_mask_ = dirty_mask_.set(slot);
  }

  std::array<PollSlotWord, MaxSockets> slots_{};
  uarch::Bitmap64 active_mask_{};
  uarch::Bitmap64 dirty_mask_{};
  std::uint8_t subsystem_id_{kPollSubsystemId};
};

}  // namespace cares
