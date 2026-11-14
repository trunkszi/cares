#pragma once
#include <compare>
#include <cstdint>

namespace cares {

struct alignas(8) QueryHandle {
  std::uint64_t raw{0};

  [[nodiscard]] static constexpr QueryHandle Pack(std::uint16_t slot, std::uint16_t generation,
                                                  std::uint32_t qid = 0) noexcept {
    return QueryHandle{static_cast<std::uint64_t>(slot) | (static_cast<std::uint64_t>(generation) << 16u) |
                       (static_cast<std::uint64_t>(qid) << 32u)};
  }
  [[nodiscard]] constexpr std::uint16_t Slot() const noexcept { return static_cast<std::uint16_t>(raw & 0xFFFFu); }
  [[nodiscard]] constexpr std::uint16_t Generation() const noexcept {
    return static_cast<std::uint16_t>((raw >> 16u) & 0xFFFFu);
  }
  [[nodiscard]] constexpr std::uint32_t Qid() const noexcept { return static_cast<std::uint32_t>(raw >> 32u); }
  [[nodiscard]] constexpr bool IsValid() const noexcept { return raw != 0; }
  friend constexpr auto operator<=>(const QueryHandle&, const QueryHandle&) noexcept = default;
};
static_assert(sizeof(QueryHandle) == 8);

}  // namespace cares
