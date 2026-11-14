/** @file @brief One live resolver per `(proactor, subsystem id)` on a shared ring. */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace cares::detail {

struct ProactorClaim {
  const void* proactor{nullptr};
  std::uint8_t subsystem_id{0};
  bool* observer_ready{nullptr};
};

inline constexpr std::size_t kProactorClaimCap = 16;

struct ProactorClaimTable {
  std::array<ProactorClaim, kProactorClaimCap> slots{};
};

[[nodiscard]] inline ProactorClaimTable& ProactorClaims() noexcept {
  static thread_local ProactorClaimTable table;
  return table;
}

/**
 * @brief Reserves `(proactor, subsystem_id)`.
 * A second resolver on the same proactor is admitted only when every live claim,
 * including the newcomer, already has a foreign-batch observer. The same id cannot
 * be claimed twice: both resolvers would otherwise consume each other's CQEs.
 */
[[nodiscard]] inline bool ClaimProactor(const void* proactor, std::uint8_t subsystem_id, bool* observer_ready) noexcept {
  if (proactor == nullptr || observer_ready == nullptr) return false;
  auto& table = ProactorClaims();
  ProactorClaim* free = nullptr;
  bool shares = false;
  for (auto& slot : table.slots) {
    if (slot.proactor == nullptr) {
      if (free == nullptr) free = &slot;
      continue;
    }
    if (slot.proactor != proactor) continue;
    if (slot.subsystem_id == subsystem_id) return false;
    if (slot.observer_ready == nullptr || !*slot.observer_ready) return false;
    shares = true;
  }
  if (shares && !*observer_ready) return false;
  if (free == nullptr) return false;
  *free = ProactorClaim{proactor, subsystem_id, observer_ready};
  return true;
}

/// Id 0 and 255 are reserved. Id 1 is the socket subsystem and cannot host a resolver.
[[nodiscard]] inline bool SubsystemOk(std::uint8_t id) noexcept { return id != 0 && id != 1 && id != 255; }

inline void ReleaseProactor(const void* proactor, std::uint8_t subsystem_id) noexcept {
  if (proactor == nullptr) return;
  for (auto& slot : ProactorClaims().slots) {
    if (slot.proactor == proactor && slot.subsystem_id == subsystem_id) slot = {};
  }
}

}  // namespace cares::detail
