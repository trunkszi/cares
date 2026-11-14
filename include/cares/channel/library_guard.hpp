/** @file @brief Process-wide c-ares library init paired with each owning guard. */
#pragma once

#include <ares.h>

#include <atomic>
#include <cares/error/ares_error.hpp>
#include <cstdint>
#include <utility>

namespace cares {

/**
 * @brief Move-only RAII owner of one `ares_library_init(ARES_LIB_INIT_ALL)` count.
 *
 * c-ares keeps a process-global init counter. Each owning guard calls init once and
 * cleanup once; a moved-from guard must not cleanup, or it would drop another owner's count.
 */
class LibraryGuard {
 public:
  LibraryGuard() noexcept = default;
  LibraryGuard(const LibraryGuard&) = delete ("library guard owns one init count");
  LibraryGuard& operator=(const LibraryGuard&) = delete ("library guard owns one init count");

  [[nodiscard]] static Result<LibraryGuard> Acquire() noexcept {
    while (gate_.test_and_set(std::memory_order_acquire)) {
    }
    const int status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
      gate_.clear(std::memory_order_release);
      return std::unexpected(Error::FromAres(status));
    }
    holders_.fetch_add(1, std::memory_order_acq_rel);
    gate_.clear(std::memory_order_release);
    return LibraryGuard{true};
  }

  LibraryGuard(LibraryGuard&& other) noexcept : owns_(other.owns_) { other.owns_ = false; }

  LibraryGuard& operator=(LibraryGuard&& other) noexcept {
    if (this != &other) {
      Release();
      owns_ = other.owns_;
      other.owns_ = false;
    }
    return *this;
  }

  ~LibraryGuard() noexcept { Release(); }

  /** @brief True while this object still owes one `ares_library_cleanup`. */
  [[nodiscard]] constexpr bool IsActive() const noexcept { return owns_; }
  [[nodiscard]] constexpr bool Owns() const noexcept { return owns_; }

  /** @brief Live owning guards. Matches the number of unpaired init calls from this type. */
  [[nodiscard]] static std::uint32_t Holders() noexcept { return holders_.load(std::memory_order_acquire); }

  /**
   * @brief Succeeds only when this c-ares build was configured without threadsafety.
   * The resolver is single-thread run-to-completion and must not link a threaded c-ares.
   */
  [[nodiscard]] static Result<void> EnsureThreadingDisabled() noexcept {
    if (ares_threadsafety() != ARES_FALSE) return std::unexpected(Error::InvalidArgument(ARES_ENOTIMP));
    return {};
  }

 private:
  explicit constexpr LibraryGuard(bool owns) noexcept : owns_(owns) {}

  void Release() noexcept {
    if (!owns_) return;
    owns_ = false;
    while (gate_.test_and_set(std::memory_order_acquire)) {
    }
    holders_.fetch_sub(1, std::memory_order_acq_rel);
    ares_library_cleanup();
    gate_.clear(std::memory_order_release);
  }

  bool owns_{false};
  static inline std::atomic<std::uint32_t> holders_{0};
  static inline std::atomic_flag gate_{};
};

}  // namespace cares
