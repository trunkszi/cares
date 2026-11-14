#include <array>
#include <atomic>
#include <barrier>
#include <cares/resolver/resolver.hpp>
#include <thread>
#include <uring/uring.hpp>

int main() {
  constexpr std::size_t kThreads = 24;
  std::barrier rendezvous{static_cast<std::ptrdiff_t>(kThreads)};
  std::atomic<unsigned> admitted{0};
  std::atomic<unsigned> duplicates_rejected{0};
  std::array<std::jthread, kThreads> threads{};
  for (auto& thread : threads) {
    thread = std::jthread{[&]() noexcept {
      auto ring = uring::Proactor::Create(32, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
      if (!ring) {
        rendezvous.arrive_and_wait();
        return;
      }
      auto resolver = cares::Resolver<>::FromSystem(*ring);
      if (resolver) {
        admitted.fetch_add(1, std::memory_order_relaxed);
        auto duplicate = cares::Resolver<>::FromSystem(*ring);
        if (!duplicate && duplicate.error() == cares::Error::InvalidArgument()) {
          duplicates_rejected.fetch_add(1, std::memory_order_relaxed);
        }
      }
      // Hold every claim until all threads have attempted admission.
      rendezvous.arrive_and_wait();
    }};
  }
  for (auto& thread : threads) thread.join();
  return admitted.load() == kThreads && duplicates_rejected.load() == kThreads ? 0 : 1;
}
