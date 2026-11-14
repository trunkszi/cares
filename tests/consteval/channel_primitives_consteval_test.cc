#include <ares.h>

#include <cares/channel/callback_table.hpp>
#include <cares/channel/completion_words.hpp>
#include <cares/channel/library_guard.hpp>
#include <cares/channel/options.hpp>
#include <cares/channel/socket_bridge.hpp>
#include <cares/channel/timer_state.hpp>
#include <cares/types/endpoint.hpp>
#include <concepts>
#include <cstdio>
#include <type_traits>
#include <uarch/core/flow/delegate.hpp>
#include <uring/uring.hpp>

static_assert(sizeof(cares::QueryStateWord) == 8);
static_assert(sizeof(uarch::BitWord<cares::QueryStateSpec>) == sizeof(std::uint64_t));

static_assert(std::same_as<cares::Delegate<void(int)>, uarch::Callback<void(int)>>);
static_assert(sizeof(cares::Delegate<void(int)>) == 16);
static_assert(alignof(cares::Delegate<void(int)>) == 8);
static_assert(uarch::NoPadding<cares::Delegate<void(int)>>);
static_assert(std::same_as<uarch::CallArg<cares::Result<cares::EndpointList>>, cares::Result<cares::EndpointList>&&>);
static_assert(std::same_as<uarch::CallArg<std::span<const uring::Delivery>>, std::span<const uring::Delivery>>);
static_assert(std::same_as<uring::CompletionDelegate, uarch::Callback<void(std::span<const uring::Delivery>)>>);
static_assert(uarch::GprPair<cares::Delegate<void(int)>>);
static_assert(std::is_trivially_copyable_v<cares::Delegate<void(int)>>);
static_assert(std::is_trivially_destructible_v<cares::Delegate<void(int)>>);

static_assert(noexcept(cares::ComputeTimerDeadline(true, 1, 2)));
static_assert(cares::ComputeTimerDeadline(true, 1, 2).armed);
static_assert(cares::ComputeTimerDeadline(true, 1, 2).relative_ns == 1'000'000'000ULL + 2'000ULL);
static_assert(cares::ComputeTimerDeadline(true, -1, 5).armed);
static_assert(cares::ComputeTimerDeadline(true, -1, 5).relative_ns == 0);
static_assert(!cares::ComputeTimerDeadline(false, -1, 5).armed);

static_assert(std::is_move_constructible_v<cares::LibraryGuard>);
static_assert(std::is_move_assignable_v<cares::LibraryGuard>);
static_assert(!std::is_copy_constructible_v<cares::LibraryGuard>);
static_assert(!std::is_copy_assignable_v<cares::LibraryGuard>);

static_assert(!std::is_copy_constructible_v<cares::CallbackTable<4>>);
static_assert(!std::is_move_constructible_v<cares::CallbackTable<4>>);
static_assert(sizeof(cares::CallbackTable<64>) > 0);

static_assert(cares::ChannelOptions{}.timeout_ms == 2000);
static_assert(cares::ChannelOptions{}.tries == 2);
static_assert(cares::ChannelOptions{}.ndots == 1);
static_assert(cares::ChannelOptions{}.udp_max_queries == 0);
static_assert(cares::ChannelOptions{}.edns_psz == 4096);
static_assert(cares::ChannelOptions{}.flags == (ARES_FLAG_EDNS | ARES_FLAG_STAYOPEN));

int main() {
  cares::CallbackTable<64> table;
  if (table.ActiveCount() != 0) return 1;
  cares::LibraryGuard idle;
  if (idle.IsActive()) return 1;
  std::fprintf(stdout, "ok channel_primitives_consteval_test\n");
  return 0;
}
