#include <ares.h>

#include <array>
#include <cares/resolver/poll_table.hpp>
#include <cstdio>

namespace {

int AcquireFirstZeroSlot() {
  cares::PollTable<4> table;
  const auto first = table.OnSocketState(11, cares::SocketInterest::Read);
  const auto second = table.OnSocketState(12, cares::SocketInterest::Write);
  if (!first.has_value() || *first != 0) return __LINE__;
  if (!second.has_value() || *second != 1) return __LINE__;
  const auto word = table.SlotAt(0);
  if (word.get<^^cares::PollSlotSpec::fd_bits>() != 11) return __LINE__;
  if (word.get<^^cares::PollSlotSpec::phase>() != cares::PollPhase::Idle) return __LINE__;
  if (table.ActiveMask().count() != 2 || table.DirtyMask().count() != 2) return __LINE__;
  return 0;
}

int ReleaseReusesLowest() {
  cares::PollTable<4> table;
  const auto first = table.OnSocketState(1, cares::SocketInterest::Read);
  const auto second = table.OnSocketState(2, cares::SocketInterest::Read);
  if (!first || !second) return __LINE__;
  const auto generation = table.SlotAt(*first).get<^^cares::PollSlotSpec::generation>();
  table.MarkClosed(*first);
  if (table.SlotAt(*first).get<^^cares::PollSlotSpec::in_use>()) return __LINE__;
  if (table.SlotAt(*first).get<^^cares::PollSlotSpec::generation>() == generation) return __LINE__;
  const auto reused = table.OnSocketState(9, cares::SocketInterest::Read);
  if (!reused.has_value() || *reused != *first) return __LINE__;
  if (table.ActiveMask().count() != 2) return __LINE__;
  return 0;
}

int TokenRoundTrip() {
  cares::PollTable<4> table;
  const auto slot = table.OnSocketState(4, cares::SocketInterest::ReadWrite);
  if (!slot) return __LINE__;
  const auto token = table.TokenFor(*slot);
  const auto generation = table.SlotAt(*slot).get<^^cares::PollSlotSpec::generation>();
  if (uring::Slot(token) != *slot || uring::Generation(token) != generation) return __LINE__;
  if (uring::Subsystem(token) != cares::kPollSubsystemId) return __LINE__;
  if (table.TokenFor(30).raw() != uring::kNullToken.raw()) return __LINE__;
  return 0;
}

int CqeRejectsStale() {
  cares::PollTable<4> table;
  const auto slot = table.OnSocketState(5, cares::SocketInterest::Read);
  if (!slot) return __LINE__;
  const auto generation = table.SlotAt(*slot).get<^^cares::PollSlotSpec::generation>();
  table.MarkClosed(*slot);
  if (table.OnPollCqe(*slot, generation, 0x1).has_value()) return __LINE__;
  const auto again = table.OnSocketState(5, cares::SocketInterest::Read);
  if (!again || table.OnPollCqe(*again, generation, 0x1).has_value()) return __LINE__;
  const auto live = table.SlotAt(*again).get<^^cares::PollSlotSpec::generation>();
  const auto event = table.OnPollCqe(*again, live, 0x1);
  if (!event || (event->events & ARES_FD_EVENT_READ) == 0) return __LINE__;
  if (table.OnPollCqe(30, live, 0x1).has_value()) return __LINE__;
  return 0;
}

int FullReturnsExhausted() {
  cares::PollTable<2> table;
  if (!table.OnSocketState(1, cares::SocketInterest::Read) || !table.OnSocketState(2, cares::SocketInterest::Read)) {
    return __LINE__;
  }
  const auto full = table.OnSocketState(3, cares::SocketInterest::Read);
  if (full.has_value() || full.error() != cares::Error::CapacityExhausted()) return __LINE__;
  if (table.OnSocketState(-1, cares::SocketInterest::Read).has_value()) return __LINE__;
  return 0;
}

int RearmSetsPhase() {
  cares::PollTable<4> table;
  const auto slot = table.OnSocketState(8, cares::SocketInterest::Read);
  if (!slot) return __LINE__;
  table.MarkArmed(*slot, cares::SocketInterest::Read);
  if (table.SlotAt(*slot).get<^^cares::PollSlotSpec::phase>() != cares::PollPhase::Armed) return __LINE__;
  if (table.DirtyMask().count() != 0) return __LINE__;
  const auto retarget = table.OnSocketState(8, cares::SocketInterest::Write);
  if (!retarget || *retarget != *slot) return __LINE__;
  if (table.SlotAt(*slot).get<^^cares::PollSlotSpec::phase>() != cares::PollPhase::Rearming) return __LINE__;
  if (table.DirtyMask().count() != 1) return __LINE__;
  return 0;
}

int FdLimitAndCustomSubsystem() {
  cares::PollTable<4> table;
  const auto high = table.OnSocketState(0xFFFF, cares::SocketInterest::Read);
  if (!high.has_value()) return __LINE__;
  const auto too_wide = table.OnSocketState(0x10000, cares::SocketInterest::Read);
  if (too_wide.has_value() || too_wide.error() != cares::Error::InvalidArgument()) return __LINE__;
  table.SetSubsystemId(7);
  if (table.SubsystemId() != 7) return __LINE__;
  const auto token = table.TokenFor(*high);
  if (uring::Subsystem(token) != 7 || uring::Member(token) != 0) return __LINE__;
  const auto tagged = table.TokenFor(*high, 3, 9);
  if (uring::Subsystem(tagged) != 9 || uring::Member(tagged) != 3) return __LINE__;
  return 0;
}

int CqeMapsWriteAndError() {
  cares::PollTable<4> table;
  const auto low = table.OnSocketState(1, cares::SocketInterest::Read);
  const auto high = table.OnSocketState(2, cares::SocketInterest::Write);
  if (!low || !high) return __LINE__;
  table.MarkArmed(*low, cares::SocketInterest::Read);
  table.MarkArmed(*high, cares::SocketInterest::Write);
  const auto generation = table.SlotAt(*high).get<^^cares::PollSlotSpec::generation>();
  const auto wrote = table.OnPollCqe(*high, generation, 0x4);
  if (!wrote || (wrote->events & ARES_FD_EVENT_WRITE) == 0 || wrote->fd != 2) return __LINE__;
  const auto failed = table.OnPollCqe(*high, generation, -1);
  if (!failed || (failed->events & ARES_FD_EVENT_READ) == 0) return __LINE__;
  table.MarkClosed(*low);
  if (table.ActiveMask().count() != 1) return __LINE__;
  return 0;
}

}  // namespace

int main() {
  const std::array<int, 8> tests{{AcquireFirstZeroSlot(), ReleaseReusesLowest(), TokenRoundTrip(), CqeRejectsStale(),
                                  FullReturnsExhausted(), RearmSetsPhase(), CqeMapsWriteAndError(),
                                  FdLimitAndCustomSubsystem()}};
  for (int line : tests) {
    if (line != 0) {
      std::fprintf(stderr, "poll_table_test failed at line %d\n", line);
      return line;
    }
  }
  return 0;
}
