/** @file
 *  @brief Codegen probes for `cares::Resolver` and `resolver_detail.hpp` primitives.
 */
#include <array>
#include <cares/channel/timer_state.hpp>
#include <cares/probes/probes.hpp>
#include <cares/query_table/query_table.hpp>
#include <cares/resolver/poll_table.hpp>
#include <cares/resolver/resolver_detail.hpp>
#include <cares/types/query_handle.hpp>
#include <cstdint>
#include <span>

namespace cares::probes {

struct ProbeState {
  cares::PollTable<1> polls = []() consteval {
    cares::PollTable<1> table{2};
    static_cast<void>(table.OnSocketState(4, cares::SocketInterest::Read));
    table.MarkArmed(0, cares::SocketInterest::Read);
    return table;
  }();
  std::array<cares::detail::PollArm, 1> arms{
      {{.fd = 4, .armed_interest = cares::SocketInterest::Read, .generation = 1, .poll = uring::MakeToken(0, 0, 2, 1)}}};
  std::array<ares_fd_events_t, 1> ready{};
  std::array<cares::detail::TimerArm, 2> timers{};
  cares::DualStackWord node_word{};
  volatile std::int64_t tv_sec{1};
  volatile std::int64_t tv_usec{250000};
  volatile std::int32_t cqe_res{1};
  volatile std::uint16_t slot{0};
  std::uint16_t ready_count{0};
  volatile bool want_v4{true};
  volatile bool want_v6{true};
  volatile bool is_v4{true};
  volatile bool has_timeout{true};
  std::uint64_t sink{0};
};

constinit ProbeState g_probe_state{};

[[gnu::always_inline]] inline void ArmProbeTimer() noexcept {
  auto& timer = g_probe_state.timers[0];
  timer.timeout_live = true;
  timer.cancel_requested = false;
  timer.cancel_retry = false;
  timer.timeout_token = uring::MakeToken(1, 0, 2, 1);
  timer.spec = cares::detail::FillTimespec(1'250'000'000);
}

}  // namespace cares::probes

using cares::probes::ArmProbeTimer;
using cares::probes::g_probe_state;

extern "C" void cares_probe_resolver_step() noexcept {
  ArmProbeTimer();
  auto word =
      cares::detail::InitNodeWord(g_probe_state.node_word, g_probe_state.slot, g_probe_state.want_v4, g_probe_state.want_v6);
  word = cares::detail::MarkNodeDone(word, g_probe_state.is_v4);
  if (cares::detail::NodeAllDone(word)) word = cares::detail::RetireNodeWord(word);
  g_probe_state.node_word = word;
  const auto outcome = cares::detail::MatchTimerCqe(std::span{g_probe_state.timers}, g_probe_state.timers[0].timeout_token,
                                                    g_probe_state.cqe_res);
  g_probe_state.sink ^= word.raw() ^ static_cast<std::uint64_t>(outcome.matched) ^ static_cast<std::uint64_t>(outcome.fired);
}

extern "C" void cares_probe_poll_flush() noexcept {
  g_probe_state.arms[0].poll_live = true;
  const auto next_ready =
      cares::detail::HandlePollCqe<1>(std::span{g_probe_state.arms}, &g_probe_state.polls, std::span{g_probe_state.ready}, 0,
                                      g_probe_state.arms[0].poll, g_probe_state.cqe_res);
  g_probe_state.ready_count = next_ready;
  g_probe_state.sink ^= static_cast<std::uint64_t>(next_ready) ^ static_cast<std::uint64_t>(g_probe_state.ready[0].fd) ^
                        g_probe_state.ready[0].events;
}

extern "C" void cares_probe_timer_reconcile() noexcept {
  const bool has_timeout = g_probe_state.has_timeout;
  const std::int64_t tv_sec = g_probe_state.tv_sec;
  const std::int64_t tv_usec = g_probe_state.tv_usec;
  const auto deadline = cares::ComputeTimerDeadline(has_timeout, tv_sec, tv_usec);
  const auto ts = cares::detail::FillTimespec(deadline.relative_ns);
  g_probe_state.timers[0].spec = ts;
  g_probe_state.sink ^= static_cast<std::uint64_t>(deadline.armed) ^ static_cast<std::uint64_t>(ts.tv_sec) ^
                        static_cast<std::uint64_t>(ts.tv_nsec);
}

extern "C" void cares_probe_record_view(std::span<const std::byte> wire) noexcept {
  const auto question = cares::ParseFirstQuestionWire(wire);
  const auto view_bits = question ? static_cast<std::uint64_t>(std::to_underlying(question->qtype)) ^
                                        static_cast<std::uint64_t>(std::to_underlying(question->qclass)) ^
                                        question->qname_wire.size()
                                  : static_cast<std::uint64_t>(question.error().raw_code);
  const auto handle = cares::QueryHandle::Pack(g_probe_state.slot, cares::detail::NodeGeneration(g_probe_state.node_word),
                                               cares::detail::kJobMark);
  g_probe_state.sink ^= handle.raw ^ view_bits;
}

extern "C" int cares_probe_callback_int(cares::Delegate<int(int)> callback, int value) noexcept { return callback(value); }
extern "C" void cares_probe_callback_result(cares::Delegate<void(cares::Result<cares::EndpointList>)> callback,
                                            cares::Result<cares::EndpointList>&& result) noexcept {
  callback(std::move(result));
}
