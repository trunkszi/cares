#include <cares/types/endpoint.hpp>
#include <cares/types/query_handle.hpp>
#if defined(CARES_CODEGEN_PROBE)
#include <cares/probes/probes.hpp>
extern "C" void cares_codegen_probe_touch(std::span<const std::byte> wire) noexcept {
  cares_probe_resolver_step();
  cares_probe_poll_flush();
  cares_probe_timer_reconcile();
  cares_probe_record_view(wire);
}
extern "C" [[nodiscard]] std::uint64_t cares_handle_pack_probe(std::uint16_t slot, std::uint16_t generation,
                                                               std::uint32_t qid) noexcept {
  return cares::QueryHandle::Pack(slot, generation, qid).raw;
}
#else
int main() {
  auto parsed = cares::ParseEndpoint("http://127.0.0.1:8080");
  if (!parsed) return 1;
  auto ip = cares::ParseIpLiteral(parsed->host);
  if (!ip) return 2;
  const cares::SocketAddress address{*ip, parsed->port};
  auto storage = address.ToSockAddr();
  return cares::SocketAddress::FromSockAddr(reinterpret_cast<const sockaddr*>(&storage)) == address ? 0 : 3;
}
#endif
