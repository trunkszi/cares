#include <array>
#include <cares/cares.hpp>
#include <cstdio>
#include <uring/uring.hpp>

namespace {

struct Bag {
  int hits{0};
  void On(cares::Result<cares::EndpointList> result) noexcept {
    if (result && result->size() == 1) ++hits;
  }
};

}  // namespace

int main() {
  auto ring = uring::Proactor::Create(32, uring::RingMode::kStandard64_16, cares::DefaultResolver::RequiredCaps());
  if (!ring) return 1;
  cares::ChannelOptions options;
  static_cast<void>(options.WithTimeoutMs(200).WithTries(1).WithNdots(1));
  options.flags = ARES_FLAG_NOSEARCH;
  const cares::ServerEndpoint server{cares::IpAddress::FromV4(cares::Ipv4Bytes{127, 0, 0, 1}), 9, false};
  if (!options.AddServer(server)) return 1;
  cares::ResolverConfig cfg;
  cfg.family = cares::IpFamily::DualStack;
  cfg.enable_hosts = false;
  Bag bag;
  auto resolver = cares::DefaultResolver::Create(*ring, options, cfg);
  if (!resolver) return 1;
  if (!resolver->InsertStaticHost("cache.internal", cares::IpAddress::FromV4(cares::Ipv4Bytes{10, 8, 0, 1}))) return 1;
  const cares::EndpointsCallback callback = uarch::bind<&Bag::On>(bag);
  const std::array<const char*, 3> targets{{"127.0.0.1:4001", "[::1]:4001", "cache.internal"}};
  for (const char* target : targets) {
    const std::uint16_t port = target[0] == 'c' ? static_cast<std::uint16_t>(53) : static_cast<std::uint16_t>(9);
    if (!resolver->SubmitEndpoints(target, port, callback)) return 1;
  }
  if (bag.hits != 3) return 1;
  std::printf("batch %d\n", bag.hits);
  return 0;
}
