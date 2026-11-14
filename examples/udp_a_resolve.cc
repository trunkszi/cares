#include <cares/cares.hpp>
#include <cstdio>
#include <uring/uring.hpp>

int main() {
  auto ring = uring::Proactor::Create(32, uring::RingMode::kStandard64_16, cares::DefaultResolver::RequiredCaps());
  if (!ring) return 1;
  cares::ChannelOptions options;
  static_cast<void>(options.WithTimeoutMs(200).WithTries(1).WithNdots(1));
  options.flags = ARES_FLAG_NOSEARCH;
  const cares::ServerEndpoint server{cares::IpAddress::FromV4(cares::Ipv4Bytes{127, 0, 0, 1}), 9, false};
  if (!options.AddServer(server)) return 1;
  cares::ResolverConfig cfg;
  cfg.family = cares::IpFamily::Ipv4;
  cfg.enable_hosts = false;
  auto resolver = cares::DefaultResolver::Create(*ring, options, cfg);
  if (!resolver) return 1;
  auto literal = resolver->ResolveEndpoints("127.0.0.1:4001", 80, 100);
  if (!literal || literal->size() != 1 || (*literal)[0].port != 4001) return 1;
  if (!resolver->InsertStaticHost("app.internal", cares::IpAddress::FromV4(cares::Ipv4Bytes{10, 1, 2, 3}))) return 1;
  auto host = resolver->ResolveEndpoints("app.internal", 53, 100);
  if (!host || host->size() != 1 || (*host)[0].port != 53) return 1;
  if ((*host)[0].ip != cares::IpAddress::FromV4(cares::Ipv4Bytes{10, 1, 2, 3})) return 1;
  std::printf("literal-port %u static-port %u\n", static_cast<unsigned>((*literal)[0].port),
              static_cast<unsigned>((*host)[0].port));
  return 0;
}
