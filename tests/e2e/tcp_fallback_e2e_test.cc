#include <cstdio>
#include <uring/uring.hpp>

#include "local_dns_fixture.hpp"

int main() {
  cares::test::LocalDns dns(cares::test::DnsMode::Truncate);
  if (dns.Port() == 0) {
    std::fprintf(stderr, "FAIL bind\n");
    return 1;
  }
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) {
    std::fprintf(stderr, "FAIL ring\n");
    return 1;
  }
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 300, 1), cares::test::Ipv4Config());
  if (!made) {
    std::fprintf(stderr, "FAIL resolver\n");
    return 1;
  }
  auto resolved = made->ResolveEndpoints("app.example", 53, 2000);
  if (!resolved || resolved->size() != 1) {
    std::fprintf(stderr, "FAIL tcp fallback\n");
    return 1;
  }
  const cares::IpAddress expect = cares::IpAddress::FromV4(cares::Ipv4Bytes{192, 0, 2, 10});
  if ((*resolved)[0].ip != expect || (*resolved)[0].port != 53) {
    std::fprintf(stderr, "FAIL address\n");
    return 1;
  }
  return 0;
}
