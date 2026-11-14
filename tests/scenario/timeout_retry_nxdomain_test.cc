#include <chrono>
#include <cstdio>
#include <uring/uring.hpp>

#include "../e2e/local_dns_fixture.hpp"

namespace {

int Fail(const char* what) {
  std::fprintf(stderr, "FAIL %s\n", what);
  return 1;
}

int ExpectTimeout() {
  cares::test::LocalDns dns(cares::test::DnsMode::Drop);
  if (dns.Port() == 0) return Fail("bind");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 80, 1), cares::test::Ipv4Config());
  if (!made) return Fail("resolver");
  auto resolved = made->ResolveEndpoints("app.example", 53, 500);
  if (resolved || resolved.error() != cares::Error::Timeout()) return Fail("timeout");
  return 0;
}

int ExpectDeadlineShorterThanAres() {
  cares::test::LocalDns dns(cares::test::DnsMode::Answer);
  if (dns.Port() == 0) return Fail("bind short deadline");
  dns.SetDropReplies(true);
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring short deadline");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 250, 2), cares::test::Ipv4Config());
  if (!made) return Fail("resolver short deadline");
  uring::SingleDispatcher<cares::Resolver<>> dispatcher{*made};
  const auto start = std::chrono::steady_clock::now();
  auto resolved = made->ResolveEndpoints("short.example", 53, 60);
  const auto elapsed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
  if (resolved || resolved.error() != cares::Error::Timeout()) return Fail("short deadline error");
  if (elapsed_ms >= 400) return Fail("short deadline took too long");
  if (made->ActiveQueryCount() != 1u) return Fail("short deadline active count before retry");
  auto lit = made->ResolveEndpoints("127.0.0.1:8080", 80, 50);
  if (!lit || lit->size() != 1) return Fail("post-deadline literal");
  dns.SetDropReplies(false);
  const auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{800};
  while (made->ActiveQueryCount() != 0u && std::chrono::steady_clock::now() < drain_deadline) {
    made->StepDriver();
    if (made->ActiveQueryCount() == 0u) break;
    static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{25}, dispatcher));
  }
  if (made->ActiveQueryCount() != 0u) return Fail("short deadline active count after retry");
  return 0;
}

int ExpectRetry() {
  cares::test::LocalDns dns(cares::test::DnsMode::Retry);
  if (dns.Port() == 0) return Fail("bind");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 150, 2), cares::test::Ipv4Config());
  if (!made) return Fail("resolver");
  auto resolved = made->ResolveEndpoints("app.example", 53, 2000);
  if (!resolved || resolved->size() != 1) return Fail("retry");
  const cares::IpAddress expect = cares::IpAddress::FromV4(cares::Ipv4Bytes{192, 0, 2, 10});
  if ((*resolved)[0].ip != expect) return Fail("retry address");
  return 0;
}

int ExpectNxDomain() {
  cares::test::LocalDns dns(cares::test::DnsMode::NxDomain);
  if (dns.Port() == 0) return Fail("bind");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 200, 1), cares::test::Ipv4Config());
  if (!made) return Fail("resolver");
  auto resolved = made->ResolveEndpoints("app.example", 53, 2000);
  if (resolved || !resolved.error().IsNotFound()) return Fail("nxdomain");
  return 0;
}

}  // namespace

int main() {
  if (const int failed = ExpectTimeout(); failed != 0) return failed;
  if (const int failed = ExpectDeadlineShorterThanAres(); failed != 0) return failed;
  if (const int failed = ExpectRetry(); failed != 0) return failed;
  return ExpectNxDomain();
}
