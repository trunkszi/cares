#include <cares/cares.hpp>
#include <chrono>
#include <cstdio>
#include <optional>
#include <uring/uring.hpp>

#include "local_dns_fixture.hpp"

namespace {

struct[[= cares::notes::Answer]][[= cares::notes::Type(cares::DnsType::A)]] ReflectedAView {
  cares::IpAddress addr[[= cares::notes::Field(ARES_RR_A_ADDR)]];
  std::uint32_t ttl[[= cares::notes::Ttl]];
};

int Fail(const char* what) {
  std::fprintf(stderr, "FAIL %s\n", what);
  return 1;
}

int CachedAnswer() {
  cares::test::LocalDns dns(cares::test::DnsMode::Answer);
  if (dns.Port() == 0) return Fail("bind");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 200, 2), cares::test::Ipv4Config());
  if (!made) return Fail("resolver");
  auto first = made->ResolveEndpoints("app.example", 53, 2000);
  if (!first || first->size() != 1) return Fail("first");
  const cares::IpAddress expect = cares::IpAddress::FromV4(cares::Ipv4Bytes{192, 0, 2, 10});
  if ((*first)[0].port != 53 || (*first)[0].ip != expect) return Fail("address");
  if (dns.UdpQueries() != 1u) return Fail("udp query count");
  dns.Stop();
  auto cached = made->ResolveEndpoints("app.example", 53, 200);
  if (!cached || cached->size() != 1 || (*cached)[0].ip != expect) return Fail("cache");
  auto missed = made->ResolveEndpoints("other.example", 53, 400);
  if (missed || !missed.error().IsRetryable()) return Fail("miss");
  return 0;
}

int DualStack() {
  cares::test::LocalDns dns(cares::test::DnsMode::Answer);
  if (dns.Port() == 0) return Fail("bind");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 200, 2), cares::test::DualConfig());
  if (!made) return Fail("resolver");
  auto both = made->ResolveEndpoints("app.example", 443, 2000);
  if (!both || both->size() != 2) return Fail("dual");
  bool saw4 = false;
  bool saw6 = false;
  for (const auto& ep : *both) {
    if (ep.port != 443) return Fail("dual port");
    saw4 = saw4 || ep.ip.IsV4();
    saw6 = saw6 || ep.ip.IsV6();
  }
  if (!saw4 || !saw6) return Fail("dual addresses");
  return 0;
}

int MixedFamilyFailure() {
  struct Capture {
    std::optional<cares::Result<cares::EndpointList>> result;
    void On(cares::Result<cares::EndpointList> value) noexcept { result = std::move(value); }
  };
  for (const auto mode : {cares::test::DnsMode::RefusedThenNoData, cares::test::DnsMode::NoDataThenRefused}) {
    cares::test::LocalDns dns(mode);
    if (dns.Port() == 0) return Fail("mixed bind");
    auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
    if (!ring) return Fail("mixed ring");
    auto resolver = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 500, 1), cares::test::DualConfig());
    if (!resolver) return Fail("mixed resolver");
    Capture capture;
    if (!resolver->SubmitEndpoints("mixed.example", 443, uarch::bind<&Capture::On>(capture))) {
      return Fail("mixed submit");
    }
    uring::SingleDispatcher<cares::Resolver<>> dispatcher{*resolver};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (resolver->ActiveQueryCount() > 1 && std::chrono::steady_clock::now() < deadline) {
      resolver->StepDriver();
      static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{5}, dispatcher));
    }
    if (resolver->ActiveQueryCount() != 1 || capture.result) return Fail("first family completion");
    const unsigned expected_first = mode == cares::test::DnsMode::RefusedThenNoData ? ARES_REC_TYPE_A : ARES_REC_TYPE_AAAA;
    if (dns.FirstFamilyReply() != expected_first) return Fail("mixed arrival order");
    dns.ReleaseFamilyReply();
    while (!capture.result && std::chrono::steady_clock::now() < deadline) {
      resolver->StepDriver();
      static_cast<void>(ring->WaitCompletions(1, std::chrono::milliseconds{5}, dispatcher));
    }
    const auto refused = cares::Error::FromAres(ARES_EREFUSED);
    if (!capture.result || *capture.result || capture.result->error() != refused) return Fail("mixed refusal masked");
    const auto before = dns.UdpQueries();
    const auto repeated = resolver->ResolveEndpoints("mixed.example", 443, 1000);
    if (repeated || repeated.error() != refused || dns.UdpQueries() <= before) return Fail("mixed failure cached");
  }
  return 0;
}

int PartialDualStackCache() {
  for (const auto mode : {cares::test::DnsMode::V4ServFail, cares::test::DnsMode::V4NoData, cares::test::DnsMode::V4NxDomain}) {
    cares::test::LocalDns dns(mode);
    if (dns.Port() == 0) return Fail("partial bind");
    auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
    if (!ring) return Fail("partial ring");
    auto resolver = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 100, 1), cares::test::DualConfig());
    if (!resolver) return Fail("partial resolver");
    auto first = resolver->ResolveEndpoints("partial.example", 443, 1000);
    if (!first || first->size() != 1 || !(*first)[0].ip.IsV6()) return Fail("partial live answer");
    const auto before = dns.UdpQueries();
    auto second = resolver->ResolveEndpoints("partial.example", 443, 1000);
    if (!second || second->size() != 1 || !(*second)[0].ip.IsV6()) return Fail("partial second answer");
    if (mode == cares::test::DnsMode::V4ServFail) {
      if (dns.UdpQueries() <= before) return Fail("transient family was cached");
    } else if (dns.UdpQueries() != before) {
      return Fail("authoritative family miss was not cached");
    }
  }
  return 0;
}

int DedupeAndMinTtl() {
  cares::test::LocalDns dns(cares::test::DnsMode::DuplicateMinTtl);
  if (dns.Port() == 0) return Fail("bind dedupe");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring dedupe");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 200, 1), cares::test::Ipv4Config());
  if (!made) return Fail("resolver dedupe");

  auto live = made->ResolveEndpoints("dedupe.example", 80, 1000);
  if (!live || live->size() != 2) return Fail("live dedupe size");
  const cares::IpAddress ip10 = cares::IpAddress::FromV4(cares::Ipv4Bytes{192, 0, 2, 10});
  const cares::IpAddress ip11 = cares::IpAddress::FromV4(cares::Ipv4Bytes{192, 0, 2, 11});
  if ((*live)[0].ip != ip10 || (*live)[1].ip != ip11) return Fail("live dedupe ips");

  auto zero_ttl = made->ResolveEndpoints("zerottl.example", 80, 1000);
  if (!zero_ttl || zero_ttl->size() != 2) return Fail("zero_ttl live");

  dns.Stop();

  // Cached entry must also have deduplicated addresses (2 endpoints, not 3).
  auto cached = made->ResolveEndpoints("dedupe.example", 80, 100);
  if (!cached || cached->size() != 2) return Fail("cached dedupe size");
  if ((*cached)[0].ip != ip10 || (*cached)[1].ip != ip11) return Fail("cached dedupe ips");

  // Minimum TTL across RRs (300, 0) is 0, so zerottl.example must not be cached.
  auto uncached = made->ResolveEndpoints("zerottl.example", 80, 100);
  if (uncached.has_value()) return Fail("zero_ttl should not be cached");
  return 0;
}

int FastPathAndStaticHostPrecedence() {
  cares::test::LocalDns dns(cares::test::DnsMode::Answer);
  if (dns.Port() == 0) return Fail("bind fast");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring fast");
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 200, 1), cares::test::DualConfig());
  if (!made) return Fail("resolver fast");

  auto v4 = made->ResolveEndpoints("127.0.0.1:8080", 80, 100);
  if (!v4 || v4->size() != 1 || (*v4)[0].port != 8080) return Fail("v4 literal");
  auto v6 = made->ResolveEndpoints("[::1]:9090", 80, 100);
  if (!v6 || v6->size() != 1 || (*v6)[0].port != 9090 || !(*v6)[0].ip.IsV6()) return Fail("v6 literal");

  const cares::IpAddress static_ip = cares::IpAddress::FromV4(cares::Ipv4Bytes{10, 9, 8, 7});
  if (!made->InsertStaticHost("app.example", static_ip)) return Fail("insert static");
  auto hit = made->ResolveEndpoints("app.example:443", 80, 100);
  if (!hit || hit->size() != 1 || (*hit)[0].ip != static_ip || (*hit)[0].port != 443) return Fail("static precedence");
  if (dns.UdpQueries() != 0u || dns.TcpQueries() != 0u) return Fail("fast-path network queries");
  return 0;
}

int SubsystemValidation() {
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring sub");
  cares::ResolverConfig bad0 = cares::test::Ipv4Config();
  bad0.subsystem_id = 0;
  auto r0 = cares::Resolver<>::FromSystem(*ring, bad0);
  if (r0.has_value() || r0.error() != cares::Error::InvalidArgument()) return Fail("subsystem 0 accepted");
  cares::ResolverConfig bad255 = cares::test::Ipv4Config();
  bad255.subsystem_id = 255;
  auto r255 = cares::Resolver<>::FromSystem(*ring, bad255);
  if (r255.has_value() || r255.error() != cares::Error::InvalidArgument()) return Fail("subsystem 255 accepted");
  return 0;
}

int FromSystemSmoke() {
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring sys");
  auto sys = cares::Resolver<>::FromSystem(*ring);
  if (!sys) return Fail("FromSystem");
  if (!sys->ResolveEndpoints("127.0.0.1:53", 53, 50)) return Fail("FromSystem literal");
  return 0;
}

int TypedResolveAndWire() {
  cares::test::LocalDns dns(cares::test::DnsMode::Answer);
  if (dns.Port() == 0) return Fail("bind typed");
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return Fail("ring typed");
  cares::ResolverConfig custom_cfg = cares::test::Ipv4Config();
  custom_cfg.subsystem_id = 7;
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 200, 2), custom_cfg);
  if (!made || made->SubsystemId() != 7) return Fail("custom subsystem");

  auto rr_a = made->Resolve<cares::ARecord>("app.example", cares::DnsType::A, 2000);
  const cares::IpAddress expect = cares::IpAddress::FromV4(cares::Ipv4Bytes{192, 0, 2, 10});
  if (!rr_a || rr_a->ttl != 60u || rr_a->addr != expect) return Fail("Resolve<ARecord>");

  auto reflected = made->Resolve<ReflectedAView>("app.example", cares::DnsType::A, 2000);
  if (!reflected || reflected->ttl != 60u || reflected->addr != expect) return Fail("Resolve<ReflectedAView>");

  auto wire = made->ResolveWire("app.example", cares::DnsType::A, 2000);
  if (!wire || wire->AsRef().RrCount(cares::RecordSection::Answer) != 1u) return Fail("ResolveWire");
  return 0;
}

}  // namespace

int main() {
  if (const int failed = CachedAnswer(); failed != 0) return failed;
  if (const int failed = DualStack(); failed != 0) return failed;
  if (const int failed = PartialDualStackCache(); failed != 0) return failed;
  if (const int failed = MixedFamilyFailure(); failed != 0) return failed;
  if (const int failed = DedupeAndMinTtl(); failed != 0) return failed;
  if (const int failed = FastPathAndStaticHostPrecedence(); failed != 0) return failed;
  if (const int failed = SubsystemValidation(); failed != 0) return failed;
  if (const int failed = FromSystemSmoke(); failed != 0) return failed;
  return TypedResolveAndWire();
}
