#include <cares/cares.hpp>
#include <cstdint>
#include <cstdio>

struct[[= cares::notes::Answer]][[= cares::notes::Type(cares::DnsType::A)]] AView {
  cares::IpAddress addr[[= cares::notes::Field(ARES_RR_A_ADDR)]];
  std::uint32_t ttl[[= cares::notes::Ttl]];
};

int main() {
  auto guard = cares::LibraryGuard::Acquire();
  if (!guard) return 1;
  auto rec = cares::DnsRecord::Create(7, cares::DnsFlags::Qr, cares::DnsOpcode::Query, cares::DnsRcode::NoError);
  if (!rec) return 1;
  const cares::ARecord rr{.addr = cares::IpAddress::FromV4(cares::Ipv4Bytes{192, 0, 2, 10}), .ttl = 60};
  if (!rec->AddRr(cares::RecordSection::Answer, "app.example", rr)) return 1;
  const auto extracted = cares::ExtractRecord<AView>(rec->AsRef());
  if (!extracted || extracted->ttl != 60 || !extracted->addr.IsV4()) return 1;
  if (extracted->addr != rr.addr) return 1;
  std::printf("extracted ttl %u\n", extracted->ttl);
  return 0;
}
