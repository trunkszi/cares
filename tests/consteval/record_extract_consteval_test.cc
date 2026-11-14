#include <cares/record/record_extract.hpp>
#include <cstdint>

struct[[= cares::notes::Answer]][[= cares::notes::Type(cares::DnsType::A)]] ConstA {
  cares::IpAddress addr[[= cares::notes::Field(ARES_RR_A_ADDR)]]{};
  std::uint32_t ttl[[= cares::notes::Ttl]]{};
};

struct[[= cares::notes::Authority]][[= cares::notes::Type(cares::DnsType::NS)]] ConstNs {
  std::array<char, 256> nsdname[[= cares::notes::Field(ARES_RR_NS_NSDNAME)]]{};
  std::uint16_t len[[= cares::notes::Field(ARES_RR_NS_NSDNAME)]]{};
  std::uint32_t ttl[[= cares::notes::Ttl]]{};
};

static_assert(cares::RecordSectionOf<ConstA>() == cares::RecordSection::Answer);
static_assert(cares::RecordTypeOf<ConstA>() == cares::DnsType::A);
static_assert(cares::RecordFieldCount<ConstA>() == 2);
static_assert(cares::RecordSectionOf<ConstNs>() == cares::RecordSection::Authority);
static_assert(cares::RecordTypeOf<ConstNs>() == cares::DnsType::NS);
static_assert(cares::RecordFieldCount<ConstNs>() == 3);

int main() { return cares::RecordFieldCount<ConstA>() == 2 && cares::RecordTypeOf<ConstNs>() == cares::DnsType::NS ? 0 : 1; }
