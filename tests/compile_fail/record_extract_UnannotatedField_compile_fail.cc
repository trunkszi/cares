// expected-error: unannotated field
#include <cares/record/record_extract.hpp>

struct[[= cares::notes::Answer]][[= cares::notes::Type(cares::DnsType::A)]] BadRecord {
  cares::IpAddress addr[[= cares::notes::Field(ARES_RR_A_ADDR)]];
  std::uint32_t extra;
};

int main() { return cares::ExtractRecord<BadRecord>(cares::DnsRecordRef{}).has_value() ? 0 : 1; }
