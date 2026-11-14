// expected-error: field key does not belong to the record type
#include <cares/record/record_extract.hpp>

struct[[= cares::notes::Answer]][[= cares::notes::Type(cares::DnsType::A)]] MxOnA {
  cares::IpAddress addr[[= cares::notes::Field(ARES_RR_MX_EXCHANGE)]];
};

int main() { return cares::ExtractRecord<MxOnA>(cares::DnsRecordRef{}).has_value() ? 0 : 1; }
