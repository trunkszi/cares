// expected-error: Invalid ares_dns_rr_key_t for the specified DnsType
#include <cares/record/record_rr.hpp>

int main() {
  cares::RequireValidRrKey<cares::DnsType::A, ARES_RR_AAAA_ADDR>();
  return 0;
}
