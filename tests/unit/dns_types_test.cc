#include <cares/types/dns_types.hpp>
static_assert(cares::HasFlag(cares::DnsFlags::Rd | cares::DnsFlags::Ad, cares::DnsFlags::Rd));
static_assert(!cares::HasFlag(cares::DnsFlags::Rd, cares::DnsFlags::Ad));
static_assert(cares::HasFlag(cares::DnsFlags::Rd | cares::DnsFlags::Ad, cares::DnsFlags::Rd | cares::DnsFlags::Ad));
static_assert(!cares::HasFlag(cares::DnsFlags::Rd, cares::DnsFlags::Rd | cares::DnsFlags::Ad));
static_assert(std::to_underlying(cares::DnsType::AAAA) == 28);
static_assert(std::to_underlying(cares::DnsClass::IN) == 1);
static_assert(cares::DnsClass::HESIOD == cares::DnsClass::HESOID);
int main() { return 0; }
