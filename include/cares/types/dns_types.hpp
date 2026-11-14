#pragma once
#include <ares.h>
#include <ares_dns_record.h>

#include <cstdint>
#include <utility>

namespace cares {

enum class DnsClass : std::uint16_t {
  IN = ARES_CLASS_IN,
  CHAOS = ARES_CLASS_CHAOS,
  HESIOD = ARES_CLASS_HESIOD,
  HESOID = ARES_CLASS_HESOID,
  NONE = ARES_CLASS_NONE,
  ANY = ARES_CLASS_ANY,
};

enum class DnsType : std::uint16_t {
  A = ARES_REC_TYPE_A,
  NS = ARES_REC_TYPE_NS,
  CNAME = ARES_REC_TYPE_CNAME,
  SOA = ARES_REC_TYPE_SOA,
  PTR = ARES_REC_TYPE_PTR,
  HINFO = ARES_REC_TYPE_HINFO,
  MX = ARES_REC_TYPE_MX,
  TXT = ARES_REC_TYPE_TXT,
  AAAA = ARES_REC_TYPE_AAAA,
  SRV = ARES_REC_TYPE_SRV,
  NAPTR = ARES_REC_TYPE_NAPTR,
  OPT = ARES_REC_TYPE_OPT,
  TLSA = ARES_REC_TYPE_TLSA,
  SVCB = ARES_REC_TYPE_SVCB,
  HTTPS = ARES_REC_TYPE_HTTPS,
  ANY = ARES_REC_TYPE_ANY,
  URI = ARES_REC_TYPE_URI,
  CAA = ARES_REC_TYPE_CAA,
};

enum class RecordSection : std::uint8_t {
  Answer = ARES_SECTION_ANSWER,
  Authority = ARES_SECTION_AUTHORITY,
  Additional = ARES_SECTION_ADDITIONAL,
};

enum class DnsRcode : std::uint8_t {
  NoError = ARES_RCODE_NOERROR,
  FormErr = ARES_RCODE_FORMERR,
  ServFail = ARES_RCODE_SERVFAIL,
  NxDomain = ARES_RCODE_NXDOMAIN,
  NotImp = ARES_RCODE_NOTIMP,
  Refused = ARES_RCODE_REFUSED,
  YXDomain = ARES_RCODE_YXDOMAIN,
  YXRRSet = ARES_RCODE_YXRRSET,
  NXRRSet = ARES_RCODE_NXRRSET,
  NotAuth = ARES_RCODE_NOTAUTH,
  NotZone = ARES_RCODE_NOTZONE,
};

enum class DnsOpcode : std::uint8_t {
  Query = ARES_OPCODE_QUERY,
  IQuery = ARES_OPCODE_IQUERY,
  Status = ARES_OPCODE_STATUS,
  Notify = ARES_OPCODE_NOTIFY,
  Update = ARES_OPCODE_UPDATE,
};

enum class DnsFlags : std::uint16_t {
  None = 0,
  Qr = ARES_FLAG_QR,
  Aa = ARES_FLAG_AA,
  Tc = ARES_FLAG_TC,
  Rd = ARES_FLAG_RD,
  Ra = ARES_FLAG_RA,
  Ad = ARES_FLAG_AD,
  Cd = ARES_FLAG_CD,
};
[[nodiscard]] constexpr DnsFlags operator|(DnsFlags a, DnsFlags b) noexcept;
[[nodiscard]] constexpr DnsFlags operator&(DnsFlags a, DnsFlags b) noexcept;
[[nodiscard]] constexpr bool HasFlag(DnsFlags flags, DnsFlags bit) noexcept;

constexpr DnsFlags operator|(DnsFlags a, DnsFlags b) noexcept {
  return static_cast<DnsFlags>(std::to_underlying(a) | std::to_underlying(b));
}
constexpr DnsFlags operator&(DnsFlags a, DnsFlags b) noexcept {
  return static_cast<DnsFlags>(std::to_underlying(a) & std::to_underlying(b));
}
constexpr bool HasFlag(DnsFlags flags, DnsFlags bit) noexcept { return (flags & bit) == bit; }
}  // namespace cares
