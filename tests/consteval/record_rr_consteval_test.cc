#include <cares/record/dns_record.hpp>
#include <cares/record/record_rr.hpp>
#include <type_traits>
#include <uarch/uarch.hpp>

namespace cares {
namespace {

consteval bool VerifyRecordLayoutsAndConcepts() noexcept {
  static_assert(DnsRecordStruct<ARecord> && ARecord::kDnsType == DnsType::A);
  static_assert(DnsRecordStruct<AaaaRecord> && AaaaRecord::kDnsType == DnsType::AAAA);
  static_assert(DnsRecordStruct<CnameRecord> && CnameRecord::kDnsType == DnsType::CNAME);
  static_assert(DnsRecordStruct<MxRecord> && MxRecord::kDnsType == DnsType::MX);
  static_assert(DnsRecordStruct<TxtRecord> && TxtRecord::kDnsType == DnsType::TXT);
  static_assert(DnsRecordStruct<SrvRecord> && SrvRecord::kDnsType == DnsType::SRV);
  static_assert(DnsRecordStruct<PtrRecord> && PtrRecord::kDnsType == DnsType::PTR);
  static_assert(DnsRecordStruct<SoaRecord> && SoaRecord::kDnsType == DnsType::SOA);
  static_assert(DnsRecordStruct<NsRecord> && NsRecord::kDnsType == DnsType::NS);
  static_assert(DnsRecordStruct<NaptrRecord> && NaptrRecord::kDnsType == DnsType::NAPTR);
  static_assert(DnsRecordStruct<CaaRecord> && CaaRecord::kDnsType == DnsType::CAA);
  static_assert(DnsRecordStruct<UriRecord> && UriRecord::kDnsType == DnsType::URI);
  static_assert(DnsRecordStruct<TlsaRecord> && TlsaRecord::kDnsType == DnsType::TLSA);
  static_assert(DnsRecordStruct<SvcbRecord> && SvcbRecord::kDnsType == DnsType::SVCB);
  static_assert(DnsRecordStruct<HttpsRecord> && HttpsRecord::kDnsType == DnsType::HTTPS);
  static_assert(DnsRecordStruct<OptRecord> && OptRecord::kDnsType == DnsType::OPT);
  static_assert(DnsRecordStruct<HinfoRecord> && HinfoRecord::kDnsType == DnsType::HINFO);
  static_assert(!DnsRecordStruct<QuestionItem>);

  static_assert(uarch::layout::NoPadding<DnsRecordRef>);
  static_assert(uarch::layout::RegisterPassable<DnsRecordRef>);
  static_assert(uarch::layout::RegisterLeaf<DnsRecordRef>);
  static_assert(sizeof(DnsRecordRef) == 8);

  static_assert(!std::is_copy_constructible_v<DnsRecord>);
  static_assert(!std::is_copy_assignable_v<DnsRecord>);
  static_assert(std::is_nothrow_move_constructible_v<DnsRecord>);
  static_assert(std::is_nothrow_move_assignable_v<DnsRecord>);
  return true;
}

consteval bool VerifyRecordCapacitiesAndLengthTypes() noexcept {
  static_assert(std::tuple_size_v<decltype(CnameRecord::cname)> == 256);
  static_assert(std::is_same_v<decltype(CnameRecord::len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(MxRecord::exchange)> == 256);
  static_assert(std::is_same_v<decltype(MxRecord::len), std::uint16_t>);

  static_assert(std::is_same_v<decltype(TxtRecord::text), TxtBuffer>);
  static_assert(TxtRecord::kMaxBytes == 65279);

  static_assert(std::tuple_size_v<decltype(SrvRecord::target)> == 256);
  static_assert(std::is_same_v<decltype(SrvRecord::len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(PtrRecord::dname)> == 256);
  static_assert(std::is_same_v<decltype(PtrRecord::len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(SoaRecord::mname)> == 256);
  static_assert(std::tuple_size_v<decltype(SoaRecord::rname)> == 256);
  static_assert(std::is_same_v<decltype(SoaRecord::mname_len), std::uint16_t>);
  static_assert(std::is_same_v<decltype(SoaRecord::rname_len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(NsRecord::nsdname)> == 256);
  static_assert(std::is_same_v<decltype(NsRecord::len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(NaptrRecord::flags)> == 64);
  static_assert(std::tuple_size_v<decltype(NaptrRecord::service)> == 128);
  static_assert(std::tuple_size_v<decltype(NaptrRecord::regexp)> == 128);
  static_assert(std::tuple_size_v<decltype(NaptrRecord::replacement)> == 256);
  static_assert(std::is_same_v<decltype(NaptrRecord::flags_len), std::uint8_t>);
  static_assert(std::is_same_v<decltype(NaptrRecord::service_len), std::uint8_t>);
  static_assert(std::is_same_v<decltype(NaptrRecord::regexp_len), std::uint8_t>);
  static_assert(std::is_same_v<decltype(NaptrRecord::replacement_len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(CaaRecord::tag)> == 64);
  static_assert(std::tuple_size_v<decltype(CaaRecord::value)> == 256);
  static_assert(std::is_same_v<decltype(CaaRecord::tag_len), std::uint8_t>);
  static_assert(std::is_same_v<decltype(CaaRecord::value_len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(UriRecord::target)> == 256);
  static_assert(std::is_same_v<decltype(UriRecord::target_len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(TlsaRecord::data)> == 256);
  static_assert(std::is_same_v<decltype(TlsaRecord::data_len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(SvcbRecord::target)> == 256);
  static_assert(std::is_same_v<decltype(SvcbRecord::target_len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(HttpsRecord::target)> == 256);
  static_assert(std::is_same_v<decltype(HttpsRecord::target_len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(HinfoRecord::cpu)> == 128);
  static_assert(std::tuple_size_v<decltype(HinfoRecord::os)> == 128);
  static_assert(std::is_same_v<decltype(HinfoRecord::cpu_len), std::uint8_t>);
  static_assert(std::is_same_v<decltype(HinfoRecord::os_len), std::uint8_t>);

  static_assert(std::tuple_size_v<decltype(QuestionItem::name)> == 256);
  static_assert(std::is_same_v<decltype(QuestionItem::name_len), std::uint16_t>);

  static_assert(std::tuple_size_v<decltype(RecordItem::name)> == 256);
  static_assert(std::is_same_v<decltype(RecordItem::name_len), std::uint16_t>);
  return true;
}

consteval bool VerifyRrKeyValidation() noexcept {
  if (!IsValidRrKeyForType(DnsType::A, ARES_RR_A_ADDR)) return false;
  if (!IsValidRrKeyForType(DnsType::AAAA, ARES_RR_AAAA_ADDR)) return false;
  if (!IsValidRrKeyForType(DnsType::CNAME, ARES_RR_CNAME_CNAME)) return false;
  if (!IsValidRrKeyForType(DnsType::MX, ARES_RR_MX_PREFERENCE)) return false;
  if (!IsValidRrKeyForType(DnsType::MX, ARES_RR_MX_EXCHANGE)) return false;
  if (!IsValidRrKeyForType(DnsType::TXT, ARES_RR_TXT_DATA)) return false;
  if (!IsValidRrKeyForType(DnsType::SRV, ARES_RR_SRV_PORT)) return false;
  if (!IsValidRrKeyForType(DnsType::PTR, ARES_RR_PTR_DNAME)) return false;
  if (!IsValidRrKeyForType(DnsType::SOA, ARES_RR_SOA_SERIAL)) return false;
  if (!IsValidRrKeyForType(DnsType::NS, ARES_RR_NS_NSDNAME)) return false;
  if (!IsValidRrKeyForType(DnsType::NAPTR, ARES_RR_NAPTR_REPLACEMENT)) return false;
  if (!IsValidRrKeyForType(DnsType::CAA, ARES_RR_CAA_VALUE)) return false;
  if (!IsValidRrKeyForType(DnsType::URI, ARES_RR_URI_TARGET)) return false;
  if (!IsValidRrKeyForType(DnsType::TLSA, ARES_RR_TLSA_DATA)) return false;
  if (!IsValidRrKeyForType(DnsType::SVCB, ARES_RR_SVCB_TARGET)) return false;
  if (!IsValidRrKeyForType(DnsType::HTTPS, ARES_RR_HTTPS_TARGET)) return false;
  if (!IsValidRrKeyForType(DnsType::OPT, ARES_RR_OPT_UDP_SIZE)) return false;

  if (IsValidRrKeyForType(DnsType::A, ARES_RR_AAAA_ADDR)) return false;
  if (IsValidRrKeyForType(DnsType::TXT, ARES_RR_MX_EXCHANGE)) return false;
  if (IsValidRrKeyForType(DnsType::ANY, ARES_RR_A_ADDR)) return false;
  if (!IsValidRrKey(ARES_RR_SRV_TARGET)) return false;
  return true;
}

consteval bool VerifyConstexprRecordViews() noexcept {
  ARecord a{.addr = IpAddress::FromV4({10, 0, 0, 1}), .ttl = 60};
  if (!a.addr.IsV4() || a.ttl != 60) return false;

  AaaaRecord aaaa{.addr = IpAddress::FromV6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), .ttl = 120};
  if (!aaaa.addr.IsV6() || aaaa.ttl != 120) return false;

  CnameRecord cname{};
  cname.cname = {'a', 'l', 'i', 'a', 's', '\0'};
  cname.len = 5;
  cname.ttl = 300;
  if (cname.View() != "alias") return false;

  MxRecord mx{};
  mx.preference = 10;
  mx.exchange = {'m', 'x', '.', 'e', 'x', '\0'};
  mx.len = 5;
  if (mx.Exchange() != "mx.ex" || mx.preference != 10) return false;

  SrvRecord srv{};
  srv.priority = 1;
  srv.weight = 5;
  srv.port = 443;
  srv.target = {'s', 'v', 'c', '\0'};
  srv.len = 3;
  if (srv.Target() != "svc" || srv.port != 443) return false;

  OptRecord opt{.udp_size = 1232, .version = 0, .flags = 0x8000, .ttl = 0};
  if (opt.udp_size != 1232 || opt.flags != 0x8000) return false;

  QuestionItem q{};
  q.name = {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', '\0'};
  q.name_len = 11;
  q.qtype = DnsType::AAAA;
  q.qclass = DnsClass::IN;
  if (q.Name() != "example.com" || q.qtype != DnsType::AAAA) return false;

  RecordItem item{};
  item.name = {'h', 'o', 's', 't', '\0'};
  item.name_len = 4;
  item.section = RecordSection::Answer;
  item.rtype = DnsType::A;
  item.rclass = DnsClass::IN;
  item.ttl = 60;
  item.data = a;
  if (item.Name() != "host" || !std::holds_alternative<ARecord>(item.data)) return false;

  constexpr DnsRecordRef kEmptyRef{};
  if (kEmptyRef.IsValid() || kEmptyRef.Raw() != nullptr) return false;

  return true;
}

static_assert(VerifyRecordLayoutsAndConcepts());
static_assert(VerifyRecordCapacitiesAndLengthTypes());
static_assert(VerifyRrKeyValidation());
static_assert(VerifyConstexprRecordViews());

}  // namespace
}  // namespace cares

int main() { return 0; }
