#include <ares.h>

#include <array>
#include <cares/record/dns_record.hpp>
#include <cares/record/record_rr.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <variant>

namespace cares {
namespace {

template <std::size_t N>
[[nodiscard]] constexpr std::array<char, N> MakeCharArray(std::string_view sv) noexcept {
  std::array<char, N> out{};
  for (std::size_t i = 0; i < sv.size() && i + 1 < N; ++i) {
    out[i] = sv[i];
  }
  return out;
}

// Core RFC 1035/3596/2782 RRs survive a wire round trip.
[[nodiscard]] bool CoreRrsWireRoundTrip() noexcept {
  auto pkt_res =
      DnsRecord::Create(0x1234, DnsFlags::Qr | DnsFlags::Aa | DnsFlags::Rd | DnsFlags::Ra, DnsOpcode::Query, DnsRcode::NoError);
  if (!pkt_res) return false;
  DnsRecord& pkt = *pkt_res;
  if (!pkt.QuestionPush("svc.example.com", DnsType::A, DnsClass::IN)) return false;

  constexpr std::string_view kCnameStr = "target.example.com";
  constexpr std::string_view kMxStr = "mail.example.com";
  constexpr std::string_view kTxtStr = "v=spf1 include:example.com ~all";
  constexpr std::string_view kSrvStr = "api.example.com";
  constexpr std::string_view kPtrStr = "host42.example.com";
  constexpr std::string_view kSoaMname = "ns1.example.com";
  constexpr std::string_view kSoaRname = "admin.example.com";
  constexpr std::string_view kNsStr = "ns2.example.com";

  ARecord a_in{.addr = IpAddress::FromV4({192, 0, 2, 42}), .ttl = 60};
  AaaaRecord aaaa_in{.addr = IpAddress::FromV6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x99}), .ttl = 120};
  CnameRecord cname_in{.cname = MakeCharArray<256>(kCnameStr), .len = static_cast<std::uint16_t>(kCnameStr.size()), .ttl = 180};
  MxRecord mx_in{
      .preference = 10, .exchange = MakeCharArray<256>(kMxStr), .len = static_cast<std::uint16_t>(kMxStr.size()), .ttl = 240};
  auto txt_text = TxtBuffer::Copy(kTxtStr);
  if (!txt_text) return false;
  TxtRecord txt_in{.text = std::move(*txt_text), .ttl = 300};
  SrvRecord srv_in{.priority = 5,
                   .weight = 20,
                   .port = 8443,
                   .target = MakeCharArray<256>(kSrvStr),
                   .len = static_cast<std::uint16_t>(kSrvStr.size()),
                   .ttl = 360};
  PtrRecord ptr_in{.dname = MakeCharArray<256>(kPtrStr), .len = static_cast<std::uint16_t>(kPtrStr.size()), .ttl = 420};
  SoaRecord soa_in{.mname = MakeCharArray<256>(kSoaMname),
                   .mname_len = static_cast<std::uint16_t>(kSoaMname.size()),
                   .rname = MakeCharArray<256>(kSoaRname),
                   .rname_len = static_cast<std::uint16_t>(kSoaRname.size()),
                   .serial = 2026111001u,
                   .refresh = 3600u,
                   .retry = 900u,
                   .expire = 604800u,
                   .minimum = 86400u,
                   .ttl = 480};
  NsRecord ns_in{.nsdname = MakeCharArray<256>(kNsStr), .len = static_cast<std::uint16_t>(kNsStr.size()), .ttl = 540};

  if (!pkt.AddRr(RecordSection::Answer, "svc.example.com", a_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "svc.example.com", aaaa_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "alias.example.com", cname_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "example.com", mx_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "example.com", txt_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "_https._tcp.example.com", srv_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "42.2.0.192.in-addr.arpa", ptr_in)) return false;
  if (!pkt.AddRr(RecordSection::Authority, "example.com", soa_in)) return false;
  if (!pkt.AddRr(RecordSection::Authority, "example.com", ns_in)) return false;

  std::array<std::byte, 2048> wire{};
  auto written = pkt.WriteWire(wire);
  if (!written || *written == 0) return false;

  auto parsed_res = DnsRecord::ParseWire(std::span<const std::byte>(wire.data(), *written));
  if (!parsed_res) return false;
  const DnsRecordRef view = parsed_res->AsRef();

  if (view.RrCount(RecordSection::Answer) != 7 || view.RrCount(RecordSection::Authority) != 2) {
    return false;
  }

  auto a_out = view.ExtractRrAt<ARecord>(RecordSection::Answer, 0);
  auto aaaa_out = view.ExtractRrAt<AaaaRecord>(RecordSection::Answer, 1);
  auto cname_out = view.ExtractRrAt<CnameRecord>(RecordSection::Answer, 2);
  auto mx_out = view.ExtractRrAt<MxRecord>(RecordSection::Answer, 3);
  auto txt_out = view.ExtractRrAt<TxtRecord>(RecordSection::Answer, 4);
  auto srv_out = view.ExtractRrAt<SrvRecord>(RecordSection::Answer, 5);
  auto ptr_out = view.ExtractRrAt<PtrRecord>(RecordSection::Answer, 6);
  auto soa_out = view.ExtractRrAt<SoaRecord>(RecordSection::Authority, 0);
  auto ns_out = view.ExtractRrAt<NsRecord>(RecordSection::Authority, 1);

  if (!a_out || *a_out != a_in || a_out->ttl != 60) return false;
  if (!aaaa_out || *aaaa_out != aaaa_in || aaaa_out->ttl != 120) return false;
  if (!cname_out || cname_out->View() != kCnameStr || cname_out->ttl != 180) return false;
  if (!mx_out || mx_out->preference != 10 || mx_out->Exchange() != kMxStr || mx_out->ttl != 240) {
    return false;
  }
  if (!txt_out || txt_out->View() != kTxtStr || txt_out->Bytes().size() != txt_in.text.size() || txt_out->ttl != 300) {
    return false;
  }
  if (!srv_out || srv_out->priority != 5 || srv_out->weight != 20 || srv_out->port != 8443 || srv_out->Target() != kSrvStr ||
      srv_out->ttl != 360) {
    return false;
  }
  if (!ptr_out || ptr_out->View() != kPtrStr || ptr_out->ttl != 420) return false;
  if (!soa_out || soa_out->Mname() != kSoaMname || soa_out->Rname() != kSoaRname || soa_out->serial != 2026111001u ||
      soa_out->refresh != 3600u || soa_out->retry != 900u || soa_out->expire != 604800u || soa_out->minimum != 86400u ||
      soa_out->ttl != 480) {
    return false;
  }
  if (!ns_out || ns_out->View() != kNsStr || ns_out->ttl != 540) return false;

  return true;
}

// Extended RRs and a multi-chunk TXT survive a wire round trip.
[[nodiscard]] bool ExtendedRrsAndEdnsRoundTrip() noexcept {
  auto pkt_res = DnsRecord::Create(0x5678, DnsFlags::Qr | DnsFlags::Aa, DnsOpcode::Query, DnsRcode::NoError);
  if (!pkt_res) return false;
  DnsRecord& pkt = *pkt_res;
  if (!pkt.QuestionPush("ext.example.com", DnsType::HTTPS, DnsClass::IN)) return false;

  constexpr std::string_view kNaptrFlags = "u";
  constexpr std::string_view kNaptrSvc = "E2U+sip";
  constexpr std::string_view kNaptrRegexp = "!^.*$!sip:info@example.com!";
  constexpr std::string_view kNaptrRepl = "_sip._udp.example.com";
  NaptrRecord naptr_in{.order = 100,
                       .preference = 50,
                       .flags = MakeCharArray<64>(kNaptrFlags),
                       .flags_len = static_cast<std::uint8_t>(kNaptrFlags.size()),
                       .service = MakeCharArray<128>(kNaptrSvc),
                       .service_len = static_cast<std::uint8_t>(kNaptrSvc.size()),
                       .regexp = MakeCharArray<128>(kNaptrRegexp),
                       .regexp_len = static_cast<std::uint8_t>(kNaptrRegexp.size()),
                       .replacement = MakeCharArray<256>(kNaptrRepl),
                       .replacement_len = static_cast<std::uint16_t>(kNaptrRepl.size()),
                       .ttl = 600};

  constexpr std::string_view kCaaTag = "issue";
  constexpr std::string_view kCaVal = "letsencrypt.org";
  CaaRecord caa_in{.critical = 128,
                   .tag = MakeCharArray<64>(kCaaTag),
                   .tag_len = static_cast<std::uint8_t>(kCaaTag.size()),
                   .value_len = static_cast<std::uint16_t>(kCaVal.size()),
                   .ttl = 660};
  std::memcpy(caa_in.value.data(), kCaVal.data(), kCaVal.size());

  constexpr std::string_view kUriTarget = "https://example.com/service";
  UriRecord uri_in{.priority = 10,
                   .weight = 1,
                   .target = MakeCharArray<256>(kUriTarget),
                   .target_len = static_cast<std::uint16_t>(kUriTarget.size()),
                   .ttl = 720};

  TlsaRecord tlsa_in{.cert_usage = 3, .selector = 1, .match = 1, .data_len = 32, .ttl = 780};
  for (std::size_t i = 0; i < 32; ++i) {
    tlsa_in.data[i] = static_cast<std::uint8_t>(0xA0u + i);
  }

  constexpr std::string_view kSvcbTarget = "svc.example.com";
  SvcbRecord svcb_in{.priority = 1,
                     .target = MakeCharArray<256>(kSvcbTarget),
                     .target_len = static_cast<std::uint16_t>(kSvcbTarget.size()),
                     .ttl = 840};

  constexpr std::string_view kHttpsTarget = "cdn.example.com";
  HttpsRecord https_in{.priority = 1,
                       .target = MakeCharArray<256>(kHttpsTarget),
                       .target_len = static_cast<std::uint16_t>(kHttpsTarget.size()),
                       .ttl = 900};

  constexpr std::string_view kCpu = "X86-64";
  constexpr std::string_view kOs = "LINUX";
  HinfoRecord hinfo_in{.cpu = MakeCharArray<128>(kCpu),
                       .cpu_len = static_cast<std::uint8_t>(kCpu.size()),
                       .os = MakeCharArray<128>(kOs),
                       .os_len = static_cast<std::uint8_t>(kOs.size()),
                       .ttl = 960};

  OptRecord opt_in{.udp_size = 1400, .version = 0, .flags = 0x8000, .ttl = 0};

  if (!pkt.AddRr(RecordSection::Answer, "ext.example.com", naptr_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "ext.example.com", caa_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "_http._tcp.example.com", uri_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "_443._tcp.example.com", tlsa_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "_dns.example.com", svcb_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "ext.example.com", https_in)) return false;
  if (!pkt.AddRr(RecordSection::Answer, "ext.example.com", hinfo_in)) return false;

  // Multi-chunk TXT ABINP record
  auto txt_rr = pkt.RrAdd(RecordSection::Answer, "txt.example.com", DnsType::TXT, DnsClass::IN, 111);
  if (!txt_rr) return false;
  if (ares_dns_rr_add_abin(*txt_rr, ARES_RR_TXT_DATA, reinterpret_cast<const unsigned char*>("part1-"), 6) != ARES_SUCCESS) {
    return false;
  }
  if (ares_dns_rr_add_abin(*txt_rr, ARES_RR_TXT_DATA, reinterpret_cast<const unsigned char*>("part2"), 5) != ARES_SUCCESS) {
    return false;
  }

  if (!pkt.AddRr(RecordSection::Additional, "", opt_in)) return false;

  std::array<std::uint8_t, 2048> wire{};
  auto written = pkt.WriteWire(wire);
  if (!written || *written == 0) return false;

  auto parsed_res = DnsRecord::ParseWire(std::span<const std::uint8_t>(wire.data(), *written));
  if (!parsed_res) return false;
  const DnsRecordRef view = parsed_res->AsRef();

  auto naptr_out = view.ExtractRrAt<NaptrRecord>(RecordSection::Answer, 0);
  auto caa_out = view.ExtractRrAt<CaaRecord>(RecordSection::Answer, 1);
  auto uri_out = view.ExtractRrAt<UriRecord>(RecordSection::Answer, 2);
  auto tlsa_out = view.ExtractRrAt<TlsaRecord>(RecordSection::Answer, 3);
  auto svcb_out = view.ExtractRrAt<SvcbRecord>(RecordSection::Answer, 4);
  auto https_out = view.ExtractRrAt<HttpsRecord>(RecordSection::Answer, 5);
  auto hinfo_out = view.ExtractRrAt<HinfoRecord>(RecordSection::Answer, 6);
  auto txt_out = view.ExtractRrAt<TxtRecord>(RecordSection::Answer, 7);
  auto opt_out = view.ExtractRrAt<OptRecord>(RecordSection::Additional, 0);

  if (!naptr_out || naptr_out->order != 100 || naptr_out->preference != 50 || naptr_out->Flags() != kNaptrFlags ||
      naptr_out->Service() != kNaptrSvc || naptr_out->Regexp() != kNaptrRegexp || naptr_out->Replacement() != kNaptrRepl ||
      naptr_out->ttl != 600) {
    return false;
  }
  if (!caa_out || caa_out->critical != 128 || caa_out->Tag() != kCaaTag || caa_out->ValueView() != kCaVal ||
      caa_out->ttl != 660) {
    return false;
  }
  if (!uri_out || uri_out->priority != 10 || uri_out->weight != 1 || uri_out->Target() != kUriTarget || uri_out->ttl != 720) {
    return false;
  }
  if (!tlsa_out || tlsa_out->cert_usage != 3 || tlsa_out->selector != 1 || tlsa_out->match != 1 ||
      tlsa_out->Data().size() != 32 || tlsa_out->Data()[0] != 0xA0u || tlsa_out->ttl != 780) {
    return false;
  }
  if (!svcb_out || svcb_out->priority != 1 || svcb_out->Target() != kSvcbTarget || svcb_out->ttl != 840) {
    return false;
  }
  if (!https_out || https_out->priority != 1 || https_out->Target() != kHttpsTarget || https_out->ttl != 900) {
    return false;
  }
  if (!hinfo_out || hinfo_out->Cpu() != kCpu || hinfo_out->Os() != kOs || hinfo_out->ttl != 960) {
    return false;
  }
  if (!txt_out || txt_out->View() != "part1-part2" || txt_out->ttl != 111) return false;
  if (!opt_out || opt_out->udp_size != 1400 || opt_out->version != 0 || opt_out->flags != 0x8000 || opt_out->ttl != 0) {
    return false;
  }

  // Verify RecordItem / RecordVariant polymorphism
  auto item_res = view.ExtractRecordItemAt(RecordSection::Answer, 5);
  if (!item_res || item_res->Name() != "ext.example.com" || item_res->rtype != DnsType::HTTPS || item_res->ttl != 900 ||
      !std::holds_alternative<HttpsRecord>(item_res->data)) {
    return false;
  }
  if (std::get<HttpsRecord>(item_res->data).Target() != kHttpsTarget) return false;

  // Negative check: type mismatch on ExtractRrAt must fail with Ebadresp
  auto mismatch = view.ExtractRrAt<ARecord>(RecordSection::Answer, 0);
  if (mismatch || mismatch.error().AsAresStatus() != AresStatus::BadResp) return false;

  return true;
}

// Hand-built RFC 1035 packet with a compression pointer yields A and AAAA.
[[nodiscard]] bool GoldenWirePacketParseAAndAaaa() noexcept {
  // Header (12B): ID=0xCAFE, Flags=0x8180 (QR|RD|RA), QDCOUNT=1, ANCOUNT=2, NSCOUNT=0, ARCOUNT=0
  // Question: 7"example"3"com"0, QTYPE=1 (A), QCLASS=1 (IN) -> 17B (ends at offset 29)
  // Answer 0: Name=0xC00C (ptr to offset 12 "example.com"), TYPE=1 (A), CLASS=1 (IN),
  //           TTL=300 (0x0000012C), RDLENGTH=4, RDATA=93.184.216.34 (5D B8 D8 22)
  // Answer 1: Name=0xC00C, TYPE=28 (AAAA), CLASS=1 (IN),
  //           TTL=600 (0x00000258), RDLENGTH=16,
  //           RDATA=2606:2800:0220:0001:0248:1893:25c8:1946
  constexpr std::array<std::uint8_t, 73> kGoldenWire = {
      0xCA, 0xFE, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
      // Question: example.com A IN
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
      // Answer 0: example.com A 93.184.216.34 TTL 300
      0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 93, 184, 216, 34,
      // Answer 1: example.com AAAA 2606:2800:220:1:248:1893:25c8:1946 TTL 600
      0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x10, 0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
      0x02, 0x48, 0x18, 0x93, 0x25, 0xC8, 0x19, 0x46};

  auto parsed_res = DnsRecord::ParseWire(std::span<const std::uint8_t>(kGoldenWire));
  if (!parsed_res) return false;
  const DnsRecordRef view = parsed_res->AsRef();

  if (view.Id() != 0xCAFEu || view.Rcode() != DnsRcode::NoError) return false;
  if (view.QuestionCount() != 1 || view.RrCount(RecordSection::Answer) != 2) return false;

  auto q0 = view.QuestionAt(0);
  if (!q0 || q0->Name() != "example.com" || q0->qtype != DnsType::A || q0->qclass != DnsClass::IN) {
    return false;
  }

  auto a_rec = view.ExtractRrAt<ARecord>(RecordSection::Answer, 0);
  if (!a_rec || a_rec->ttl != 300 || a_rec->addr != IpAddress::FromV4({93, 184, 216, 34})) {
    return false;
  }

  auto aaaa_rec = view.ExtractRrAt<AaaaRecord>(RecordSection::Answer, 1);
  const IpAddress expected_v6 =
      IpAddress::FromV6({0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xC8, 0x19, 0x46});
  if (!aaaa_rec || aaaa_rec->ttl != 600 || aaaa_rec->addr != expected_v6) {
    return false;
  }

  return true;
}

}  // namespace
}  // namespace cares

int main() {
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) return 1;
  const bool ok =
      cares::CoreRrsWireRoundTrip() && cares::ExtendedRrsAndEdnsRoundTrip() && cares::GoldenWirePacketParseAAndAaaa();
  ares_library_cleanup();
  return ok ? 0 : 1;
}
