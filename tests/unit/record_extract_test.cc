#include <ares.h>
#include <ares_dns_record.h>
#include <netinet/in.h>

#include <array>
#include <cares/record/record_extract.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <source_location>

namespace {

int g_failed = 0;

inline void Check(bool ok, const std::source_location where = std::source_location::current()) {
  if (ok) return;
  std::fprintf(stderr, "FAIL %s:%u\n", where.file_name(), where.line());
  ++g_failed;
}

struct OwnedRecord {
  ares_dns_record_t *rec{nullptr};
  ~OwnedRecord() {
    if (rec != nullptr) ares_dns_record_destroy(rec);
  }
  OwnedRecord() = default;
  OwnedRecord(const OwnedRecord &) = delete ("single-owner resource");
  OwnedRecord &operator=(const OwnedRecord &) = delete ("single-owner resource");
};

[[nodiscard]] bool Create(OwnedRecord &owned) {
  return ares_dns_record_create(&owned.rec, 7, ARES_FLAG_QR, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR) == ARES_SUCCESS;
}

struct[[= cares::notes::Answer]][[= cares::notes::Type(cares::DnsType::A)]] AView {
  cares::IpAddress addr[[= cares::notes::Field(ARES_RR_A_ADDR)]];
  std::uint32_t ttl[[= cares::notes::Ttl]];
};

struct[[= cares::notes::Answer]][[= cares::notes::Type(cares::DnsType::CNAME)]] CnameView {
  std::array<char, 256> cname[[= cares::notes::Field(ARES_RR_CNAME_CNAME)]];
  std::uint16_t len[[= cares::notes::Field(ARES_RR_CNAME_CNAME)]];
  std::uint32_t ttl[[= cares::notes::Ttl]];
};

struct[[= cares::notes::Authority]][[= cares::notes::Type(cares::DnsType::NS)]] NsView {
  std::array<char, 256> nsdname[[= cares::notes::Field(ARES_RR_NS_NSDNAME)]];
  std::uint16_t len[[= cares::notes::Field(ARES_RR_NS_NSDNAME)]];
  std::uint32_t ttl[[= cares::notes::Ttl]];
};

void ExtractFirstA() {
  OwnedRecord owned;
  Check(Create(owned));
  ares_dns_rr_t *first = nullptr;
  ares_dns_rr_t *second = nullptr;
  Check(ares_dns_record_rr_add(&first, owned.rec, ARES_SECTION_ANSWER, "example.com", ARES_REC_TYPE_CNAME, ARES_CLASS_IN, 30) ==
        ARES_SUCCESS);
  Check(ares_dns_rr_set_str(first, ARES_RR_CNAME_CNAME, "target.example") == ARES_SUCCESS);
  Check(ares_dns_record_rr_add(&second, owned.rec, ARES_SECTION_ANSWER, "example.com", ARES_REC_TYPE_A, ARES_CLASS_IN, 60) ==
        ARES_SUCCESS);
  in_addr addr{};
  const std::array<unsigned char, 4> bytes{{1, 2, 3, 4}};
  std::memcpy(&addr.s_addr, bytes.data(), sizeof(bytes));
  Check(ares_dns_rr_set_addr(second, ARES_RR_A_ADDR, &addr) == ARES_SUCCESS);

  const auto extracted = cares::ExtractRecord<AView>(cares::DnsRecordRef{owned.rec});
  Check(extracted.has_value());
  if (!extracted) return;
  Check(extracted->ttl == 60);
  Check(extracted->addr.IsV4());
  Check(extracted->addr == cares::IpAddress::FromV4(cares::Ipv4Bytes{1, 2, 3, 4}));

  const auto cname = cares::ExtractRecord<CnameView>(cares::DnsRecordRef{owned.rec});
  Check(cname.has_value());
  if (!cname) return;
  Check(cname->len == 14);
  Check(cname->ttl == 30);
  Check(std::strcmp(cname->cname.data(), "target.example") == 0);
}

void AuthorityAndMiss() {
  OwnedRecord owned;
  Check(Create(owned));
  ares_dns_rr_t *ns = nullptr;
  Check(ares_dns_record_rr_add(&ns, owned.rec, ARES_SECTION_AUTHORITY, "example.com", ARES_REC_TYPE_NS, ARES_CLASS_IN, 100) ==
        ARES_SUCCESS);
  Check(ares_dns_rr_set_str(ns, ARES_RR_NS_NSDNAME, "ns.example") == ARES_SUCCESS);
  const auto extracted = cares::ExtractRecord<NsView>(cares::DnsRecordRef{owned.rec});
  Check(extracted.has_value());
  if (!extracted) return;
  Check(extracted->len == 10);
  Check(extracted->ttl == 100);
  Check(std::strcmp(extracted->nsdname.data(), "ns.example") == 0);

  const auto missing = cares::ExtractRecord<AView>(cares::DnsRecordRef{owned.rec});
  Check(!missing.has_value());
  Check(missing.error() == cares::Error::NotFound());
  const auto invalid = cares::ExtractRecord<AView>(cares::DnsRecordRef{});
  Check(invalid.error() == cares::Error::BadResponse());
}

struct[[= cares::notes::Answer]][[= cares::notes::Type(cares::DnsType::CNAME)]] ShortCname {
  std::array<char, 8> cname[[= cares::notes::Field(ARES_RR_CNAME_CNAME)]];
  std::uint32_t ttl[[= cares::notes::Ttl]];
};

struct[[= cares::notes::Answer]][[= cares::notes::Type(cares::DnsType::TXT)]] TxtBytes {
  std::array<std::uint8_t, 8> data[[= cares::notes::Field(ARES_RR_TXT_DATA)]];
  std::uint32_t ttl[[= cares::notes::Ttl]];
};

struct[[= cares::notes::Answer]][[= cares::notes::Type(cares::DnsType::AAAA)]] AaaaView {
  cares::IpAddress addr[[= cares::notes::Field(ARES_RR_AAAA_ADDR)]];
  std::uint32_t ttl[[= cares::notes::Ttl]];
};

void CnameOverflowRejected() {
  OwnedRecord owned;
  Check(Create(owned));
  ares_dns_rr_t *rr = nullptr;
  Check(ares_dns_record_rr_add(&rr, owned.rec, ARES_SECTION_ANSWER, "example.com", ARES_REC_TYPE_CNAME, ARES_CLASS_IN, 5) ==
        ARES_SUCCESS);
  Check(ares_dns_rr_set_str(rr, ARES_RR_CNAME_CNAME, "example.com") == ARES_SUCCESS);
  const auto extracted = cares::ExtractRecord<ShortCname>(cares::DnsRecordRef{owned.rec});
  Check(!extracted.has_value());
  Check(extracted.error() == cares::Error::BadResponse());
}

void TxtExactCapacity() {
  OwnedRecord owned;
  Check(Create(owned));
  ares_dns_rr_t *rr = nullptr;
  Check(ares_dns_record_rr_add(&rr, owned.rec, ARES_SECTION_ANSWER, "example.com", ARES_REC_TYPE_TXT, ARES_CLASS_IN, 4) ==
        ARES_SUCCESS);
  const std::array<unsigned char, 4> first{{'a', 'b', 'c', 'd'}};
  const std::array<unsigned char, 4> second{{'e', 'f', 'g', 'h'}};
  Check(ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, first.data(), 4) == ARES_SUCCESS);
  Check(ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, second.data(), 4) == ARES_SUCCESS);
  const auto extracted = cares::ExtractRecord<TxtBytes>(cares::DnsRecordRef{owned.rec});
  Check(extracted.has_value());
  if (!extracted) return;
  const std::array<std::uint8_t, 8> expect{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
  Check(extracted->data == expect);
  Check(extracted->ttl == 4);
}

void AaaaAddressExtracted() {
  OwnedRecord owned;
  Check(Create(owned));
  ares_dns_rr_t *rr = nullptr;
  Check(ares_dns_record_rr_add(&rr, owned.rec, ARES_SECTION_ANSWER, "example.com", ARES_REC_TYPE_AAAA, ARES_CLASS_IN, 9) ==
        ARES_SUCCESS);
  ares_in6_addr addr{};
  cares::Ipv6Bytes expect{};
  for (int index = 0; index < 16; ++index) {
    const auto byte = static_cast<unsigned char>(index + 1);
    addr._S6_un._S6_u8[index] = byte;
    expect[static_cast<std::size_t>(index)] = byte;
  }
  Check(ares_dns_rr_set_addr6(rr, ARES_RR_AAAA_ADDR, &addr) == ARES_SUCCESS);
  const auto extracted = cares::ExtractRecord<AaaaView>(cares::DnsRecordRef{owned.rec});
  Check(extracted.has_value());
  if (!extracted) return;
  Check(extracted->addr.IsV6());
  Check(extracted->addr == cares::IpAddress::FromV6(expect));
  Check(extracted->ttl == 9);
}

}  // namespace

int main() {
  ExtractFirstA();
  AuthorityAndMiss();
  CnameOverflowRejected();
  TxtExactCapacity();
  AaaaAddressExtracted();
  if (g_failed != 0) {
    std::fprintf(stderr, "%d checks failed\n", g_failed);
    return 1;
  }
  return 0;
}
