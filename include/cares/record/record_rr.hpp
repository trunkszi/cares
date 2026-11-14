/** @file
 *  @brief Fixed-layout DNS Resource Record (RR) value types, EDNS0 OptRecord, and QuestionItem.
 */
#pragma once

#include <ares.h>
#include <ares_dns_record.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cares/error/ares_error.hpp>
#include <cares/types/dns_types.hpp>
#include <cares/types/host_types.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace cares {

/** @brief IPv4 host address resource record (RFC 1035 TYPE 1). */
struct ARecord {
  static constexpr DnsType kDnsType = DnsType::A;

  IpAddress addr{};
  std::uint32_t ttl{0};

  friend constexpr bool operator==(const ARecord&, const ARecord&) noexcept = default;
};

/** @brief IPv6 host address resource record (RFC 3596 TYPE 28). */
struct AaaaRecord {
  static constexpr DnsType kDnsType = DnsType::AAAA;

  IpAddress addr{IpAddress::FromV6({})};
  std::uint32_t ttl{0};

  friend constexpr bool operator==(const AaaaRecord&, const AaaaRecord&) noexcept = default;
};

/** @brief Canonical name resource record (RFC 1035 TYPE 5). */
struct CnameRecord {
  static constexpr DnsType kDnsType = DnsType::CNAME;

  std::array<char, 256> cname{};
  std::uint16_t len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view View() const noexcept {
    return {cname.data(), std::min<std::size_t>(len, cname.size())};
  }
  [[nodiscard]] constexpr std::string_view Cname() const noexcept { return View(); }
  friend constexpr bool operator==(const CnameRecord&, const CnameRecord&) noexcept = default;
};

/** @brief Mail exchange resource record (RFC 1035 TYPE 15). */
struct MxRecord {
  static constexpr DnsType kDnsType = DnsType::MX;

  std::uint16_t preference{0};
  std::array<char, 256> exchange{};
  std::uint16_t len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view Exchange() const noexcept {
    return {exchange.data(), std::min<std::size_t>(len, exchange.size())};
  }
  [[nodiscard]] constexpr std::string_view View() const noexcept { return Exchange(); }
  friend constexpr bool operator==(const MxRecord&, const MxRecord&) noexcept = default;
};

/** @brief Move-only TXT payload. 256 bytes stay inline; a larger value uses one calloc buffer. */
class TxtBuffer {
 public:
  static constexpr std::size_t kInline = 256;

  constexpr TxtBuffer() noexcept = default;
  TxtBuffer(const TxtBuffer&) = delete ("TXT bytes are move-only");
  TxtBuffer& operator=(const TxtBuffer&) = delete ("TXT bytes are move-only");
  TxtBuffer(TxtBuffer&& other) noexcept : size_(other.size_), heap_(other.heap_) {
    if (heap_ == nullptr) {
      for (std::size_t i = 0; i < size_; ++i) inline_[i] = other.inline_[i];
    }
    other.heap_ = nullptr;
    other.size_ = 0;
  }
  TxtBuffer& operator=(TxtBuffer&& other) noexcept {
    if (this == &other) return *this;
    std::free(heap_);
    heap_ = other.heap_;
    size_ = other.size_;
    if (heap_ == nullptr) {
      for (std::size_t i = 0; i < size_; ++i) inline_[i] = other.inline_[i];
    }
    other.heap_ = nullptr;
    other.size_ = 0;
    return *this;
  }
  constexpr ~TxtBuffer() noexcept {
    if !consteval {
      std::free(heap_);
    }
  }

  [[nodiscard]] static Result<TxtBuffer> Copy(std::string_view text) noexcept {
    TxtBuffer out;
    if (auto stored = out.Assign(text); !stored) return std::unexpected(stored.error());
    return out;
  }
  [[nodiscard]] Result<void> Assign(std::string_view text) noexcept {
    std::free(heap_);
    heap_ = nullptr;
    size_ = 0;
    if (text.size() <= kInline) {
      for (std::size_t i = 0; i < text.size(); ++i) inline_[i] = text[i];
      size_ = text.size();
      return {};
    }
    auto* buf = static_cast<char*>(std::calloc(text.size(), 1));
    if (buf == nullptr) return std::unexpected(Error::CapacityExhausted());
    std::memcpy(buf, text.data(), text.size());
    heap_ = buf;
    size_ = text.size();
    return {};
  }
  [[nodiscard]] Result<void> Append(std::span<const unsigned char> chunk) noexcept {
    if (chunk.empty()) return {};
    const std::size_t next = size_ + chunk.size();
    if (heap_ == nullptr && next <= kInline) {
      for (std::size_t i = 0; i < chunk.size(); ++i) inline_[size_ + i] = static_cast<char>(chunk[i]);
      size_ = next;
      return {};
    }
    auto* buf = static_cast<char*>(std::calloc(next, 1));
    if (buf == nullptr) return std::unexpected(Error::CapacityExhausted());
    if (size_ != 0) std::memcpy(buf, data(), size_);
    std::memcpy(buf + size_, chunk.data(), chunk.size());
    std::free(heap_);
    heap_ = buf;
    size_ = next;
    return {};
  }
  [[nodiscard]] constexpr const char* data() const noexcept { return heap_ != nullptr ? heap_ : inline_.data(); }
  [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
  [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }
  [[nodiscard]] constexpr char front() const noexcept { return data()[0]; }
  [[nodiscard]] constexpr char back() const noexcept { return data()[size_ - 1]; }
  [[nodiscard]] constexpr std::string_view View() const noexcept { return {data(), size()}; }
  [[nodiscard]] constexpr operator std::string_view() const noexcept { return View(); }
  friend constexpr bool operator==(const TxtBuffer& lhs, const TxtBuffer& rhs) noexcept { return lhs.View() == rhs.View(); }

 private:
  std::array<char, kInline> inline_{};
  std::size_t size_{0};
  char* heap_{nullptr};
};

/// Each TXT character-string costs one length byte. 65279 payload octets encode to 65535 wire octets.
[[nodiscard]] constexpr bool TxtRdlengthFits(std::size_t n) noexcept {
  const auto chunks = std::max<std::size_t>(1, (n + 254) / 255);
  return n + chunks <= 65535;
}

/** @brief Text strings resource record (RFC 1035 TYPE 16). */
struct TxtRecord {
  static constexpr DnsType kDnsType = DnsType::TXT;
  static constexpr std::size_t kMaxBytes = 65279;

  TxtBuffer text{};
  std::uint32_t ttl{0};

  [[nodiscard]] std::span<const std::uint8_t> Bytes() const noexcept {
    return {std::bit_cast<const std::uint8_t*>(text.data()), text.size()};
  }
  [[nodiscard]] constexpr std::string_view View() const noexcept { return text.View(); }
  [[nodiscard]] constexpr std::string_view Text() const noexcept { return View(); }
  friend constexpr bool operator==(const TxtRecord&, const TxtRecord&) noexcept = default;
};

[[nodiscard]] inline Result<void> AppendTxtChunk(TxtBuffer& text, const unsigned char* chunk, std::size_t chunk_len) noexcept {
  if ((chunk == nullptr && chunk_len > 0) || text.size() + chunk_len > TxtRecord::kMaxBytes) {
    return std::unexpected(Error::BadResponse());
  }
  if (chunk_len == 0) return {};
  return text.Append(std::span<const unsigned char>{chunk, chunk_len});
}

/** @brief Server selection resource record (RFC 2782 TYPE 33). */
struct SrvRecord {
  static constexpr DnsType kDnsType = DnsType::SRV;

  std::uint16_t priority{0};
  std::uint16_t weight{0};
  std::uint16_t port{0};
  std::array<char, 256> target{};
  std::uint16_t len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view Target() const noexcept {
    return {target.data(), std::min<std::size_t>(len, target.size())};
  }
  [[nodiscard]] constexpr std::string_view View() const noexcept { return Target(); }
  friend constexpr bool operator==(const SrvRecord&, const SrvRecord&) noexcept = default;
};

/** @brief Domain name pointer resource record (RFC 1035 TYPE 12). */
struct PtrRecord {
  static constexpr DnsType kDnsType = DnsType::PTR;

  std::array<char, 256> dname{};
  std::uint16_t len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view View() const noexcept {
    return {dname.data(), std::min<std::size_t>(len, dname.size())};
  }
  [[nodiscard]] constexpr std::string_view Dname() const noexcept { return View(); }
  friend constexpr bool operator==(const PtrRecord&, const PtrRecord&) noexcept = default;
};

/** @brief Start of authority resource record (RFC 1035 TYPE 6). */
struct SoaRecord {
  static constexpr DnsType kDnsType = DnsType::SOA;

  std::array<char, 256> mname{};
  std::uint16_t mname_len{0};
  std::array<char, 256> rname{};
  std::uint16_t rname_len{0};
  std::uint32_t serial{0};
  std::uint32_t refresh{0};
  std::uint32_t retry{0};
  std::uint32_t expire{0};
  std::uint32_t minimum{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view Mname() const noexcept {
    return {mname.data(), std::min<std::size_t>(mname_len, mname.size())};
  }
  [[nodiscard]] constexpr std::string_view Rname() const noexcept {
    return {rname.data(), std::min<std::size_t>(rname_len, rname.size())};
  }
  friend constexpr bool operator==(const SoaRecord&, const SoaRecord&) noexcept = default;
};

/** @brief Authoritative name server resource record (RFC 1035 TYPE 2). */
struct NsRecord {
  static constexpr DnsType kDnsType = DnsType::NS;

  std::array<char, 256> nsdname{};
  std::uint16_t len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view View() const noexcept {
    return {nsdname.data(), std::min<std::size_t>(len, nsdname.size())};
  }
  [[nodiscard]] constexpr std::string_view Nsdname() const noexcept { return View(); }
  friend constexpr bool operator==(const NsRecord&, const NsRecord&) noexcept = default;
};

/** @brief Naming authority pointer resource record (RFC 3403 TYPE 35). */
struct NaptrRecord {
  static constexpr DnsType kDnsType = DnsType::NAPTR;

  std::uint16_t order{0};
  std::uint16_t preference{0};
  std::array<char, 64> flags{};
  std::uint8_t flags_len{0};
  std::array<char, 128> service{};
  std::uint8_t service_len{0};
  std::array<char, 128> regexp{};
  std::uint8_t regexp_len{0};
  std::array<char, 256> replacement{};
  std::uint16_t replacement_len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view Flags() const noexcept {
    return {flags.data(), std::min<std::size_t>(flags_len, flags.size())};
  }
  [[nodiscard]] constexpr std::string_view Service() const noexcept {
    return {service.data(), std::min<std::size_t>(service_len, service.size())};
  }
  [[nodiscard]] constexpr std::string_view Regexp() const noexcept {
    return {regexp.data(), std::min<std::size_t>(regexp_len, regexp.size())};
  }
  [[nodiscard]] constexpr std::string_view Replacement() const noexcept {
    return {replacement.data(), std::min<std::size_t>(replacement_len, replacement.size())};
  }
  friend constexpr bool operator==(const NaptrRecord&, const NaptrRecord&) noexcept = default;
};

/** @brief Certification Authority Authorization resource record (RFC 6844 TYPE 257). */
struct CaaRecord {
  static constexpr DnsType kDnsType = DnsType::CAA;

  std::uint8_t critical{0};
  std::array<char, 64> tag{};
  std::uint8_t tag_len{0};
  std::array<std::uint8_t, 256> value{};
  std::uint16_t value_len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view Tag() const noexcept {
    return {tag.data(), std::min<std::size_t>(tag_len, tag.size())};
  }
  [[nodiscard]] constexpr std::span<const std::uint8_t> ValueBytes() const noexcept {
    return {value.data(), std::min<std::size_t>(value_len, value.size())};
  }
  [[nodiscard]] constexpr std::string_view ValueView() const noexcept {
    return {std::bit_cast<const char*>(value.data()), std::min<std::size_t>(value_len, value.size())};
  }
  friend constexpr bool operator==(const CaaRecord&, const CaaRecord&) noexcept = default;
};

/** @brief Uniform Resource Identifier resource record (RFC 7553 TYPE 256). */
struct UriRecord {
  static constexpr DnsType kDnsType = DnsType::URI;

  std::uint16_t priority{0};
  std::uint16_t weight{0};
  std::array<char, 256> target{};
  std::uint16_t target_len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view Target() const noexcept {
    return {target.data(), std::min<std::size_t>(target_len, target.size())};
  }
  [[nodiscard]] constexpr std::string_view View() const noexcept { return Target(); }
  friend constexpr bool operator==(const UriRecord&, const UriRecord&) noexcept = default;
};

/** @brief DANE TLSA certificate association resource record (RFC 6698 TYPE 52). */
struct TlsaRecord {
  static constexpr DnsType kDnsType = DnsType::TLSA;

  std::uint8_t cert_usage{0};
  std::uint8_t selector{0};
  std::uint8_t match{0};
  std::array<std::uint8_t, 256> data{};
  std::uint16_t data_len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::span<const std::uint8_t> Data() const noexcept {
    return {data.data(), std::min<std::size_t>(data_len, data.size())};
  }
  friend constexpr bool operator==(const TlsaRecord&, const TlsaRecord&) noexcept = default;
};

/** @brief Fixed-header projection of an SVCB record (RFC 9460 TYPE 64).
 *  Only priority and target name are stored. SvcParams remain on the owning `DnsRecord`.
 */
struct SvcbRecord {
  static constexpr DnsType kDnsType = DnsType::SVCB;

  std::uint16_t priority{0};
  std::array<char, 256> target{};
  std::uint16_t target_len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view Target() const noexcept {
    return {target.data(), std::min<std::size_t>(target_len, target.size())};
  }
  [[nodiscard]] constexpr std::string_view View() const noexcept { return Target(); }
  friend constexpr bool operator==(const SvcbRecord&, const SvcbRecord&) noexcept = default;
};

/** @brief Fixed-header projection of an HTTPS record (RFC 9460 TYPE 65).
 *  Only priority and target name are stored. SvcParams remain on the owning `DnsRecord`.
 */
struct HttpsRecord {
  static constexpr DnsType kDnsType = DnsType::HTTPS;

  std::uint16_t priority{0};
  std::array<char, 256> target{};
  std::uint16_t target_len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view Target() const noexcept {
    return {target.data(), std::min<std::size_t>(target_len, target.size())};
  }
  [[nodiscard]] constexpr std::string_view View() const noexcept { return Target(); }
  friend constexpr bool operator==(const HttpsRecord&, const HttpsRecord&) noexcept = default;
};

/** @brief Fixed-header projection of an EDNS0 OPT record (RFC 6891 TYPE 41).
 *  UDP size, version, and flags only. EDNS options remain on the owning `DnsRecord`.
 */
struct OptRecord {
  static constexpr DnsType kDnsType = DnsType::OPT;

  std::uint16_t udp_size{4096};
  std::uint8_t version{0};
  std::uint16_t flags{0};
  std::uint32_t ttl{0};

  friend constexpr bool operator==(const OptRecord&, const OptRecord&) noexcept = default;
};

/** @brief Host information resource record (RFC 1035 TYPE 13). */
struct HinfoRecord {
  static constexpr DnsType kDnsType = DnsType::HINFO;

  std::array<char, 128> cpu{};
  std::uint8_t cpu_len{0};
  std::array<char, 128> os{};
  std::uint8_t os_len{0};
  std::uint32_t ttl{0};

  [[nodiscard]] constexpr std::string_view Cpu() const noexcept {
    return {cpu.data(), std::min<std::size_t>(cpu_len, cpu.size())};
  }
  [[nodiscard]] constexpr std::string_view Os() const noexcept { return {os.data(), std::min<std::size_t>(os_len, os.size())}; }
  friend constexpr bool operator==(const HinfoRecord&, const HinfoRecord&) noexcept = default;
};

/** @brief DNS Question section entry (RFC 1035 Section 4.1.2). */
struct QuestionItem {
  std::array<char, 256> name{};
  std::uint16_t name_len{0};
  DnsType qtype{DnsType::A};
  DnsClass qclass{DnsClass::IN};

  [[nodiscard]] constexpr std::string_view Name() const noexcept {
    return {name.data(), std::min<std::size_t>(name_len, name.size())};
  }
  friend constexpr bool operator==(const QuestionItem&, const QuestionItem&) noexcept = default;
};

/** @brief Closed variant over all supported typed DNS resource records. */
using RecordVariant =
    std::variant<ARecord, AaaaRecord, CnameRecord, MxRecord, TxtRecord, SrvRecord, PtrRecord, SoaRecord, NsRecord, NaptrRecord,
                 CaaRecord, UriRecord, TlsaRecord, SvcbRecord, HttpsRecord, OptRecord, HinfoRecord>;

/** @brief Complete DNS Resource Record item combining owner metadata and typed payload. */
struct RecordItem {
  std::array<char, 256> name{};
  std::uint16_t name_len{0};
  RecordSection section{RecordSection::Answer};
  DnsType rtype{DnsType::A};
  DnsClass rclass{DnsClass::IN};
  std::uint32_t ttl{0};
  RecordVariant data{};

  [[nodiscard]] constexpr std::string_view Name() const noexcept {
    return {name.data(), std::min<std::size_t>(name_len, name.size())};
  }
  friend constexpr bool operator==(const RecordItem&, const RecordItem&) noexcept = default;
};

/** @brief Concept satisfied by fixed-layout typed DNS resource record structs. */
template <typename T>
concept DnsRecordStruct =
    std::is_same_v<std::remove_cvref_t<T>, ARecord> || std::is_same_v<std::remove_cvref_t<T>, AaaaRecord> ||
    std::is_same_v<std::remove_cvref_t<T>, CnameRecord> || std::is_same_v<std::remove_cvref_t<T>, MxRecord> ||
    std::is_same_v<std::remove_cvref_t<T>, TxtRecord> || std::is_same_v<std::remove_cvref_t<T>, SrvRecord> ||
    std::is_same_v<std::remove_cvref_t<T>, PtrRecord> || std::is_same_v<std::remove_cvref_t<T>, SoaRecord> ||
    std::is_same_v<std::remove_cvref_t<T>, NsRecord> || std::is_same_v<std::remove_cvref_t<T>, NaptrRecord> ||
    std::is_same_v<std::remove_cvref_t<T>, CaaRecord> || std::is_same_v<std::remove_cvref_t<T>, UriRecord> ||
    std::is_same_v<std::remove_cvref_t<T>, TlsaRecord> || std::is_same_v<std::remove_cvref_t<T>, SvcbRecord> ||
    std::is_same_v<std::remove_cvref_t<T>, HttpsRecord> || std::is_same_v<std::remove_cvref_t<T>, OptRecord> ||
    std::is_same_v<std::remove_cvref_t<T>, HinfoRecord>;

/** @brief Returns the owning DnsType encoded in a c-ares RR key (`key / 100`). */
[[nodiscard]] consteval DnsType RrKeyRecordType(ares_dns_rr_key_t key) noexcept {
  return static_cast<DnsType>(std::to_underlying(key) / 100u);
}

/** @brief Compile-time check whether `key` is a known valid c-ares RR key for `type`. */
[[nodiscard]] consteval bool IsValidRrKeyForType(DnsType type, ares_dns_rr_key_t key) noexcept {
  switch (type) {
    case DnsType::A:
      return key == ARES_RR_A_ADDR;
    case DnsType::NS:
      return key == ARES_RR_NS_NSDNAME;
    case DnsType::CNAME:
      return key == ARES_RR_CNAME_CNAME;
    case DnsType::SOA:
      return key == ARES_RR_SOA_MNAME || key == ARES_RR_SOA_RNAME || key == ARES_RR_SOA_SERIAL || key == ARES_RR_SOA_REFRESH ||
             key == ARES_RR_SOA_RETRY || key == ARES_RR_SOA_EXPIRE || key == ARES_RR_SOA_MINIMUM;
    case DnsType::PTR:
      return key == ARES_RR_PTR_DNAME;
    case DnsType::HINFO:
      return key == ARES_RR_HINFO_CPU || key == ARES_RR_HINFO_OS;
    case DnsType::MX:
      return key == ARES_RR_MX_PREFERENCE || key == ARES_RR_MX_EXCHANGE;
    case DnsType::TXT:
      return key == ARES_RR_TXT_DATA;
    case DnsType::AAAA:
      return key == ARES_RR_AAAA_ADDR;
    case DnsType::SRV:
      return key == ARES_RR_SRV_PRIORITY || key == ARES_RR_SRV_WEIGHT || key == ARES_RR_SRV_PORT || key == ARES_RR_SRV_TARGET;
    case DnsType::NAPTR:
      return key == ARES_RR_NAPTR_ORDER || key == ARES_RR_NAPTR_PREFERENCE || key == ARES_RR_NAPTR_FLAGS ||
             key == ARES_RR_NAPTR_SERVICES || key == ARES_RR_NAPTR_REGEXP || key == ARES_RR_NAPTR_REPLACEMENT;
    case DnsType::OPT:
      return key == ARES_RR_OPT_UDP_SIZE || key == ARES_RR_OPT_VERSION || key == ARES_RR_OPT_FLAGS ||
             key == ARES_RR_OPT_OPTIONS;
    case DnsType::TLSA:
      return key == ARES_RR_TLSA_CERT_USAGE || key == ARES_RR_TLSA_SELECTOR || key == ARES_RR_TLSA_MATCH ||
             key == ARES_RR_TLSA_DATA;
    case DnsType::SVCB:
      return key == ARES_RR_SVCB_PRIORITY || key == ARES_RR_SVCB_TARGET || key == ARES_RR_SVCB_PARAMS;
    case DnsType::HTTPS:
      return key == ARES_RR_HTTPS_PRIORITY || key == ARES_RR_HTTPS_TARGET || key == ARES_RR_HTTPS_PARAMS;
    case DnsType::URI:
      return key == ARES_RR_URI_PRIORITY || key == ARES_RR_URI_WEIGHT || key == ARES_RR_URI_TARGET;
    case DnsType::CAA:
      return key == ARES_RR_CAA_CRITICAL || key == ARES_RR_CAA_TAG || key == ARES_RR_CAA_VALUE;
    case DnsType::ANY:
      return false;
  }
  return false;
}

/** @brief Compile-time check whether `key` is a valid c-ares RR key for any supported DnsType. */
[[nodiscard]] consteval bool IsValidRrKey(ares_dns_rr_key_t key) noexcept {
  return IsValidRrKeyForType(RrKeyRecordType(key), key);
}

/** @brief Enforces at compile time that `Key` belongs to `Type`. */
template <DnsType Type, ares_dns_rr_key_t Key>
consteval void RequireValidRrKey() noexcept {
  static_assert(IsValidRrKeyForType(Type, Key), "Invalid ares_dns_rr_key_t for the specified DnsType");
}

/** @brief Enforces at compile time that `Key` belongs to `RrT::kDnsType`. */
template <DnsRecordStruct RrT, ares_dns_rr_key_t Key>
consteval void RequireValidRecordKey() noexcept {
  static_assert(IsValidRrKeyForType(RrT::kDnsType, Key), "Invalid ares_dns_rr_key_t for the specified DnsType");
}

static_assert(std::is_trivially_copyable_v<ARecord> && std::is_standard_layout_v<ARecord>);
static_assert(std::is_trivially_copyable_v<AaaaRecord> && std::is_standard_layout_v<AaaaRecord>);
static_assert(std::is_trivially_copyable_v<CnameRecord> && std::is_standard_layout_v<CnameRecord>);
static_assert(std::is_trivially_copyable_v<MxRecord> && std::is_standard_layout_v<MxRecord>);
static_assert(std::is_trivially_copyable_v<SrvRecord> && std::is_standard_layout_v<SrvRecord>);
static_assert(std::is_trivially_copyable_v<PtrRecord> && std::is_standard_layout_v<PtrRecord>);
static_assert(std::is_trivially_copyable_v<SoaRecord> && std::is_standard_layout_v<SoaRecord>);
static_assert(std::is_trivially_copyable_v<NsRecord> && std::is_standard_layout_v<NsRecord>);
static_assert(std::is_trivially_copyable_v<NaptrRecord> && std::is_standard_layout_v<NaptrRecord>);
static_assert(std::is_trivially_copyable_v<CaaRecord> && std::is_standard_layout_v<CaaRecord>);
static_assert(std::is_trivially_copyable_v<UriRecord> && std::is_standard_layout_v<UriRecord>);
static_assert(std::is_trivially_copyable_v<TlsaRecord> && std::is_standard_layout_v<TlsaRecord>);
static_assert(std::is_trivially_copyable_v<SvcbRecord> && std::is_standard_layout_v<SvcbRecord>);
static_assert(std::is_trivially_copyable_v<HttpsRecord> && std::is_standard_layout_v<HttpsRecord>);
static_assert(std::is_trivially_copyable_v<OptRecord> && std::is_standard_layout_v<OptRecord>);
static_assert(std::is_trivially_copyable_v<HinfoRecord> && std::is_standard_layout_v<HinfoRecord>);
static_assert(std::is_trivially_copyable_v<QuestionItem> && std::is_standard_layout_v<QuestionItem>);

}  // namespace cares
