/** @file
 *  @brief Internal implementation helpers for DnsRecordRef and DnsRecord.
 */
#pragma once

#include <ares.h>
#include <ares_dns_record.h>
#include <netinet/in.h>

#include <array>
#include <bit>
#include <cares/error/ares_error.hpp>
#include <cares/record/record_rr.hpp>
#include <cares/types/dns_types.hpp>
#include <cares/types/host_types.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <uarch/uarch.hpp>
#include <utility>

namespace cares::detail {

[[gnu::cold, gnu::noinline]] inline Error MakeAresErrorSlow(std::underlying_type_t<ares_status_t> status) noexcept {
  const auto code = static_cast<int>(status);
  return code == ARES_SUCCESS ? Error::BadResponse() : Error::FromAres(code);
}

[[gnu::cold, gnu::noinline]] inline Error MakeInvalidArgErrorSlow() noexcept { return Error::InvalidArgument(); }
[[gnu::cold, gnu::noinline]] inline Error MakeBadNameErrorSlow() noexcept { return Error::BadName(); }
[[gnu::cold, gnu::noinline]] inline Error MakeBadResponseErrorSlow() noexcept { return Error::BadResponse(); }
[[gnu::cold, gnu::noinline]] inline Error MakeCapacityErrorSlow() noexcept { return Error::CapacityExhausted(); }

template <std::size_t N, typename LenT>
struct BoundedCopy {
  std::array<char, N> bytes{};
  LenT len{0};
};

template <std::size_t N>
[[nodiscard]] inline std::optional<BoundedCopy<N, std::uint16_t>> CopyCStringBounded(const char* src) noexcept {
  if (uarch::flow::unlikely(src == nullptr)) return std::nullopt;
  const std::size_t len = std::strlen(src);
  if (uarch::flow::unlikely(len >= N || len > 0xFFFFu)) return std::nullopt;
  BoundedCopy<N, std::uint16_t> out{};
  if (len > 0) std::memcpy(out.bytes.data(), src, len);
  out.bytes[len] = '\0';
  out.len = static_cast<std::uint16_t>(len);
  return out;
}

template <std::size_t N>
[[nodiscard]] inline std::optional<BoundedCopy<N, std::uint8_t>> CopyCStringBoundedU8(const char* src) noexcept {
  if (uarch::flow::unlikely(src == nullptr)) return std::nullopt;
  const std::size_t len = std::strlen(src);
  if (uarch::flow::unlikely(len >= N || len > 255u)) return std::nullopt;
  BoundedCopy<N, std::uint8_t> out{};
  if (len > 0) std::memcpy(out.bytes.data(), src, len);
  out.bytes[len] = '\0';
  out.len = static_cast<std::uint8_t>(len);
  return out;
}

// RFC 1035: one encoded QNAME is at most 255 octets and each label is at most 63.
[[nodiscard]] constexpr bool DnsNameFitsWire(std::string_view name) noexcept {
  if (name.contains('\0')) return false;
  if (name.empty() || name == ".") return true;
  if (name.back() == '.') name.remove_suffix(1);
  if (name.empty()) return false;
  std::size_t cursor = 0;
  std::size_t begin = 0;
  const auto flush = [&](std::size_t end) noexcept {
    const std::size_t label = end - begin;
    if (label == 0 || label > 63 || cursor + label + 2 > 255) return false;
    cursor += label + 1;
    return true;
  };
  for (std::size_t index = 0; index < name.size(); ++index) {
    if (name[index] != '.') continue;
    if (!flush(index)) return false;
    begin = index + 1;
  }
  return flush(name.size()) && cursor + 1 <= 255;
}

[[nodiscard]] inline std::optional<Error> RejectDnsName(std::string_view name) noexcept {
  if (name.size() >= 256 || !DnsNameFitsWire(name)) return MakeBadNameErrorSlow();
  return std::nullopt;
}

template <std::size_t N>
[[nodiscard]] constexpr std::optional<std::array<char, N>> ToNullTerminatedName(std::string_view sv) noexcept {
  if (uarch::flow::unlikely(sv.size() >= N || sv.contains('\0'))) {
    return std::nullopt;
  }
  std::array<char, N> buf{};
  for (std::size_t i = 0; i < sv.size(); ++i) {
    buf[i] = sv[i];
  }
  buf[sv.size()] = '\0';
  return buf;
}

template <DnsRecordStruct RrT>
[[nodiscard]] constexpr bool ValidateRecordInput(const RrT& rec) noexcept {
  if constexpr (std::is_same_v<RrT, ARecord>) {
    return rec.addr.IsV4();
  } else if constexpr (std::is_same_v<RrT, AaaaRecord>) {
    return rec.addr.IsV6();
  } else if constexpr (std::is_same_v<RrT, CnameRecord>) {
    return rec.len < rec.cname.size() && DnsNameFitsWire(rec.View());
  } else if constexpr (std::is_same_v<RrT, MxRecord>) {
    return rec.len < rec.exchange.size() && DnsNameFitsWire(rec.Exchange());
  } else if constexpr (std::is_same_v<RrT, TxtRecord>) {
    return TxtRdlengthFits(rec.text.size());
  } else if constexpr (std::is_same_v<RrT, SrvRecord>) {
    return rec.len < rec.target.size() && DnsNameFitsWire(rec.Target());
  } else if constexpr (std::is_same_v<RrT, PtrRecord>) {
    return rec.len < rec.dname.size() && DnsNameFitsWire(rec.View());
  } else if constexpr (std::is_same_v<RrT, SoaRecord>) {
    return rec.mname_len < rec.mname.size() && rec.rname_len < rec.rname.size() && DnsNameFitsWire(rec.Mname()) &&
           DnsNameFitsWire(rec.Rname());
  } else if constexpr (std::is_same_v<RrT, NsRecord>) {
    return rec.len < rec.nsdname.size() && DnsNameFitsWire(rec.View());
  } else if constexpr (std::is_same_v<RrT, NaptrRecord>) {
    return rec.flags_len < rec.flags.size() && rec.service_len < rec.service.size() && rec.regexp_len < rec.regexp.size() &&
           rec.replacement_len < rec.replacement.size() && !rec.Flags().contains('\0') && !rec.Service().contains('\0') &&
           !rec.Regexp().contains('\0') && DnsNameFitsWire(rec.Replacement());
  } else if constexpr (std::is_same_v<RrT, CaaRecord>) {
    return rec.tag_len > 0 && rec.tag_len < rec.tag.size() && rec.value_len <= rec.value.size() && !rec.Tag().contains('\0');
  } else if constexpr (std::is_same_v<RrT, UriRecord>) {
    return rec.target_len < rec.target.size() && !rec.Target().contains('\0');
  } else if constexpr (std::is_same_v<RrT, TlsaRecord>) {
    return rec.data_len <= rec.data.size();
  } else if constexpr (std::is_same_v<RrT, SvcbRecord> || std::is_same_v<RrT, HttpsRecord>) {
    return rec.target_len < rec.target.size() && DnsNameFitsWire(rec.Target());
  } else if constexpr (std::is_same_v<RrT, OptRecord>) {
    return true;
  } else if constexpr (std::is_same_v<RrT, HinfoRecord>) {
    return rec.cpu_len < rec.cpu.size() && rec.os_len < rec.os.size() && !rec.Cpu().contains('\0') && !rec.Os().contains('\0');
  } else {
    static_assert(sizeof(RrT) == 0, "Unsupported DnsRecordStruct type");
    return false;
  }
}

template <DnsRecordStruct RrT>
[[nodiscard]] inline ares_status_t PopulateTypedRr(ares_dns_rr_t* __restrict rr, const RrT& rec) noexcept {
  ares_status_t st = ARES_SUCCESS;
  if constexpr (std::is_same_v<RrT, ARecord>) {
    struct in_addr addr4{};
    std::memcpy(&addr4.s_addr, rec.addr.v4.data(), rec.addr.v4.size());
    st = ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr4);
  } else if constexpr (std::is_same_v<RrT, AaaaRecord>) {
    struct ares_in6_addr addr6{};
    std::memcpy(&addr6, rec.addr.v6.data(), rec.addr.v6.size());
    st = ares_dns_rr_set_addr6(rr, ARES_RR_AAAA_ADDR, &addr6);
  } else if constexpr (std::is_same_v<RrT, CnameRecord>) {
    const auto buf = ToNullTerminatedName<256>(rec.View());
    st = ares_dns_rr_set_str(rr, ARES_RR_CNAME_CNAME, buf->data());
  } else if constexpr (std::is_same_v<RrT, MxRecord>) {
    const auto buf = ToNullTerminatedName<256>(rec.Exchange());
    st = ares_dns_rr_set_u16(rr, ARES_RR_MX_PREFERENCE, rec.preference);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_MX_EXCHANGE, buf->data());
  } else if constexpr (std::is_same_v<RrT, TxtRecord>) {
    const auto* data = std::bit_cast<const unsigned char*>(rec.text.data());
    std::size_t offset = 0;
    // One character-string is at most 255 octets. An empty TXT is a single empty string.
    do {
      const std::size_t chunk = (rec.text.size() - offset) > 255 ? 255 : (rec.text.size() - offset);
      st = ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, data + offset, chunk);
      offset += chunk;
    } while (st == ARES_SUCCESS && offset < rec.text.size());
  } else if constexpr (std::is_same_v<RrT, SrvRecord>) {
    const auto buf = ToNullTerminatedName<256>(rec.Target());
    st = ares_dns_rr_set_u16(rr, ARES_RR_SRV_PRIORITY, rec.priority);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u16(rr, ARES_RR_SRV_WEIGHT, rec.weight);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u16(rr, ARES_RR_SRV_PORT, rec.port);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_SRV_TARGET, buf->data());
  } else if constexpr (std::is_same_v<RrT, PtrRecord>) {
    const auto buf = ToNullTerminatedName<256>(rec.View());
    st = ares_dns_rr_set_str(rr, ARES_RR_PTR_DNAME, buf->data());
  } else if constexpr (std::is_same_v<RrT, SoaRecord>) {
    const auto mbuf = ToNullTerminatedName<256>(rec.Mname());
    const auto rbuf = ToNullTerminatedName<256>(rec.Rname());
    st = ares_dns_rr_set_str(rr, ARES_RR_SOA_MNAME, mbuf->data());
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_SOA_RNAME, rbuf->data());
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u32(rr, ARES_RR_SOA_SERIAL, rec.serial);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u32(rr, ARES_RR_SOA_REFRESH, rec.refresh);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u32(rr, ARES_RR_SOA_RETRY, rec.retry);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u32(rr, ARES_RR_SOA_EXPIRE, rec.expire);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u32(rr, ARES_RR_SOA_MINIMUM, rec.minimum);
  } else if constexpr (std::is_same_v<RrT, NsRecord>) {
    const auto buf = ToNullTerminatedName<256>(rec.View());
    st = ares_dns_rr_set_str(rr, ARES_RR_NS_NSDNAME, buf->data());
  } else if constexpr (std::is_same_v<RrT, NaptrRecord>) {
    const auto fbuf = ToNullTerminatedName<64>(rec.Flags());
    const auto sbuf = ToNullTerminatedName<128>(rec.Service());
    const auto rxbuf = ToNullTerminatedName<128>(rec.Regexp());
    const auto repbuf = ToNullTerminatedName<256>(rec.Replacement());
    st = ares_dns_rr_set_u16(rr, ARES_RR_NAPTR_ORDER, rec.order);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u16(rr, ARES_RR_NAPTR_PREFERENCE, rec.preference);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_NAPTR_FLAGS, fbuf->data());
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_NAPTR_SERVICES, sbuf->data());
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_NAPTR_REGEXP, rxbuf->data());
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_NAPTR_REPLACEMENT, repbuf->data());
  } else if constexpr (std::is_same_v<RrT, CaaRecord>) {
    const auto tbuf = ToNullTerminatedName<64>(rec.Tag());
    st = ares_dns_rr_set_u8(rr, ARES_RR_CAA_CRITICAL, rec.critical);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_CAA_TAG, tbuf->data());
    if (st == ARES_SUCCESS) {
      st = ares_dns_rr_set_bin(rr, ARES_RR_CAA_VALUE, rec.value.data(), rec.value_len);
    }
  } else if constexpr (std::is_same_v<RrT, UriRecord>) {
    const auto buf = ToNullTerminatedName<256>(rec.Target());
    st = ares_dns_rr_set_u16(rr, ARES_RR_URI_PRIORITY, rec.priority);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u16(rr, ARES_RR_URI_WEIGHT, rec.weight);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_URI_TARGET, buf->data());
  } else if constexpr (std::is_same_v<RrT, TlsaRecord>) {
    st = ares_dns_rr_set_u8(rr, ARES_RR_TLSA_CERT_USAGE, rec.cert_usage);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u8(rr, ARES_RR_TLSA_SELECTOR, rec.selector);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u8(rr, ARES_RR_TLSA_MATCH, rec.match);
    if (st == ARES_SUCCESS) {
      st = ares_dns_rr_set_bin(rr, ARES_RR_TLSA_DATA, rec.data.data(), rec.data_len);
    }
  } else if constexpr (std::is_same_v<RrT, SvcbRecord>) {
    const auto buf = ToNullTerminatedName<256>(rec.Target());
    st = ares_dns_rr_set_u16(rr, ARES_RR_SVCB_PRIORITY, rec.priority);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_SVCB_TARGET, buf->data());
  } else if constexpr (std::is_same_v<RrT, HttpsRecord>) {
    const auto buf = ToNullTerminatedName<256>(rec.Target());
    st = ares_dns_rr_set_u16(rr, ARES_RR_HTTPS_PRIORITY, rec.priority);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_HTTPS_TARGET, buf->data());
  } else if constexpr (std::is_same_v<RrT, OptRecord>) {
    st = ares_dns_rr_set_u16(rr, ARES_RR_OPT_UDP_SIZE, rec.udp_size);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u8(rr, ARES_RR_OPT_VERSION, rec.version);
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_u16(rr, ARES_RR_OPT_FLAGS, rec.flags);
  } else if constexpr (std::is_same_v<RrT, HinfoRecord>) {
    const auto cbuf = ToNullTerminatedName<128>(rec.Cpu());
    const auto obuf = ToNullTerminatedName<128>(rec.Os());
    st = ares_dns_rr_set_str(rr, ARES_RR_HINFO_CPU, cbuf->data());
    if (st == ARES_SUCCESS) st = ares_dns_rr_set_str(rr, ARES_RR_HINFO_OS, obuf->data());
  }
  return st;
}

template <DnsRecordStruct RrT>
[[nodiscard]] inline Result<ares_dns_rr_t*> PopulateAndFinalizeRr(ares_dns_record_t* __restrict rec, RecordSection section,
                                                                  std::size_t new_idx, ares_dns_rr_t* __restrict rr,
                                                                  const RrT& typed_rr) noexcept {
  const ares_status_t st = PopulateTypedRr<RrT>(rr, typed_rr);
  if (uarch::flow::unlikely(st != ARES_SUCCESS)) {
    [[maybe_unused]] const auto deleted =
        ares_dns_record_rr_del(rec, static_cast<ares_dns_section_t>(std::to_underlying(section)), new_idx);
    return std::unexpected(MakeAresErrorSlow(std::to_underlying(st)));
  }
  return rr;
}

template <DnsRecordStruct RrT>
[[nodiscard]] inline Result<RrT> ExtractTypedRr(const ares_dns_rr_t* __restrict rr) noexcept {
  if (uarch::flow::unlikely(rr == nullptr)) {
    return std::unexpected(MakeBadResponseErrorSlow());
  }
  const auto actual_type = static_cast<DnsType>(ares_dns_rr_get_type(rr));
  if (uarch::flow::unlikely(actual_type != RrT::kDnsType)) {
    return std::unexpected(MakeBadResponseErrorSlow());
  }
  const auto ttl = static_cast<std::uint32_t>(ares_dns_rr_get_ttl(rr));

  if constexpr (std::is_same_v<RrT, ARecord>) {
    RequireValidRecordKey<ARecord, ARES_RR_A_ADDR>();
    const struct in_addr* addr = ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR);
    if (uarch::flow::unlikely(addr == nullptr)) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    Ipv4Bytes bytes{};
    std::memcpy(bytes.data(), &addr->s_addr, bytes.size());
    return ARecord{.addr = IpAddress::FromV4(bytes), .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, AaaaRecord>) {
    RequireValidRecordKey<AaaaRecord, ARES_RR_AAAA_ADDR>();
    const struct ares_in6_addr* addr6 = ares_dns_rr_get_addr6(rr, ARES_RR_AAAA_ADDR);
    if (uarch::flow::unlikely(addr6 == nullptr)) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    Ipv6Bytes bytes{};
    std::memcpy(bytes.data(), addr6, bytes.size());
    return AaaaRecord{.addr = IpAddress::FromV6(bytes), .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, CnameRecord>) {
    RequireValidRecordKey<CnameRecord, ARES_RR_CNAME_CNAME>();
    const auto copied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_CNAME_CNAME));
    if (uarch::flow::unlikely(!copied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return CnameRecord{.cname = copied->bytes, .len = copied->len, .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, MxRecord>) {
    RequireValidRecordKey<MxRecord, ARES_RR_MX_PREFERENCE>();
    RequireValidRecordKey<MxRecord, ARES_RR_MX_EXCHANGE>();
    const auto copied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_MX_EXCHANGE));
    if (uarch::flow::unlikely(!copied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return MxRecord{.preference = ares_dns_rr_get_u16(rr, ARES_RR_MX_PREFERENCE),
                    .exchange = copied->bytes,
                    .len = copied->len,
                    .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, TxtRecord>) {
    RequireValidRecordKey<TxtRecord, ARES_RR_TXT_DATA>();
    TxtRecord out{.ttl = ttl};
    const std::size_t abin_cnt = ares_dns_rr_get_abin_cnt(rr, ARES_RR_TXT_DATA);
    if (abin_cnt > 0) {
      for (std::size_t i = 0; i < abin_cnt; ++i) {
        std::size_t chunk_len = 0;
        const unsigned char* chunk = ares_dns_rr_get_abin(rr, ARES_RR_TXT_DATA, i, &chunk_len);
        if (auto step = AppendTxtChunk(out.text, chunk, chunk_len); uarch::flow::unlikely(!step)) {
          return std::unexpected(step.error());
        }
      }
      return out;
    }
    std::size_t bin_len = 0;
    const unsigned char* bin_ptr = ares_dns_rr_get_bin(rr, ARES_RR_TXT_DATA, &bin_len);
    if (bin_ptr != nullptr) {
      if (auto step = AppendTxtChunk(out.text, bin_ptr, bin_len); uarch::flow::unlikely(!step)) {
        return std::unexpected(step.error());
      }
    }
    return out;
  } else if constexpr (std::is_same_v<RrT, SrvRecord>) {
    RequireValidRecordKey<SrvRecord, ARES_RR_SRV_PRIORITY>();
    RequireValidRecordKey<SrvRecord, ARES_RR_SRV_WEIGHT>();
    RequireValidRecordKey<SrvRecord, ARES_RR_SRV_PORT>();
    RequireValidRecordKey<SrvRecord, ARES_RR_SRV_TARGET>();
    const auto copied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_SRV_TARGET));
    if (uarch::flow::unlikely(!copied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return SrvRecord{.priority = ares_dns_rr_get_u16(rr, ARES_RR_SRV_PRIORITY),
                     .weight = ares_dns_rr_get_u16(rr, ARES_RR_SRV_WEIGHT),
                     .port = ares_dns_rr_get_u16(rr, ARES_RR_SRV_PORT),
                     .target = copied->bytes,
                     .len = copied->len,
                     .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, PtrRecord>) {
    RequireValidRecordKey<PtrRecord, ARES_RR_PTR_DNAME>();
    const auto copied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_PTR_DNAME));
    if (uarch::flow::unlikely(!copied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return PtrRecord{.dname = copied->bytes, .len = copied->len, .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, SoaRecord>) {
    RequireValidRecordKey<SoaRecord, ARES_RR_SOA_MNAME>();
    RequireValidRecordKey<SoaRecord, ARES_RR_SOA_RNAME>();
    RequireValidRecordKey<SoaRecord, ARES_RR_SOA_SERIAL>();
    RequireValidRecordKey<SoaRecord, ARES_RR_SOA_REFRESH>();
    RequireValidRecordKey<SoaRecord, ARES_RR_SOA_RETRY>();
    RequireValidRecordKey<SoaRecord, ARES_RR_SOA_EXPIRE>();
    RequireValidRecordKey<SoaRecord, ARES_RR_SOA_MINIMUM>();
    const auto mcopied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_SOA_MNAME));
    const auto rcopied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_SOA_RNAME));
    if (uarch::flow::unlikely(!mcopied.has_value() || !rcopied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return SoaRecord{.mname = mcopied->bytes,
                     .mname_len = mcopied->len,
                     .rname = rcopied->bytes,
                     .rname_len = rcopied->len,
                     .serial = ares_dns_rr_get_u32(rr, ARES_RR_SOA_SERIAL),
                     .refresh = ares_dns_rr_get_u32(rr, ARES_RR_SOA_REFRESH),
                     .retry = ares_dns_rr_get_u32(rr, ARES_RR_SOA_RETRY),
                     .expire = ares_dns_rr_get_u32(rr, ARES_RR_SOA_EXPIRE),
                     .minimum = ares_dns_rr_get_u32(rr, ARES_RR_SOA_MINIMUM),
                     .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, NsRecord>) {
    RequireValidRecordKey<NsRecord, ARES_RR_NS_NSDNAME>();
    const auto copied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_NS_NSDNAME));
    if (uarch::flow::unlikely(!copied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return NsRecord{.nsdname = copied->bytes, .len = copied->len, .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, NaptrRecord>) {
    RequireValidRecordKey<NaptrRecord, ARES_RR_NAPTR_ORDER>();
    RequireValidRecordKey<NaptrRecord, ARES_RR_NAPTR_PREFERENCE>();
    RequireValidRecordKey<NaptrRecord, ARES_RR_NAPTR_FLAGS>();
    RequireValidRecordKey<NaptrRecord, ARES_RR_NAPTR_SERVICES>();
    RequireValidRecordKey<NaptrRecord, ARES_RR_NAPTR_REGEXP>();
    RequireValidRecordKey<NaptrRecord, ARES_RR_NAPTR_REPLACEMENT>();
    const auto fcopied = CopyCStringBoundedU8<64>(ares_dns_rr_get_str(rr, ARES_RR_NAPTR_FLAGS));
    const auto scopied = CopyCStringBoundedU8<128>(ares_dns_rr_get_str(rr, ARES_RR_NAPTR_SERVICES));
    const auto rcopied = CopyCStringBoundedU8<128>(ares_dns_rr_get_str(rr, ARES_RR_NAPTR_REGEXP));
    const auto pcopied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_NAPTR_REPLACEMENT));
    if (uarch::flow::unlikely(!fcopied.has_value() || !scopied.has_value() || !rcopied.has_value() || !pcopied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return NaptrRecord{.order = ares_dns_rr_get_u16(rr, ARES_RR_NAPTR_ORDER),
                       .preference = ares_dns_rr_get_u16(rr, ARES_RR_NAPTR_PREFERENCE),
                       .flags = fcopied->bytes,
                       .flags_len = fcopied->len,
                       .service = scopied->bytes,
                       .service_len = scopied->len,
                       .regexp = rcopied->bytes,
                       .regexp_len = rcopied->len,
                       .replacement = pcopied->bytes,
                       .replacement_len = pcopied->len,
                       .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, CaaRecord>) {
    RequireValidRecordKey<CaaRecord, ARES_RR_CAA_CRITICAL>();
    RequireValidRecordKey<CaaRecord, ARES_RR_CAA_TAG>();
    RequireValidRecordKey<CaaRecord, ARES_RR_CAA_VALUE>();
    const auto tcopied = CopyCStringBoundedU8<64>(ares_dns_rr_get_str(rr, ARES_RR_CAA_TAG));
    if (uarch::flow::unlikely(!tcopied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    CaaRecord out{
        .critical = ares_dns_rr_get_u8(rr, ARES_RR_CAA_CRITICAL), .tag = tcopied->bytes, .tag_len = tcopied->len, .ttl = ttl};
    std::size_t val_len = 0;
    const unsigned char* val_ptr = ares_dns_rr_get_bin(rr, ARES_RR_CAA_VALUE, &val_len);
    if (uarch::flow::unlikely((val_ptr == nullptr && val_len > 0) || val_len > out.value.size())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    if (val_ptr != nullptr && val_len > 0) {
      std::memcpy(out.value.data(), val_ptr, val_len);
    }
    out.value_len = static_cast<std::uint16_t>(val_len);
    return out;
  } else if constexpr (std::is_same_v<RrT, UriRecord>) {
    RequireValidRecordKey<UriRecord, ARES_RR_URI_PRIORITY>();
    RequireValidRecordKey<UriRecord, ARES_RR_URI_WEIGHT>();
    RequireValidRecordKey<UriRecord, ARES_RR_URI_TARGET>();
    const auto copied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_URI_TARGET));
    if (uarch::flow::unlikely(!copied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return UriRecord{.priority = ares_dns_rr_get_u16(rr, ARES_RR_URI_PRIORITY),
                     .weight = ares_dns_rr_get_u16(rr, ARES_RR_URI_WEIGHT),
                     .target = copied->bytes,
                     .target_len = copied->len,
                     .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, TlsaRecord>) {
    RequireValidRecordKey<TlsaRecord, ARES_RR_TLSA_CERT_USAGE>();
    RequireValidRecordKey<TlsaRecord, ARES_RR_TLSA_SELECTOR>();
    RequireValidRecordKey<TlsaRecord, ARES_RR_TLSA_MATCH>();
    RequireValidRecordKey<TlsaRecord, ARES_RR_TLSA_DATA>();
    TlsaRecord out{.cert_usage = ares_dns_rr_get_u8(rr, ARES_RR_TLSA_CERT_USAGE),
                   .selector = ares_dns_rr_get_u8(rr, ARES_RR_TLSA_SELECTOR),
                   .match = ares_dns_rr_get_u8(rr, ARES_RR_TLSA_MATCH),
                   .ttl = ttl};
    std::size_t data_len = 0;
    const unsigned char* data_ptr = ares_dns_rr_get_bin(rr, ARES_RR_TLSA_DATA, &data_len);
    if (uarch::flow::unlikely((data_ptr == nullptr && data_len > 0) || data_len > out.data.size())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    if (data_ptr != nullptr && data_len > 0) {
      std::memcpy(out.data.data(), data_ptr, data_len);
    }
    out.data_len = static_cast<std::uint16_t>(data_len);
    return out;
  } else if constexpr (std::is_same_v<RrT, SvcbRecord>) {
    RequireValidRecordKey<SvcbRecord, ARES_RR_SVCB_PRIORITY>();
    RequireValidRecordKey<SvcbRecord, ARES_RR_SVCB_TARGET>();
    const auto copied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_SVCB_TARGET));
    if (uarch::flow::unlikely(!copied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return SvcbRecord{.priority = ares_dns_rr_get_u16(rr, ARES_RR_SVCB_PRIORITY),
                      .target = copied->bytes,
                      .target_len = copied->len,
                      .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, HttpsRecord>) {
    RequireValidRecordKey<HttpsRecord, ARES_RR_HTTPS_PRIORITY>();
    RequireValidRecordKey<HttpsRecord, ARES_RR_HTTPS_TARGET>();
    const auto copied = CopyCStringBounded<256>(ares_dns_rr_get_str(rr, ARES_RR_HTTPS_TARGET));
    if (uarch::flow::unlikely(!copied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return HttpsRecord{.priority = ares_dns_rr_get_u16(rr, ARES_RR_HTTPS_PRIORITY),
                       .target = copied->bytes,
                       .target_len = copied->len,
                       .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, OptRecord>) {
    RequireValidRecordKey<OptRecord, ARES_RR_OPT_UDP_SIZE>();
    RequireValidRecordKey<OptRecord, ARES_RR_OPT_VERSION>();
    RequireValidRecordKey<OptRecord, ARES_RR_OPT_FLAGS>();
    return OptRecord{.udp_size = ares_dns_rr_get_u16(rr, ARES_RR_OPT_UDP_SIZE),
                     .version = ares_dns_rr_get_u8(rr, ARES_RR_OPT_VERSION),
                     .flags = ares_dns_rr_get_u16(rr, ARES_RR_OPT_FLAGS),
                     .ttl = ttl};
  } else if constexpr (std::is_same_v<RrT, HinfoRecord>) {
    RequireValidRecordKey<HinfoRecord, ARES_RR_HINFO_CPU>();
    RequireValidRecordKey<HinfoRecord, ARES_RR_HINFO_OS>();
    const auto ccopied = CopyCStringBoundedU8<128>(ares_dns_rr_get_str(rr, ARES_RR_HINFO_CPU));
    const auto ocopied = CopyCStringBoundedU8<128>(ares_dns_rr_get_str(rr, ARES_RR_HINFO_OS));
    if (uarch::flow::unlikely(!ccopied.has_value() || !ocopied.has_value())) {
      return std::unexpected(MakeBadResponseErrorSlow());
    }
    return HinfoRecord{
        .cpu = ccopied->bytes, .cpu_len = ccopied->len, .os = ocopied->bytes, .os_len = ocopied->len, .ttl = ttl};
  }
}

template <DnsRecordStruct RrT>
[[nodiscard]] inline Result<RecordVariant> ToRecordVariant(Result<RrT>&& res) noexcept {
  if (uarch::flow::unlikely(!res.has_value())) {
    return std::unexpected(res.error());
  }
  return RecordVariant{std::move(*res)};
}

[[nodiscard]] inline Result<RecordItem> ExtractRecordItemFromRaw(RecordSection section,
                                                                 const ares_dns_rr_t* __restrict rr) noexcept {
  if (uarch::flow::unlikely(rr == nullptr)) {
    return std::unexpected(MakeBadResponseErrorSlow());
  }
  const auto ncopied = CopyCStringBounded<256>(ares_dns_rr_get_name(rr));
  if (uarch::flow::unlikely(!ncopied.has_value())) {
    return std::unexpected(MakeBadResponseErrorSlow());
  }
  const auto rtype = static_cast<DnsType>(ares_dns_rr_get_type(rr));
  Result<RecordVariant> var_res = std::unexpected(MakeBadResponseErrorSlow());
  switch (rtype) {
    case DnsType::A:
      var_res = ToRecordVariant(ExtractTypedRr<ARecord>(rr));
      break;
    case DnsType::AAAA:
      var_res = ToRecordVariant(ExtractTypedRr<AaaaRecord>(rr));
      break;
    case DnsType::CNAME:
      var_res = ToRecordVariant(ExtractTypedRr<CnameRecord>(rr));
      break;
    case DnsType::MX:
      var_res = ToRecordVariant(ExtractTypedRr<MxRecord>(rr));
      break;
    case DnsType::TXT:
      var_res = ToRecordVariant(ExtractTypedRr<TxtRecord>(rr));
      break;
    case DnsType::SRV:
      var_res = ToRecordVariant(ExtractTypedRr<SrvRecord>(rr));
      break;
    case DnsType::PTR:
      var_res = ToRecordVariant(ExtractTypedRr<PtrRecord>(rr));
      break;
    case DnsType::SOA:
      var_res = ToRecordVariant(ExtractTypedRr<SoaRecord>(rr));
      break;
    case DnsType::NS:
      var_res = ToRecordVariant(ExtractTypedRr<NsRecord>(rr));
      break;
    case DnsType::NAPTR:
      var_res = ToRecordVariant(ExtractTypedRr<NaptrRecord>(rr));
      break;
    case DnsType::CAA:
      var_res = ToRecordVariant(ExtractTypedRr<CaaRecord>(rr));
      break;
    case DnsType::URI:
      var_res = ToRecordVariant(ExtractTypedRr<UriRecord>(rr));
      break;
    case DnsType::TLSA:
      var_res = ToRecordVariant(ExtractTypedRr<TlsaRecord>(rr));
      break;
    case DnsType::SVCB:
      var_res = ToRecordVariant(ExtractTypedRr<SvcbRecord>(rr));
      break;
    case DnsType::HTTPS:
      var_res = ToRecordVariant(ExtractTypedRr<HttpsRecord>(rr));
      break;
    case DnsType::OPT:
      var_res = ToRecordVariant(ExtractTypedRr<OptRecord>(rr));
      break;
    case DnsType::HINFO:
      var_res = ToRecordVariant(ExtractTypedRr<HinfoRecord>(rr));
      break;
    case DnsType::ANY:
      return std::unexpected(MakeBadResponseErrorSlow());
    default:
      // DNSSEC and other unmodeled types are absent from RecordItem, not a broken message.
      return std::unexpected(Error::NotFound());
  }
  if (uarch::flow::unlikely(!var_res.has_value())) {
    return std::unexpected(var_res.error());
  }
  return RecordItem{.name = ncopied->bytes,
                    .name_len = ncopied->len,
                    .section = section,
                    .rtype = rtype,
                    .rclass = static_cast<DnsClass>(ares_dns_rr_get_class(rr)),
                    .ttl = static_cast<std::uint32_t>(ares_dns_rr_get_ttl(rr)),
                    .data = std::move(*var_res)};
}

}  // namespace cares::detail
