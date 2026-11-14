/**
 * @file record_extract.hpp
 * @brief Copy one annotated resource record out of a `DnsRecordRef`.
 */
#pragma once

#include <ares.h>
#include <ares_dns_record.h>

#include <array>
#include <cares/error/ares_error.hpp>
#include <cares/record/dns_record.hpp>
#include <cares/types/dns_types.hpp>
#include <cares/types/host_types.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <meta>
#include <optional>
#include <tuple>
#include <type_traits>
#include <uarch/uarch.hpp>
#include <utility>

namespace cares::notes {

/** @brief Section an annotated record value is read from. */
struct DnsSectionNote {
  RecordSection section{};
};

/** @brief DNS type an annotated record value matches. */
struct DnsTypeNote {
  DnsType type{};
};

/** @brief c-ares RR key copied into one data member. */
struct DnsFieldNote {
  ares_dns_rr_key_t key{};
};

/** @brief Member receives `ares_dns_rr_get_ttl` rather than an RR key. */
struct DnsTtlNote {};

[[nodiscard]] inline constexpr DnsSectionNote Section(RecordSection section) noexcept { return DnsSectionNote{section}; }

inline constexpr DnsSectionNote Answer{RecordSection::Answer};
inline constexpr DnsSectionNote Authority{RecordSection::Authority};
inline constexpr DnsSectionNote Additional{RecordSection::Additional};

[[nodiscard]] inline constexpr DnsTypeNote Type(DnsType type) noexcept { return DnsTypeNote{type}; }

[[nodiscard]] inline constexpr DnsFieldNote Field(ares_dns_rr_key_t key) noexcept { return DnsFieldNote{key}; }

inline constexpr DnsTtlNote Ttl{};

}  // namespace cares::notes

namespace cares {
namespace record_detail {

template <typename Annotation, std::meta::info kEntity>
[[nodiscard]] consteval std::size_t NoteCount() {
  std::size_t count = 0;
  template for (constexpr auto kNote : std::define_static_array(std::meta::annotations_of(kEntity))) {
    constexpr auto kValue = std::meta::constant_of(kNote);
    if constexpr (std::meta::remove_cv(std::meta::type_of(kValue)) == ^^Annotation) ++count;
  }
  return count;
}

template <typename Annotation, std::meta::info kEntity>
[[nodiscard]] consteval Annotation NoteValue() {
  Annotation result{};
  template for (constexpr auto kNote : std::define_static_array(std::meta::annotations_of(kEntity))) {
    constexpr auto kValue = std::meta::constant_of(kNote);
    if constexpr (std::meta::remove_cv(std::meta::type_of(kValue)) == ^^Annotation) {
      result = std::meta::extract<Annotation>(kValue);
    }
  }
  return result;
}

template <typename T>
inline constexpr bool kIsCharArray = false;

template <std::size_t kN>
inline constexpr bool kIsCharArray<std::array<char, kN>> = true;

template <typename T>
inline constexpr bool kIsByteArray = false;

template <std::size_t kN>
inline constexpr bool kIsByteArray<std::array<std::uint8_t, kN>> = true;

template <typename T>
inline constexpr bool kAlwaysFalse = false;

template <typename T>
[[nodiscard]] consteval bool AnnotationsHold() {
  static constexpr auto kMembers =
      std::define_static_array(std::meta::nonstatic_data_members_of(^^T, std::meta::access_context::unchecked()));
  static_assert(NoteCount<notes::DnsSectionNote, ^^T>() == 1, "missing section annotation");
  static_assert(NoteCount<notes::DnsTypeNote, ^^T>() == 1, "missing type annotation");
  template for (constexpr auto kMember : kMembers) {
    constexpr auto kFieldCount = NoteCount<notes::DnsFieldNote, kMember>();
    constexpr auto kTtlCount = NoteCount<notes::DnsTtlNote, kMember>();
    if constexpr (kFieldCount + kTtlCount == 0) {
      static_assert(kAlwaysFalse<T>, "unannotated field");
    } else {
      static_assert(kFieldCount + kTtlCount == 1, "ambiguous field annotation");
    }
    if constexpr (kFieldCount == 1) {
      constexpr auto kType = NoteValue<notes::DnsTypeNote, ^^T>().type;
      constexpr auto kKey = NoteValue<notes::DnsFieldNote, kMember>().key;
      static_assert(IsValidRrKeyForType(kType, kKey), "field key does not belong to the record type");
    }
    if constexpr (kTtlCount == 1) {
      using MemberType = [:std::meta::type_of(kMember):];
      static_assert(std::is_same_v<MemberType, std::uint32_t>, "ttl field must be uint32_t");
    }
  }
  return true;
}

[[nodiscard]] inline std::optional<std::uint16_t> MeasureText(const ares_dns_rr_t *rr, ares_dns_rr_key_t key,
                                                              ares_dns_datatype_t datatype) noexcept {
  if (datatype == ARES_DATATYPE_NAME || datatype == ARES_DATATYPE_STR) {
    const char *text = ares_dns_rr_get_str(rr, key);
    if (text == nullptr) return std::nullopt;
    std::size_t size = 0;
    while (text[size] != '\0') {
      if (size == 0xFFFF) return std::nullopt;
      ++size;
    }
    return static_cast<std::uint16_t>(size);
  }
  if (datatype == ARES_DATATYPE_BIN || datatype == ARES_DATATYPE_BINP) {
    std::size_t size = 0;
    if (ares_dns_rr_get_bin(rr, key, &size) == nullptr && size != 0) return std::nullopt;
    if (size > 0xFFFF) return std::nullopt;
    return static_cast<std::uint16_t>(size);
  }
  if (datatype == ARES_DATATYPE_ABINP) {
    const std::size_t chunks = ares_dns_rr_get_abin_cnt(rr, key);
    std::size_t size = 0;
    for (std::size_t index = 0; index < chunks; ++index) {
      std::size_t chunk = 0;
      if (ares_dns_rr_get_abin(rr, key, index, &chunk) == nullptr && chunk != 0) return std::nullopt;
      if (size + chunk > 0xFFFF) return std::nullopt;
      size += chunk;
    }
    return static_cast<std::uint16_t>(size);
  }
  return std::nullopt;
}

template <typename FieldType>
[[nodiscard]] inline Result<FieldType> AssignField(const ares_dns_rr_t *rr, ares_dns_rr_key_t key) noexcept {
  const auto datatype = ares_dns_rr_key_datatype(key);
  if constexpr (std::is_same_v<FieldType, IpAddress>) {
    if (datatype == ARES_DATATYPE_INADDR) {
      const in_addr *addr = ares_dns_rr_get_addr(rr, key);
      if (addr == nullptr) return std::unexpected(Error::BadResponse());
      Ipv4Bytes bytes{};
      std::memcpy(bytes.data(), addr, bytes.size());
      return IpAddress::FromV4(bytes);
    }
    if (datatype == ARES_DATATYPE_INADDR6) {
      const ares_in6_addr *addr = ares_dns_rr_get_addr6(rr, key);
      if (addr == nullptr) return std::unexpected(Error::BadResponse());
      Ipv6Bytes bytes{};
      std::memcpy(bytes.data(), addr->_S6_un._S6_u8, bytes.size());
      return IpAddress::FromV6(bytes);
    }
    return std::unexpected(Error::BadResponse());
  } else if constexpr (std::is_same_v<FieldType, std::uint8_t> || std::is_same_v<FieldType, std::uint16_t>) {
    if constexpr (std::is_same_v<FieldType, std::uint8_t>) {
      if (datatype == ARES_DATATYPE_U8) return static_cast<std::uint8_t>(ares_dns_rr_get_u8(rr, key));
    } else if (datatype == ARES_DATATYPE_U16) {
      return static_cast<std::uint16_t>(ares_dns_rr_get_u16(rr, key));
    }
    const std::optional<std::uint16_t> length = MeasureText(rr, key, datatype);
    if (!length.has_value()) return std::unexpected(Error::BadResponse());
    if constexpr (std::is_same_v<FieldType, std::uint8_t>) {
      if (*length > 0xFF) return std::unexpected(Error::BadResponse());
      return static_cast<std::uint8_t>(*length);
    }
    return *length;
  } else if constexpr (std::is_same_v<FieldType, std::uint32_t>) {
    if (datatype != ARES_DATATYPE_U32) return std::unexpected(Error::BadResponse());
    return ares_dns_rr_get_u32(rr, key);
  } else if constexpr (kIsCharArray<FieldType> || kIsByteArray<FieldType>) {
    constexpr std::size_t kCapacity = std::tuple_size_v<FieldType>;
    FieldType dest{};
    if (datatype == ARES_DATATYPE_NAME || datatype == ARES_DATATYPE_STR) {
      const char *text = ares_dns_rr_get_str(rr, key);
      if (text == nullptr) return std::unexpected(Error::BadResponse());
      std::size_t size = 0;
      while (text[size] != '\0') ++size;
      if (size >= kCapacity) return std::unexpected(Error::BadResponse());
      std::memcpy(dest.data(), text, size);
      return dest;
    }
    if (datatype == ARES_DATATYPE_BIN || datatype == ARES_DATATYPE_BINP) {
      std::size_t size = 0;
      const unsigned char *bytes = ares_dns_rr_get_bin(rr, key, &size);
      if (bytes == nullptr && size != 0) return std::unexpected(Error::BadResponse());
      if (size > kCapacity) return std::unexpected(Error::BadResponse());
      if (size != 0) std::memcpy(dest.data(), bytes, size);
      return dest;
    }
    if (datatype == ARES_DATATYPE_ABINP) {
      const std::size_t chunks = ares_dns_rr_get_abin_cnt(rr, key);
      std::size_t written = 0;
      for (std::size_t index = 0; index < chunks; ++index) {
        std::size_t chunk = 0;
        const unsigned char *bytes = ares_dns_rr_get_abin(rr, key, index, &chunk);
        if (bytes == nullptr && chunk != 0) return std::unexpected(Error::BadResponse());
        if (written + chunk > kCapacity) return std::unexpected(Error::BadResponse());
        if (chunk != 0) std::memcpy(dest.data() + written, bytes, chunk);
        written += chunk;
      }
      return dest;
    }
    return std::unexpected(Error::BadResponse());
  } else {
    static_assert(kAlwaysFalse<FieldType>, "unsupported extract field type");
    return std::unexpected(Error::BadResponse());
  }
}

template <typename T>
[[nodiscard]] inline Result<T> FillMatching(const ares_dns_rr_t *rr) noexcept {
  T out{};
  bool failed = false;
  static constexpr auto kMembers =
      std::define_static_array(std::meta::nonstatic_data_members_of(^^T, std::meta::access_context::unchecked()));
  template for (constexpr auto kMember : kMembers) {
    if (!failed) {
      constexpr auto kTtlCount = NoteCount<notes::DnsTtlNote, kMember>();
      if constexpr (kTtlCount == 1) {
        out.[:kMember:] = ares_dns_rr_get_ttl(rr);
      } else {
        constexpr auto kField = NoteValue<notes::DnsFieldNote, kMember>();
        using MemberType = [:std::meta::type_of(kMember):];
        const Result<MemberType> assigned = AssignField<MemberType>(rr, kField.key);
        if (!assigned.has_value())
          failed = true;
        else
          out.[:kMember:] = *assigned;
      }
    }
  }
  if (uarch::flow::unlikely(failed)) return std::unexpected(Error::BadResponse());
  return out;
}

}  // namespace record_detail

/**
 * @brief Section attached to an annotated record value.
 * @tparam T Record value with `notes::Answer` / `Authority` / `Additional` (or
 * `notes::Section`).
 */
template <typename T>
[[nodiscard]] consteval RecordSection RecordSectionOf() {
  static_assert(record_detail::AnnotationsHold<T>());
  return record_detail::NoteValue<notes::DnsSectionNote, ^^T>().section;
}

/**
 * @brief DNS type attached to an annotated record value.
 * @tparam T Record value with `notes::Type`.
 */
template <typename T>
[[nodiscard]] consteval DnsType RecordTypeOf() {
  static_assert(record_detail::AnnotationsHold<T>());
  return record_detail::NoteValue<notes::DnsTypeNote, ^^T>().type;
}

/**
 * @brief Number of reflected data members on an annotated record value.
 * @tparam T Record value whose every data member carries `notes::Field` or
 * `notes::Ttl`.
 */
template <typename T>
[[nodiscard]] consteval std::size_t RecordFieldCount() {
  static_assert(record_detail::AnnotationsHold<T>());
  return std::define_static_array(std::meta::nonstatic_data_members_of(^^T, std::meta::access_context::unchecked())).size();
}

/**
 * @brief Copy the first RR in `T`'s section whose type matches `T`.
 *
 * Every non-static data member of `T` must carry exactly one `notes::Field` or
 * `notes::Ttl` annotation. The returned value owns its bytes; it does not alias
 * the c-ares record.
 */
template <typename T>
[[nodiscard]] inline Result<T> ExtractRecord(DnsRecordRef record) noexcept {
  static_assert(record_detail::AnnotationsHold<T>());
  if (uarch::flow::unlikely(!record.IsValid())) return std::unexpected(Error::BadResponse());
  constexpr RecordSection kSection = RecordSectionOf<T>();
  constexpr DnsType kType = RecordTypeOf<T>();
  const std::size_t count = record.RrCount(kSection);
  for (std::size_t index = 0; index < count; ++index) {
    const ares_dns_rr_t *rr = record.RrRawAt(kSection, index);
    if (uarch::flow::unlikely(rr == nullptr)) return std::unexpected(Error::BadResponse());
    if (std::to_underlying(ares_dns_rr_get_type(rr)) != std::to_underlying(kType)) continue;
    return record_detail::FillMatching<T>(rr);
  }
  return std::unexpected(Error::NotFound());
}

}  // namespace cares
