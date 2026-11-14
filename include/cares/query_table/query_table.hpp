/**
 * @file query_table.hpp
 * @brief Compile-time DNS question routes and a first-question wire parser.
 */
#pragma once

#include <array>
#include <bit>
#include <cares/error/ares_error.hpp>
#include <cares/types/dns_types.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <meta>
#include <span>
#include <string_view>
#include <type_traits>
#include <uarch/uarch.hpp>
#include <utility>

namespace cares::notes {

/**
 * @brief One exact question route: presentation name, type, and class.
 *
 * The name is stored by value. A pointer into a string literal is not a valid
 * P2996 annotation argument on the supported compilers.
 */
struct QueryRouteNote {
  std::array<char, 256> qname{};
  std::uint8_t qname_len{0};
  std::uint8_t valid{0};
  DnsType qtype{DnsType::A};
  DnsClass qclass{DnsClass::IN};
};

[[nodiscard]] inline constexpr QueryRouteNote QueryRoute(const char *qname, DnsType qtype,
                                                         DnsClass qclass = DnsClass::IN) noexcept {
  QueryRouteNote note{};
  note.qtype = qtype;
  note.qclass = qclass;
  if (qname == nullptr) return note;
  std::size_t len = 0;
  while (qname[len] != '\0') {
    if (len + 1 >= note.qname.size()) return note;
    ++len;
  }
  for (std::size_t index = 0; index < len; ++index) note.qname[index] = qname[index];
  note.qname_len = static_cast<std::uint8_t>(len);
  note.valid = 1;
  return note;
}

}  // namespace cares::notes

namespace cares {

/** @brief Wire image of the first question. `qname_wire` aliases the source
 * packet. */
struct FirstQuestionWire {
  std::span<const std::byte> qname_wire{};
  DnsType qtype{DnsType::A};
  DnsClass qclass{DnsClass::IN};
};

/** @brief Presentation name encoded as an uncompressed RFC 1035 QNAME. */
struct EncodedQname {
  std::array<std::uint8_t, 255> wire{};
  std::uint8_t len{0};
  std::uint8_t ok{0};

  [[nodiscard]] constexpr std::span<const std::uint8_t> Wire() const noexcept { return {wire.data(), len}; }
};

/** @brief One reflected route after the presentation name has been encoded. */
struct QueryRouteDescriptor {
  std::array<std::uint8_t, 255> wire{};
  std::uint8_t wire_len{0};
  DnsType qtype{DnsType::A};
  DnsClass qclass{DnsClass::IN};
  std::uint16_t index{0};

  [[nodiscard]] constexpr std::span<const std::uint8_t> Wire() const noexcept { return {wire.data(), wire_len}; }
};

inline constexpr std::uint16_t kEmptyRoute = 0xFFFF;

/**
 * @brief Uncompressed QNAME view. Comparison folds ASCII case and ignores no
 * other bits.
 *
 * A view does not own its bytes. Empty views compare unequal.
 */
class DnsQnameWireView {
 public:
  constexpr DnsQnameWireView() noexcept = default;
  explicit constexpr DnsQnameWireView(std::span<const std::byte> wire) noexcept : wire_(wire) {}

  [[nodiscard]] constexpr std::span<const std::byte> Wire() const noexcept { return wire_; }
  [[nodiscard]] constexpr bool Empty() const noexcept { return wire_.empty(); }
  [[nodiscard]] constexpr bool Equals(DnsQnameWireView other) const noexcept;
  [[nodiscard]] constexpr bool EqualsPresentation(std::string_view name) const noexcept;

 private:
  std::span<const std::byte> wire_{};
};

namespace query_detail {

[[nodiscard, gnu::always_inline]] constexpr bool Cold(bool condition) noexcept {
  if consteval {
    return condition;
  } else {
    return uarch::unlikely(condition);
  }
}

[[nodiscard]] constexpr unsigned char AsciiLower(unsigned char value) noexcept {
  const auto delta = static_cast<unsigned char>(value - static_cast<unsigned char>('A'));
  const auto is_upper = static_cast<unsigned char>(delta <= static_cast<unsigned char>('Z' - 'A'));
  return static_cast<unsigned char>(value | static_cast<unsigned char>(is_upper << 5));
}

// Byte 0x80 marks an ASCII uppercase letter. Shifting that bit by two yields
// the 0x20 case bit without crossing into the next byte, so a word fold is
// eight independent ASCII conversions.
[[nodiscard, gnu::always_inline]] constexpr std::uint64_t SwarAsciiLower(std::uint64_t word) noexcept {
  constexpr std::uint64_t kOnes = 0x0101010101010101ULL;
  constexpr std::uint64_t kHigh = 0x8080808080808080ULL;
  constexpr std::uint64_t kA = 0x41ULL * kOnes;
  constexpr std::uint64_t kAfterZ = 0x5BULL * kOnes;
  const std::uint64_t biased = (word & ~kHigh) | kHigh;
  const std::uint64_t upper = ((biased - kA) & kHigh) & ~((biased - kAfterZ) & kHigh) & ~word;
  return word | (upper >> 2);
}

template <typename Byte>
[[nodiscard]] constexpr std::uint64_t LoadLe8(const Byte *data) noexcept {
  static_assert(sizeof(Byte) == 1);
  if consteval {
    std::uint64_t word = 0;
    for (int shift = 0; shift < 8; ++shift) {
      unsigned char value = 0;
      if constexpr (std::is_same_v<Byte, std::byte>)
        value = std::to_integer<unsigned char>(data[shift]);
      else
        value = static_cast<unsigned char>(data[shift]);
      word |= static_cast<std::uint64_t>(value) << static_cast<unsigned>(shift * 8);
    }
    return word;
  } else {
    std::uint64_t word = 0;
    std::memcpy(&word, data, sizeof(word));
    return word;
  }
}

template <typename Left, typename Right>
[[nodiscard, gnu::always_inline]] constexpr bool FoldedEqual(std::span<const Left> left,
                                                             std::span<const Right> right) noexcept {
  if (left.size() != right.size()) return false;
  std::size_t index = 0;
  while (index + 8 <= left.size()) {
    if (SwarAsciiLower(LoadLe8(left.data() + index)) != SwarAsciiLower(LoadLe8(right.data() + index))) return false;
    index += 8;
  }
  for (; index < left.size(); ++index) {
    unsigned char lhs = 0;
    unsigned char rhs = 0;
    if constexpr (std::is_same_v<Left, std::byte>)
      lhs = std::to_integer<unsigned char>(left[index]);
    else
      lhs = static_cast<unsigned char>(left[index]);
    if constexpr (std::is_same_v<Right, std::byte>)
      rhs = std::to_integer<unsigned char>(right[index]);
    else
      rhs = static_cast<unsigned char>(right[index]);
    if (AsciiLower(lhs) != AsciiLower(rhs)) return false;
  }
  return true;
}

template <typename Byte>
[[nodiscard, gnu::always_inline]] constexpr std::uint32_t HashWire(std::span<const Byte> wire, DnsType qtype, DnsClass qclass,
                                                                   std::uint32_t salt) noexcept {
  std::uint32_t hash = 2166136261u ^ salt;
  for (const Byte byte : wire) {
    unsigned char value = 0;
    if constexpr (std::is_same_v<Byte, std::byte>)
      value = std::to_integer<unsigned char>(byte);
    else
      value = static_cast<unsigned char>(byte);
    hash ^= static_cast<std::uint32_t>(AsciiLower(value));
    hash *= 16777619u;
  }
  hash ^= static_cast<std::uint32_t>(std::to_underlying(qtype));
  hash *= 16777619u;
  hash ^= static_cast<std::uint32_t>(std::to_underlying(qclass));
  hash *= 16777619u;
  return hash;
}

[[nodiscard]] constexpr std::uint16_t ReadBe16(std::span<const std::byte> packet, std::size_t offset) noexcept {
  const auto hi = static_cast<unsigned>(std::to_integer<unsigned char>(packet[offset]));
  const auto lo = static_cast<unsigned>(std::to_integer<unsigned char>(packet[offset + 1]));
  return static_cast<std::uint16_t>((hi << 8u) | lo);
}

[[nodiscard]] constexpr EncodedQname EncodeQname(std::string_view name) noexcept {
  EncodedQname encoded{};
  if (name.empty() || name == ".") {
    encoded.wire[0] = 0;
    encoded.len = 1;
    encoded.ok = 1;
    return encoded;
  }
  if (!name.empty() && name.back() == '.') name.remove_suffix(1);
  if (name.empty()) return encoded;
  std::size_t cursor = 0;
  std::size_t label_begin = 0;
  const auto flush = [&](std::size_t begin, std::size_t end) noexcept {
    const std::size_t label_len = end - begin;
    if (label_len == 0 || label_len > 63) return false;
    if (cursor + 1 + label_len + 1 > encoded.wire.size()) return false;
    encoded.wire[cursor++] = static_cast<std::uint8_t>(label_len);
    for (std::size_t index = begin; index < end; ++index) {
      const auto value = static_cast<unsigned char>(name[index]);
      if (value == 0) return false;
      encoded.wire[cursor++] = static_cast<std::uint8_t>(value);
    }
    return true;
  };
  for (std::size_t index = 0; index < name.size(); ++index) {
    if (name[index] != '.') continue;
    if (!flush(label_begin, index)) return EncodedQname{};
    label_begin = index + 1;
  }
  if (!flush(label_begin, name.size())) return EncodedQname{};
  encoded.wire[cursor++] = 0;
  encoded.len = static_cast<std::uint8_t>(cursor);
  encoded.ok = 1;
  return encoded;
}

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

template <typename Route, std::size_t kIndex>
[[nodiscard]] consteval QueryRouteDescriptor DescribeRoute() {
  static_assert(NoteCount<notes::QueryRouteNote, ^^Route>() == 1, "missing query route annotation");
  constexpr auto kNote = NoteValue<notes::QueryRouteNote, ^^Route>();
  static_assert(kNote.valid != 0, "invalid query route qname");
  constexpr auto kEncoded = EncodeQname(std::string_view{kNote.qname.data(), kNote.qname_len});
  static_assert(kEncoded.ok != 0, "invalid query route qname");
  QueryRouteDescriptor descriptor{};
  descriptor.wire = kEncoded.wire;
  descriptor.wire_len = kEncoded.len;
  descriptor.qtype = kNote.qtype;
  descriptor.qclass = kNote.qclass;
  descriptor.index = static_cast<std::uint16_t>(kIndex);
  return descriptor;
}

template <typename... Routes, std::size_t... kIndex>
[[nodiscard]] consteval auto DescribeIndexed(std::index_sequence<kIndex...>) {
  return std::array<QueryRouteDescriptor, sizeof...(Routes)>{DescribeRoute<Routes...[kIndex], kIndex>()...};
}

template <typename... Routes>
[[nodiscard]] consteval auto BuildRoutes() {
  if constexpr (sizeof...(Routes) == 0)
    return std::array<QueryRouteDescriptor, 0>{};
  else
    return DescribeIndexed<Routes...>(std::make_index_sequence<sizeof...(Routes)>{});
}

template <std::size_t kCount>
[[nodiscard]] constexpr bool UniqueRoutes(const std::array<QueryRouteDescriptor, kCount> &routes) noexcept {
  for (std::size_t left = 0; left < kCount; ++left) {
    for (std::size_t right = left + 1; right < kCount; ++right) {
      if (routes[left].qtype != routes[right].qtype || routes[left].qclass != routes[right].qclass) continue;
      if (FoldedEqual(routes[left].Wire(), routes[right].Wire())) return false;
    }
  }
  return true;
}

template <std::size_t kCount>
struct DispatchPlan {
  static constexpr std::size_t kSlotCount = std::bit_ceil(kCount == 0 ? std::size_t{1} : kCount * 2);
  static constexpr std::uint32_t kMask = static_cast<std::uint32_t>(kSlotCount - 1);
  std::uint32_t salt{1};
  std::array<QueryRouteDescriptor, kSlotCount> slots{};
};

template <std::size_t kCount>
[[nodiscard]] consteval bool SaltFits(const std::array<QueryRouteDescriptor, kCount> &routes, std::uint32_t salt) {
  constexpr std::size_t kSlotCount = DispatchPlan<kCount>::kSlotCount;
  std::array<std::uint8_t, kSlotCount> used{};
  for (const QueryRouteDescriptor &route : routes) {
    const auto slot = HashWire(route.Wire(), route.qtype, route.qclass, salt) & DispatchPlan<kCount>::kMask;
    if (used[slot] != 0) return false;
    used[slot] = 1;
  }
  return true;
}

template <std::size_t kCount>
[[nodiscard]] consteval DispatchPlan<kCount> BuildDispatch(const std::array<QueryRouteDescriptor, kCount> &routes) {
  DispatchPlan<kCount> plan{};
  for (QueryRouteDescriptor &slot : plan.slots) slot.index = kEmptyRoute;
  if (!UniqueRoutes(routes)) return plan;
  std::uint32_t salt = 1;
  for (; salt < 128; ++salt) {
    if (SaltFits(routes, salt)) break;
  }
  if (salt == 128) {
    plan.salt = 0;
    return plan;
  }
  plan.salt = salt;
  for (const QueryRouteDescriptor &route : routes) {
    const auto slot = HashWire(route.Wire(), route.qtype, route.qclass, salt) & DispatchPlan<kCount>::kMask;
    plan.slots[slot] = route;
  }
  return plan;
}

template <std::size_t kCount>
[[nodiscard]] consteval bool SaltFound(const DispatchPlan<kCount> &plan) noexcept {
  return kCount == 0 || plan.salt != 0;
}

template <typename... Routes>
struct TableOps {
  static constexpr std::size_t kRouteCount = sizeof...(Routes);
  static constexpr auto kRoutes = BuildRoutes<Routes...>();
  static constexpr bool kUnique = UniqueRoutes(kRoutes);
  static constexpr auto kPlan = BuildDispatch(kRoutes);
  static constexpr bool kSeeded = kUnique && SaltFound(kPlan);

  template <typename Visitor>
  [[nodiscard]] static constexpr bool Invoke([[maybe_unused]] std::uint16_t index, [[maybe_unused]] Visitor &visitor,
                                             [[maybe_unused]] const FirstQuestionWire &question) noexcept {
    if constexpr (kRouteCount == 0) {
      return false;
    } else {
      constexpr auto kIndices = []() consteval {
        std::array<std::size_t, kRouteCount> values{};
        for (std::size_t cursor = 0; cursor < kRouteCount; ++cursor) values[cursor] = cursor;
        return values;
      }();
      template for (constexpr auto kRouteIndex : std::define_static_array(kIndices)) {
        if (index == kRouteIndex) {
          visitor.template operator()<Routes...[kRouteIndex]>(question);
          return true;
        }
      }
      return false;
    }
  }
};

}  // namespace query_detail

[[nodiscard]] constexpr bool DnsQnameWireView::Equals(DnsQnameWireView other) const noexcept {
  if (wire_.empty() || other.wire_.empty()) return false;
  return query_detail::FoldedEqual(wire_, other.wire_);
}

[[nodiscard]] constexpr bool DnsQnameWireView::EqualsPresentation(std::string_view name) const noexcept {
  const EncodedQname encoded = query_detail::EncodeQname(name);
  if (encoded.ok == 0 || wire_.empty()) return false;
  return query_detail::FoldedEqual(wire_, encoded.Wire());
}

/**
 * @brief Encode a presentation name. A trailing dot is the root and is not
 * stored as an empty label.
 */
[[nodiscard]] constexpr EncodedQname EncodeQname(std::string_view name) noexcept { return query_detail::EncodeQname(name); }

/**
 * @brief Parse the first question of a DNS message.
 *
 * The QNAME walk is a scalar RFC 1035 label-length hop. ASCII case-folding of
 * the decoded labels is the SWAR 8-byte fold used by compare and hash.
 * Compression and the two reserved label types are rejected from the
 * length octet alone: `(len & 0xC0) != 0` yields `Error::BadName()`. Payload
 * octets are skipped by that length, so a label may contain `0xC0`.
 */
[[nodiscard, gnu::always_inline]] constexpr Result<FirstQuestionWire> ParseFirstQuestionWire(
    std::span<const std::byte> packet) noexcept {
  if (query_detail::Cold(packet.size() < 12)) return std::unexpected(Error::BadResponse());
  const auto qdcount = query_detail::ReadBe16(packet, 4);
  if (query_detail::Cold(qdcount == 0)) return std::unexpected(Error::BadResponse());
  std::size_t offset = 12;
  const std::size_t name_begin = 12;
  std::size_t labels = 0;
  while (true) {
    if (query_detail::Cold(offset >= packet.size())) return std::unexpected(Error::BadName());
    const auto len = static_cast<unsigned>(std::to_integer<unsigned char>(packet[offset]));
    if (query_detail::Cold((len & 0xC0u) != 0u)) return std::unexpected(Error::BadName());
    if (len == 0) {
      ++offset;
      break;
    }
    if (query_detail::Cold(offset + len >= packet.size())) return std::unexpected(Error::BadName());
    offset += static_cast<std::size_t>(len) + 1;
    ++labels;
    if (query_detail::Cold(labels > 127 || offset - name_begin > 255)) return std::unexpected(Error::BadName());
  }
  if (query_detail::Cold(offset - name_begin > 255)) return std::unexpected(Error::BadName());
  if (query_detail::Cold(offset + 4 > packet.size())) return std::unexpected(Error::BadResponse());
  const auto qtype = static_cast<DnsType>(query_detail::ReadBe16(packet, offset));
  const auto qclass = static_cast<DnsClass>(query_detail::ReadBe16(packet, offset + 2));
  return FirstQuestionWire{packet.subspan(name_begin, offset - name_begin), qtype, qclass};
}

/**
 * @brief O(1) perfect-hash dispatch over reflected `notes::QueryRoute` types.
 *
 * Duplicate routes are rejected while the table is built. Case and a single
 * trailing dot do not make two routes distinct. `DispatchQuestion` compares one
 * slot; the route index then expands to a direct call of `visitor.template
 * operator()<Route>(question)`.
 */
template <typename... Routes>
class QueryTable {
 public:
  static constexpr std::size_t kRouteCount = sizeof...(Routes);
  static constexpr auto kRoutes = query_detail::TableOps<Routes...>::kRoutes;
  static constexpr bool kRoutesAreUnique = query_detail::TableOps<Routes...>::kUnique;
  static constexpr auto kPlan = query_detail::TableOps<Routes...>::kPlan;

  static_assert(kRouteCount <= 32, "query route capacity exceeded");
  static_assert(kRoutesAreUnique, "duplicate query route");
  static_assert(!kRoutesAreUnique || query_detail::TableOps<Routes...>::kSeeded, "query route hash seed exhausted");

  template <typename Visitor>
  [[nodiscard]] static constexpr Result<std::uint16_t> DispatchQuestion(DnsQnameWireView qname, DnsType qtype, DnsClass qclass,
                                                                        Visitor &&visitor) noexcept {
    const FirstQuestionWire question{qname.Wire(), qtype, qclass};
    const auto hash = query_detail::HashWire(qname.Wire(), qtype, qclass, kPlan.salt);
    const QueryRouteDescriptor &slot = kPlan.slots[hash & kPlan.kMask];
    if (query_detail::Cold(slot.index == kEmptyRoute || slot.qtype != qtype || slot.qclass != qclass ||
                           !query_detail::FoldedEqual(slot.Wire(), qname.Wire()))) {
      return std::unexpected(Error::NotFound());
    }
    if (query_detail::Cold(!query_detail::TableOps<Routes...>::Invoke(slot.index, visitor, question))) {
      return std::unexpected(Error::NotFound());
    }
    // Value-initialize, then emplace. GCC 16 treats `return slot.index` into
    // std::expected as a read of an uninitialized union after this function is
    // inlined.
    Result<std::uint16_t> found(std::in_place, std::uint16_t{0});
    found.emplace(slot.index);
    return found;
  }

  template <typename Visitor>
  [[nodiscard]] static constexpr Result<std::uint16_t> DispatchWireQuestion(std::span<const std::byte> packet,
                                                                            Visitor &&visitor) noexcept {
    const Result<FirstQuestionWire> parsed = ParseFirstQuestionWire(packet);
    if (query_detail::Cold(!parsed.has_value())) return std::unexpected(parsed.error());
    return DispatchQuestion(DnsQnameWireView{parsed->qname_wire}, parsed->qtype, parsed->qclass,
                            std::forward<Visitor>(visitor));
  }
};

}  // namespace cares
