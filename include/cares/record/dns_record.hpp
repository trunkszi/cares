/** @file
 *  @brief Zero-copy borrowed DnsRecordRef view and RAII move-only DnsRecord wrapper.
 */
#pragma once

#include <ares.h>
#include <ares_dns_record.h>

#include <bit>
#include <cares/error/ares_error.hpp>
#include <cares/record/dns_record_detail.hpp>
#include <cares/record/record_rr.hpp>
#include <cares/types/dns_types.hpp>
#include <cares/types/host_types.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string_view>
#include <type_traits>
#include <uarch/uarch.hpp>
#include <utility>

namespace cares {

class DnsRecord;

/** @brief Zero-copy, register-passable borrowed view over an `ares_dns_record_t`. */
class[[= uarch::layout::register_leaf]] DnsRecordRef;
class DnsRecordRef {
 public:
  explicit constexpr DnsRecordRef(const ares_dns_record_t* rec = nullptr) noexcept : rec_(rec) {}

  [[nodiscard]] constexpr bool IsValid() const noexcept { return rec_ != nullptr; }
  [[nodiscard]] explicit constexpr operator bool() const noexcept { return IsValid(); }
  [[nodiscard]] constexpr const ares_dns_record_t* Raw() const noexcept { return rec_; }

  [[nodiscard]] std::uint16_t Id() const noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) return 0;
    return static_cast<std::uint16_t>(ares_dns_record_get_id(rec_));
  }

  [[nodiscard]] DnsFlags Flags() const noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) return DnsFlags::None;
    return static_cast<DnsFlags>(ares_dns_record_get_flags(rec_));
  }

  [[nodiscard]] DnsOpcode Opcode() const noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) return DnsOpcode::Query;
    return static_cast<DnsOpcode>(ares_dns_record_get_opcode(rec_));
  }

  [[nodiscard]] DnsRcode Rcode() const noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) return DnsRcode::FormErr;
    return static_cast<DnsRcode>(ares_dns_record_get_rcode(rec_));
  }

  [[nodiscard]] std::size_t QuestionCount() const noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) return 0;
    return ares_dns_record_query_cnt(rec_);
  }

  [[nodiscard]] Result<QuestionItem> QuestionAt(std::size_t idx) const noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) {
      return std::unexpected(detail::MakeInvalidArgErrorSlow());
    }
    const char* name_ptr = nullptr;
    ares_dns_rec_type_t qtype = ARES_REC_TYPE_A;
    ares_dns_class_t qclass = ARES_CLASS_IN;
    const ares_status_t status = ares_dns_record_query_get(rec_, idx, &name_ptr, &qtype, &qclass);
    if (uarch::flow::unlikely(status != ARES_SUCCESS)) {
      return std::unexpected(detail::MakeAresErrorSlow(std::to_underlying(status)));
    }
    const auto copied = detail::CopyCStringBounded<256>(name_ptr);
    if (uarch::flow::unlikely(!copied.has_value())) {
      return std::unexpected(detail::MakeBadNameErrorSlow());
    }
    return QuestionItem{.name = copied->bytes,
                        .name_len = copied->len,
                        .qtype = static_cast<DnsType>(qtype),
                        .qclass = static_cast<DnsClass>(qclass)};
  }

  [[nodiscard]] std::size_t RrCount(RecordSection section) const noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) return 0;
    return ares_dns_record_rr_cnt(rec_, static_cast<ares_dns_section_t>(std::to_underlying(section)));
  }

  [[nodiscard]] const ares_dns_rr_t* RrRawAt(RecordSection section, std::size_t idx) const noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) return nullptr;
    return ares_dns_record_rr_get_const(rec_, static_cast<ares_dns_section_t>(std::to_underlying(section)), idx);
  }

  /** @brief Extracts a typed DNS resource record or `RecordItem` at `(section, idx)`.
   *  TXT character-strings are concatenated into `TxtRecord::text` (65279 payload octets, 65535 on the wire).
   *  A null record or an index past the section is `BadResponse`, matching `ExtractRecord`.
   */
  template <typename RrT>
  [[nodiscard]] Result<RrT> ExtractRrAt(RecordSection section, std::size_t idx) const noexcept {
    static_assert(DnsRecordStruct<RrT> || std::is_same_v<RrT, RecordItem>,
                  "ExtractRrAt requires a supported typed DNS record struct or RecordItem");
    const ares_dns_rr_t* rr = RrRawAt(section, idx);
    if (uarch::flow::unlikely(rr == nullptr)) {
      return std::unexpected(detail::MakeBadResponseErrorSlow());
    }
    if constexpr (std::is_same_v<RrT, RecordItem>) {
      return detail::ExtractRecordItemFromRaw(section, rr);
    } else {
      return detail::ExtractTypedRr<RrT>(rr);
    }
  }

  [[nodiscard]] Result<RecordItem> ExtractRecordItemAt(RecordSection section, std::size_t idx) const noexcept {
    return ExtractRrAt<RecordItem>(section, idx);
  }

  [[nodiscard]] Result<std::size_t> WriteWire(std::span<std::byte> out_buf) const noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) {
      return std::unexpected(detail::MakeInvalidArgErrorSlow());
    }
    unsigned char* wire_ptr = nullptr;
    std::size_t wire_len = 0;
    const ares_status_t status = ares_dns_write(rec_, &wire_ptr, &wire_len);
    if (uarch::flow::unlikely(status != ARES_SUCCESS || wire_ptr == nullptr)) {
      if (wire_ptr != nullptr) {
        ares_free_string(wire_ptr);
      }
      return std::unexpected(detail::MakeAresErrorSlow(std::to_underlying(status)));
    }
    if (uarch::flow::unlikely(out_buf.size() < wire_len)) {
      ares_free_string(wire_ptr);
      return std::unexpected(detail::MakeCapacityErrorSlow());
    }
    if (wire_len > 0) {
      std::memcpy(out_buf.data(), wire_ptr, wire_len);
    }
    ares_free_string(wire_ptr);
    return wire_len;
  }

  [[nodiscard]] Result<std::size_t> WriteWire(std::span<std::uint8_t> out_buf) const noexcept {
    return WriteWire(std::as_writable_bytes(out_buf));
  }

  [[nodiscard]] Result<DnsRecord> ToOwned() const noexcept;

  friend constexpr bool operator==(const DnsRecordRef&, const DnsRecordRef&) noexcept = default;

 private:
  const ares_dns_record_t* rec_{nullptr};
};

static_assert(sizeof(DnsRecordRef) == 8);
static_assert(uarch::layout::NoPadding<DnsRecordRef> && uarch::layout::RegisterPassable<DnsRecordRef> &&
              uarch::layout::RegisterLeaf<DnsRecordRef>);

/** @brief Move-only RAII wrapper owning an `ares_dns_record_t*`. */
class DnsRecord {
 public:
  constexpr DnsRecord() noexcept = default;
  explicit constexpr DnsRecord(ares_dns_record_t* rec) noexcept : rec_(rec) {}

  DnsRecord(const DnsRecord&) = delete ("DnsRecord owns an ares_dns_record_t* and is move-only; use AsRef() or ToOwned()");
  DnsRecord& operator=(const DnsRecord&) =
      delete ("DnsRecord owns an ares_dns_record_t* and is move-only; use AsRef() or ToOwned()");

  constexpr DnsRecord(DnsRecord&& other) noexcept : rec_(std::exchange(other.rec_, nullptr)) {}

  DnsRecord& operator=(DnsRecord&& other) noexcept {
    if (this != &other) {
      Reset(std::exchange(other.rec_, nullptr));
    }
    return *this;
  }

  ~DnsRecord() noexcept { Reset(); }

  void Reset(ares_dns_record_t* new_rec = nullptr) noexcept {
    if (new_rec == rec_) {
      return;
    }
    if (rec_ != nullptr) {
      ares_dns_record_destroy(rec_);
    }
    rec_ = new_rec;
  }

  [[nodiscard]] constexpr ares_dns_record_t* Release() noexcept { return std::exchange(rec_, nullptr); }

  [[nodiscard]] static Result<DnsRecord> Create(std::uint16_t id, DnsFlags flags = DnsFlags::None,
                                                DnsOpcode opcode = DnsOpcode::Query,
                                                DnsRcode rcode = DnsRcode::NoError) noexcept {
    ares_dns_record_t* raw = nullptr;
    const ares_status_t status =
        ares_dns_record_create(&raw, id, std::to_underlying(flags), static_cast<ares_dns_opcode_t>(std::to_underlying(opcode)),
                               static_cast<ares_dns_rcode_t>(std::to_underlying(rcode)));
    if (uarch::flow::unlikely(status != ARES_SUCCESS || raw == nullptr)) {
      return std::unexpected(detail::MakeAresErrorSlow(std::to_underlying(status)));
    }
    return DnsRecord(raw);
  }

  [[nodiscard]] static Result<DnsRecord> CreateQuery(std::string_view qname, DnsType qtype, DnsClass qclass = DnsClass::IN,
                                                     std::uint16_t id = 0, DnsFlags flags = DnsFlags::Rd) noexcept {
    auto rec = Create(id, flags, DnsOpcode::Query, DnsRcode::NoError);
    if (uarch::flow::unlikely(!rec)) {
      return rec;
    }
    auto qres = rec->QuestionPush(qname, qtype, qclass);
    if (uarch::flow::unlikely(!qres)) {
      return std::unexpected(qres.error());
    }
    return rec;
  }

  [[nodiscard]] static Result<DnsRecord> ParseWire(std::span<const std::byte> wire, unsigned int parse_flags = 0) noexcept {
    if (uarch::flow::unlikely(wire.empty())) {
      return std::unexpected(detail::MakeBadResponseErrorSlow());
    }
    ares_dns_record_t* raw = nullptr;
    const ares_status_t status =
        ares_dns_parse(std::bit_cast<const unsigned char*>(wire.data()), wire.size(), parse_flags, &raw);
    if (uarch::flow::unlikely(status != ARES_SUCCESS || raw == nullptr)) {
      return std::unexpected(detail::MakeAresErrorSlow(std::to_underlying(status)));
    }
    return DnsRecord(raw);
  }

  [[nodiscard]] static Result<DnsRecord> ParseWire(std::span<const std::uint8_t> wire, unsigned int parse_flags = 0) noexcept {
    return ParseWire(std::as_bytes(wire), parse_flags);
  }

  [[nodiscard]] Result<std::size_t> WriteWire(std::span<std::byte> out_buf) const noexcept {
    return AsRef().WriteWire(out_buf);
  }

  [[nodiscard]] Result<std::size_t> WriteWire(std::span<std::uint8_t> out_buf) const noexcept {
    return AsRef().WriteWire(out_buf);
  }

  [[nodiscard]] Result<void> QuestionPush(std::string_view qname, DnsType qtype, DnsClass qclass = DnsClass::IN) noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) {
      return std::unexpected(detail::MakeInvalidArgErrorSlow());
    }
    if (const auto rejected = detail::RejectDnsName(qname)) return std::unexpected(*rejected);
    const auto name_buf = detail::ToNullTerminatedName<256>(qname);
    if (uarch::flow::unlikely(!name_buf.has_value())) {
      return std::unexpected(detail::MakeBadNameErrorSlow());
    }
    const ares_status_t status =
        ares_dns_record_query_add(rec_, name_buf->data(), static_cast<ares_dns_rec_type_t>(std::to_underlying(qtype)),
                                  static_cast<ares_dns_class_t>(std::to_underlying(qclass)));
    if (uarch::flow::unlikely(status != ARES_SUCCESS)) {
      return std::unexpected(detail::MakeAresErrorSlow(std::to_underlying(status)));
    }
    return {};
  }

  /** @brief Appends an unpopulated resource record entry to `section`.
   *  @warning The returned `ares_dns_rr_t*` is borrowed from `DnsRecord` and may be
   *           invalidated by subsequent calls to `RrAdd` or `AddRr` on the same section.
   */
  [[nodiscard]] Result<ares_dns_rr_t*> RrAdd(RecordSection section, std::string_view name, DnsType rtype,
                                             DnsClass rclass = DnsClass::IN, std::uint32_t ttl = 0) noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr)) {
      return std::unexpected(detail::MakeInvalidArgErrorSlow());
    }
    if (const auto rejected = detail::RejectDnsName(name)) return std::unexpected(*rejected);
    const auto name_buf = detail::ToNullTerminatedName<256>(name);
    if (uarch::flow::unlikely(!name_buf.has_value())) {
      return std::unexpected(detail::MakeBadNameErrorSlow());
    }
    ares_dns_rr_t* rr_out = nullptr;
    const ares_status_t status =
        ares_dns_record_rr_add(&rr_out, rec_, static_cast<ares_dns_section_t>(std::to_underlying(section)), name_buf->data(),
                               static_cast<ares_dns_rec_type_t>(std::to_underlying(rtype)),
                               static_cast<ares_dns_class_t>(std::to_underlying(rclass)), static_cast<unsigned int>(ttl));
    if (uarch::flow::unlikely(status != ARES_SUCCESS || rr_out == nullptr)) {
      return std::unexpected(detail::MakeAresErrorSlow(std::to_underlying(status)));
    }
    return rr_out;
  }

  /** @brief Atomically validates and appends a typed resource record to `section`.
   *  All length and address fields in `rec` are validated BEFORE modifying `DnsRecord`;
   *  if any c-ares setter fails, the newly created RR is rolled back via `ares_dns_record_rr_del`.
   *  @warning The returned `ares_dns_rr_t*` is borrowed from `DnsRecord` and may be
   *           invalidated by subsequent calls to `RrAdd` or `AddRr` on the same section.
   */
  template <DnsRecordStruct RrT>
  [[nodiscard]] Result<ares_dns_rr_t*> AddRr(RecordSection section, std::string_view name, const RrT& rec,
                                             DnsClass rclass = DnsClass::IN) noexcept {
    if (uarch::flow::unlikely(rec_ == nullptr || !detail::ValidateRecordInput(rec))) {
      return std::unexpected(detail::MakeInvalidArgErrorSlow());
    }
    if (const auto rejected = detail::RejectDnsName(name)) return std::unexpected(*rejected);
    const std::size_t new_idx = RrCount(section);
    auto rr_res = RrAdd(section, name, RrT::kDnsType, rclass, rec.ttl);
    if (uarch::flow::unlikely(!rr_res)) {
      return rr_res;
    }
    return detail::PopulateAndFinalizeRr(rec_, section, new_idx, *rr_res, rec);
  }

  [[nodiscard]] constexpr bool IsValid() const noexcept { return rec_ != nullptr; }
  [[nodiscard]] explicit constexpr operator bool() const noexcept { return IsValid(); }
  [[nodiscard]] constexpr DnsRecordRef AsRef() const noexcept { return DnsRecordRef(rec_); }
  [[nodiscard]] constexpr operator DnsRecordRef() const noexcept { return AsRef(); }
  [[nodiscard]] constexpr ares_dns_record_t* Raw() noexcept { return rec_; }
  [[nodiscard]] constexpr const ares_dns_record_t* Raw() const noexcept { return rec_; }

  [[nodiscard]] std::uint16_t Id() const noexcept { return AsRef().Id(); }
  [[nodiscard]] DnsFlags Flags() const noexcept { return AsRef().Flags(); }
  [[nodiscard]] DnsOpcode Opcode() const noexcept { return AsRef().Opcode(); }
  [[nodiscard]] DnsRcode Rcode() const noexcept { return AsRef().Rcode(); }
  [[nodiscard]] std::size_t QuestionCount() const noexcept { return AsRef().QuestionCount(); }
  [[nodiscard]] Result<QuestionItem> QuestionAt(std::size_t idx) const noexcept { return AsRef().QuestionAt(idx); }
  [[nodiscard]] std::size_t RrCount(RecordSection section) const noexcept { return AsRef().RrCount(section); }
  [[nodiscard]] const ares_dns_rr_t* RrRawAt(RecordSection section, std::size_t idx) const noexcept {
    return AsRef().RrRawAt(section, idx);
  }
  template <typename RrT>
  [[nodiscard]] Result<RrT> ExtractRrAt(RecordSection section, std::size_t idx) const noexcept {
    return AsRef().ExtractRrAt<RrT>(section, idx);
  }
  [[nodiscard]] Result<RecordItem> ExtractRecordItemAt(RecordSection section, std::size_t idx) const noexcept {
    return AsRef().ExtractRecordItemAt(section, idx);
  }
  [[nodiscard]] Result<DnsRecord> ToOwned() const noexcept { return AsRef().ToOwned(); }

 private:
  ares_dns_record_t* rec_{nullptr};
};

inline Result<DnsRecord> DnsRecordRef::ToOwned() const noexcept {
  if (uarch::flow::unlikely(rec_ == nullptr)) {
    return std::unexpected(detail::MakeInvalidArgErrorSlow());
  }
  ares_dns_record_t* dup = ares_dns_record_duplicate(rec_);
  if (uarch::flow::unlikely(dup == nullptr)) {
    return std::unexpected(Error::CapacityExhausted());
  }
  return DnsRecord(dup);
}

}  // namespace cares
