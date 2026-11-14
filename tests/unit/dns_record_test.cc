#include <ares.h>

#include <algorithm>
#include <array>
#include <cares/record/dns_record.hpp>
#include <cares/record/record_extract.hpp>
#include <cares/record/record_rr.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <utility>

namespace cares {
namespace {

template <std::size_t N>
[[nodiscard]] constexpr std::array<char, N> MakeNullTerminatedFilled(char fill_ch) noexcept {
  std::array<char, N> out{};
  for (std::size_t i = 0; i + 1 < N; ++i) {
    out[i] = fill_ch;
  }
  out[N - 1] = '\0';
  return out;
}

// A moved-from record must not share its c-ares handle with the destination.
[[nodiscard]] bool QueryCreateMoveAndToOwned() noexcept {
  auto query_res =
      DnsRecord::CreateQuery("db.internal.example.org", DnsType::AAAA, DnsClass::IN, 0xCAFE, DnsFlags::Rd | DnsFlags::Ad);
  if (!query_res) return false;

  DnsRecord moved_ctor(std::move(*query_res));
  if (query_res->IsValid() || !moved_ctor.IsValid()) return false;

  DnsRecord moved_assign{};
  moved_assign = std::move(moved_ctor);
  // NOLINTNEXTLINE(bugprone-use-after-move) -- Moved-from owning records remain inspectable.
  if (moved_ctor.IsValid() || !moved_assign.IsValid()) return false;

  // Self-reset with the currently owned pointer must be a no-op rather than destroying the handle.
  moved_assign.Reset(moved_assign.Raw());
  if (!moved_assign.IsValid() || moved_assign.Id() != 0xCAFE) return false;

  const DnsRecordRef ref = moved_assign.AsRef();
  if (!ref.IsValid() || ref.Id() != 0xCAFE || !HasFlag(ref.Flags(), DnsFlags::Rd) || !HasFlag(ref.Flags(), DnsFlags::Ad) ||
      ref.Opcode() != DnsOpcode::Query || ref.Rcode() != DnsRcode::NoError) {
    return false;
  }
  if (ref.QuestionCount() != 1) return false;
  auto q0 = ref.QuestionAt(0);
  if (!q0 || q0->Name() != "db.internal.example.org" || q0->qtype != DnsType::AAAA || q0->qclass != DnsClass::IN) {
    return false;
  }

  // Duplicate via ToOwned and destroy original to prove deep ownership independence.
  auto owned_copy = ref.ToOwned();
  if (!owned_copy || !owned_copy->IsValid()) return false;
  moved_assign.Reset();
  if (moved_assign.IsValid()) return false;

  auto copy_q0 = owned_copy->QuestionAt(0);
  if (!copy_q0 || copy_q0->Name() != "db.internal.example.org" || owned_copy->Id() != 0xCAFE) {
    return false;
  }
  return true;
}

// Null views, short buffers, truncated wire, and the 255-octet QNAME boundary.
[[nodiscard]] bool BoundaryAndNameGuards() noexcept {
  constexpr DnsRecordRef kNullRef{};
  if (kNullRef.IsValid() || kNullRef.Id() != 0 || kNullRef.Flags() != DnsFlags::None || kNullRef.QuestionCount() != 0 ||
      kNullRef.RrCount(RecordSection::Answer) != 0 || kNullRef.RrRawAt(RecordSection::Answer, 0) != nullptr) {
    return false;
  }
  if (kNullRef.QuestionAt(0) || kNullRef.ExtractRrAt<ARecord>(RecordSection::Answer, 0) || kNullRef.ToOwned()) {
    return false;
  }

  auto pkt_res = DnsRecord::CreateQuery("a.example.com", DnsType::A, DnsClass::IN, 0x0042);
  if (!pkt_res) return false;
  if (!pkt_res->AddRr(RecordSection::Answer, "a.example.com", ARecord{.addr = IpAddress::FromV4({127, 0, 0, 1}), .ttl = 30})) {
    return false;
  }

  // Buffer smaller than serialized packet size must fail with ResourceExhausted.
  std::array<std::byte, 4> tiny_buf{};
  auto small_write = pkt_res->WriteWire(tiny_buf);
  if (small_write || small_write.error().category != ErrorCategory::ResourceExhausted) {
    return false;
  }

  // Empty and truncated wire inputs must fail ParseWire.
  std::span<const std::byte> empty_wire{};
  if (DnsRecord::ParseWire(empty_wire)) return false;

  constexpr std::array<std::uint8_t, 5> kTruncatedWire{0x00, 0x42, 0x01, 0x00, 0x00};
  if (DnsRecord::ParseWire(kTruncatedWire)) return false;

  // 63+63+63+61 label bytes and three dots: 253 presentation characters, 255 wire octets.
  std::array<char, 253> name_253_buf{};
  name_253_buf.fill('a');
  name_253_buf[63] = '.';
  name_253_buf[127] = '.';
  name_253_buf[191] = '.';
  const std::string_view name_253(name_253_buf.data(), name_253_buf.size());

  auto q253_pkt = DnsRecord::CreateQuery(name_253, DnsType::A, DnsClass::IN, 0x0253);
  if (!q253_pkt) return false;
  auto q253_item = q253_pkt->QuestionAt(0);
  if (!q253_item || q253_item->Name() != name_253) return false;
  if (!q253_pkt->AddRr(RecordSection::Answer, name_253, ARecord{.addr = IpAddress::FromV4({10, 0, 0, 1}), .ttl = 60})) {
    return false;
  }
  auto rr253_item = q253_pkt->ExtractRecordItemAt(RecordSection::Answer, 0);
  if (!rr253_item || rr253_item->Name() != name_253) return false;

  // Four 63-octet labels are 255 presentation characters and 257 wire octets.
  std::array<char, 255> name_255_buf{};
  name_255_buf.fill('a');
  name_255_buf[63] = '.';
  name_255_buf[127] = '.';
  name_255_buf[191] = '.';
  const std::string_view name_255(name_255_buf.data(), name_255_buf.size());
  auto bad_wire = DnsRecord::CreateQuery(name_255, DnsType::A);
  if (bad_wire || bad_wire.error() != Error::BadName()) return false;
  auto bad_push = q253_pkt->QuestionPush(name_255, DnsType::A);
  if (bad_push || bad_push.error() != Error::BadName() || q253_pkt->QuestionCount() != 1) return false;
  auto bad_rr_wire = q253_pkt->RrAdd(RecordSection::Answer, name_255, DnsType::A);
  if (bad_rr_wire || bad_rr_wire.error() != Error::BadName() || q253_pkt->RrCount(RecordSection::Answer) != 1) {
    return false;
  }
  auto bad_add_wire =
      q253_pkt->AddRr(RecordSection::Answer, name_255, ARecord{.addr = IpAddress::FromV4({10, 0, 0, 2}), .ttl = 1});
  if (bad_add_wire || bad_add_wire.error() != Error::BadName() || q253_pkt->RrCount(RecordSection::Answer) != 1) {
    return false;
  }

  // 63+63+63+62 label bytes encode to 256 wire octets.
  std::array<char, 254> name_254_buf{};
  name_254_buf.fill('c');
  name_254_buf[63] = '.';
  name_254_buf[127] = '.';
  name_254_buf[191] = '.';
  const std::string_view name_254(name_254_buf.data(), name_254_buf.size());
  auto bad_256_wire = DnsRecord::CreateQuery(name_254, DnsType::A);
  if (bad_256_wire || bad_256_wire.error() != Error::BadName()) return false;

  std::array<char, 11> nul_name{'a', '.', 'e', 'x', 'a', '\0', 'p', 'l', 'e', '.', 'x'};
  const std::string_view nul_view(nul_name.data(), nul_name.size());
  auto bad_nul = DnsRecord::CreateQuery(nul_view, DnsType::A);
  auto bad_nul_push = q253_pkt->QuestionPush(nul_view, DnsType::A);
  if (bad_nul || bad_nul.error() != Error::BadName() || bad_nul_push || bad_nul_push.error() != Error::BadName()) {
    return false;
  }

  // Exact 256-byte name must be rejected with BadName across CreateQuery, QuestionPush, RrAdd, and AddRr.
  std::array<char, 256> name_256_buf{};
  name_256_buf.fill('b');
  name_256_buf[63] = '.';
  name_256_buf[127] = '.';
  name_256_buf[191] = '.';
  const std::string_view name_256(name_256_buf.data(), name_256_buf.size());

  auto bad_create = DnsRecord::CreateQuery(name_256, DnsType::A);
  if (bad_create || bad_create.error().AsAresStatus() != AresStatus::BadName) return false;

  auto bad_q = pkt_res->QuestionPush(name_256, DnsType::A);
  if (bad_q || bad_q.error().AsAresStatus() != AresStatus::BadName || pkt_res->QuestionCount() != 1) {
    return false;
  }

  auto bad_rr = pkt_res->RrAdd(RecordSection::Answer, name_256, DnsType::A, DnsClass::IN, 10);
  if (bad_rr || bad_rr.error().AsAresStatus() != AresStatus::BadName || pkt_res->RrCount(RecordSection::Answer) != 1) {
    return false;
  }

  auto bad_add_rr =
      pkt_res->AddRr(RecordSection::Answer, name_256, ARecord{.addr = IpAddress::FromV4({127, 0, 0, 2}), .ttl = 10});
  if (bad_add_rr || bad_add_rr.error().AsAresStatus() != AresStatus::BadName || pkt_res->RrCount(RecordSection::Answer) != 1) {
    return false;
  }

  return true;
}

// Bad fields are rejected before c-ares mutation, and a failed populate rolls the RR back.
[[nodiscard]] bool PreValidationAndAtomicRollback() noexcept {
  auto pkt_res = DnsRecord::CreateQuery("guard.example.com", DnsType::A, DnsClass::IN, 0x0099);
  if (!pkt_res) return false;
  DnsRecord& pkt = *pkt_res;

  if (!pkt.AddRr(RecordSection::Answer, "guard.example.com", ARecord{.addr = IpAddress::FromV4({192, 0, 2, 10}), .ttl = 60})) {
    return false;
  }
  const std::size_t baseline_count = pkt.RrCount(RecordSection::Answer);
  if (baseline_count != 1) return false;

  std::array<std::byte, 512> wire_before{};
  const auto wire_before_len = pkt.WriteWire(wire_before);
  if (!wire_before_len || *wire_before_len == 0) return false;

  auto expect_invalid = [&](const auto& bad_rec) noexcept -> bool {
    auto res = pkt.AddRr(RecordSection::Answer, "guard.example.com", bad_rec);
    return !res && res.error().category == ErrorCategory::InvalidInput && pkt.RrCount(RecordSection::Answer) == baseline_count;
  };

  // Out-of-bounds length fields and mismatched IP families must be rejected before mutating c-ares state.
  if (!expect_invalid(ARecord{.addr = IpAddress::FromV6({}), .ttl = 60})) return false;
  if (!expect_invalid(AaaaRecord{.addr = IpAddress::FromV4({1, 2, 3, 4}), .ttl = 60})) return false;
  if (!expect_invalid(CnameRecord{.len = 256, .ttl = 60})) return false;
  if (!expect_invalid(MxRecord{.preference = 10, .len = 256, .ttl = 60})) return false;
  std::array<char, 65536> huge{};
  huge.fill('x');
  auto huge_text = TxtBuffer::Copy(std::string_view{huge.data(), huge.size()});
  if (!huge_text) return false;
  if (!expect_invalid(TxtRecord{.text = std::move(*huge_text), .ttl = 60})) return false;
  if (!expect_invalid(SrvRecord{.priority = 1, .weight = 1, .port = 80, .len = 256, .ttl = 60})) {
    return false;
  }
  if (!expect_invalid(PtrRecord{.len = 256, .ttl = 60})) return false;
  if (!expect_invalid(SoaRecord{.mname_len = 256, .rname_len = 10, .ttl = 60})) return false;
  if (!expect_invalid(SoaRecord{.mname_len = 10, .rname_len = 256, .ttl = 60})) return false;
  if (!expect_invalid(NsRecord{.len = 256, .ttl = 60})) return false;
  if (!expect_invalid(NaptrRecord{.flags_len = 64, .ttl = 60})) return false;
  if (!expect_invalid(NaptrRecord{.service_len = 128, .ttl = 60})) return false;
  if (!expect_invalid(NaptrRecord{.regexp_len = 128, .ttl = 60})) return false;
  if (!expect_invalid(NaptrRecord{.replacement_len = 256, .ttl = 60})) return false;
  if (!expect_invalid(CaaRecord{.tag_len = 0, .value_len = 4, .ttl = 60})) return false;
  if (!expect_invalid(CaaRecord{.tag_len = 64, .value_len = 4, .ttl = 60})) return false;
  if (!expect_invalid(CaaRecord{.tag = {'i', 's', 's', 'u', 'e'}, .tag_len = 5, .value_len = 257, .ttl = 60})) {
    return false;
  }
  if (!expect_invalid(UriRecord{.target_len = 256, .ttl = 60})) return false;
  if (!expect_invalid(TlsaRecord{.data_len = 257, .ttl = 60})) return false;
  if (!expect_invalid(SvcbRecord{.target_len = 256, .ttl = 60})) return false;
  if (!expect_invalid(HttpsRecord{.target_len = 256, .ttl = 60})) return false;
  if (!expect_invalid(HinfoRecord{.cpu_len = 128, .os_len = 4, .ttl = 60})) return false;
  if (!expect_invalid(HinfoRecord{.cpu_len = 4, .os_len = 128, .ttl = 60})) return false;

  // Post-RrAdd rollback invariant: when PopulateTypedRr fails after RrAdd has appended an entry,
  // PopulateAndFinalizeRr must delete the half-built RR and preserve RrCount and wire bytes.
  const std::size_t new_idx = pkt.RrCount(RecordSection::Answer);
  auto raw_rr = pkt.RrAdd(RecordSection::Answer, "rollback.example.com", DnsType::TXT, DnsClass::IN, 60);
  if (!raw_rr || pkt.RrCount(RecordSection::Answer) != baseline_count + 1) return false;

  auto rollback_res = detail::PopulateAndFinalizeRr<ARecord>(pkt.Raw(), RecordSection::Answer, new_idx, *raw_rr,
                                                             ARecord{.addr = IpAddress::FromV4({192, 0, 2, 99}), .ttl = 60});
  if (rollback_res || rollback_res.error().AsAresStatus() != AresStatus::FormErr) return false;
  if (pkt.RrCount(RecordSection::Answer) != baseline_count) return false;

  std::array<std::byte, 512> wire_after{};
  const auto wire_after_len = pkt.WriteWire(wire_after);
  if (!wire_after_len || *wire_after_len != *wire_before_len) return false;
  if (std::memcmp(wire_before.data(), wire_after.data(), *wire_before_len) != 0) return false;

  return true;
}

// Fixed-capacity fields reject c-ares values that do not fit. TXT is bounded by the RR size, not 512.
[[nodiscard]] bool ExtractionOverflowBoundaries() noexcept {
  auto pkt_res = DnsRecord::CreateQuery("extract.example.com", DnsType::ANY, DnsClass::IN, 0x0100);
  if (!pkt_res) return false;
  DnsRecord& pkt = *pkt_res;

  // 1. TXT concatenates character-strings through 512 and through a 1500-octet SPF/DKIM value.
  std::array<unsigned char, 256> chunk_256{};
  chunk_256.fill('t');
  std::array<unsigned char, 250> chunk_250{};
  chunk_250.fill('k');

  auto txt_512_rr = pkt.RrAdd(RecordSection::Answer, "txt512.example.com", DnsType::TXT, DnsClass::IN, 60);
  if (!txt_512_rr) return false;
  if (ares_dns_rr_add_abin(*txt_512_rr, ARES_RR_TXT_DATA, chunk_256.data(), chunk_256.size()) != ARES_SUCCESS ||
      ares_dns_rr_add_abin(*txt_512_rr, ARES_RR_TXT_DATA, chunk_256.data(), chunk_256.size()) != ARES_SUCCESS) {
    return false;
  }
  auto txt_512_out = pkt.ExtractRrAt<TxtRecord>(RecordSection::Answer, 0);
  if (!txt_512_out || txt_512_out->text.size() != 512 || txt_512_out->View().size() != 512) return false;

  auto txt_1500_rr = pkt.RrAdd(RecordSection::Answer, "txt1500.example.com", DnsType::TXT, DnsClass::IN, 60);
  if (!txt_1500_rr) return false;
  for (int n = 0; n < 6; ++n) {
    if (ares_dns_rr_add_abin(*txt_1500_rr, ARES_RR_TXT_DATA, chunk_250.data(), chunk_250.size()) != ARES_SUCCESS) return false;
  }
  auto txt_1500_out = pkt.ExtractRrAt<TxtRecord>(RecordSection::Answer, 1);
  if (!txt_1500_out || txt_1500_out->text.size() != 1500 || txt_1500_out->View().size() != 1500) return false;
  if (txt_1500_out->text.front() != 'k' || txt_1500_out->text.back() != 'k') return false;

  // 2. CAA overflow guards: value > 256 (257 bytes) and tag >= 64 (64 chars) rejected with Ebadresp.
  std::array<unsigned char, 257> bin_257{};
  bin_257.fill(0x41);
  auto caa_val_rr = pkt.RrAdd(RecordSection::Answer, "caa1.example.com", DnsType::CAA, DnsClass::IN, 60);
  if (!caa_val_rr) return false;
  if (ares_dns_rr_set_u8(*caa_val_rr, ARES_RR_CAA_CRITICAL, 0) != ARES_SUCCESS ||
      ares_dns_rr_set_str(*caa_val_rr, ARES_RR_CAA_TAG, "issue") != ARES_SUCCESS ||
      ares_dns_rr_set_bin(*caa_val_rr, ARES_RR_CAA_VALUE, bin_257.data(), bin_257.size()) != ARES_SUCCESS) {
    return false;
  }
  auto caa_val_out = pkt.ExtractRrAt<CaaRecord>(RecordSection::Answer, 2);
  if (caa_val_out || caa_val_out.error().AsAresStatus() != AresStatus::BadResp) return false;

  constexpr auto kStr64 = MakeNullTerminatedFilled<65>('c');
  auto caa_tag_rr = pkt.RrAdd(RecordSection::Answer, "caa2.example.com", DnsType::CAA, DnsClass::IN, 60);
  if (!caa_tag_rr) return false;
  if (ares_dns_rr_set_u8(*caa_tag_rr, ARES_RR_CAA_CRITICAL, 0) != ARES_SUCCESS ||
      ares_dns_rr_set_str(*caa_tag_rr, ARES_RR_CAA_TAG, kStr64.data()) != ARES_SUCCESS ||
      ares_dns_rr_set_bin(*caa_tag_rr, ARES_RR_CAA_VALUE, chunk_256.data(), 8) != ARES_SUCCESS) {
    return false;
  }
  auto caa_tag_out = pkt.ExtractRrAt<CaaRecord>(RecordSection::Answer, 3);
  if (caa_tag_out || caa_tag_out.error().AsAresStatus() != AresStatus::BadResp) return false;

  // 3. TLSA overflow guard: 257-byte certificate association data rejected with Ebadresp.
  auto tlsa_rr = pkt.RrAdd(RecordSection::Answer, "_443._tcp.example.com", DnsType::TLSA, DnsClass::IN, 60);
  if (!tlsa_rr) return false;
  if (ares_dns_rr_set_bin(*tlsa_rr, ARES_RR_TLSA_DATA, bin_257.data(), bin_257.size()) != ARES_SUCCESS) {
    return false;
  }
  auto tlsa_out = pkt.ExtractRrAt<TlsaRecord>(RecordSection::Answer, 4);
  if (tlsa_out || tlsa_out.error().AsAresStatus() != AresStatus::BadResp) return false;

  // 4. NAPTR overflow guards: flags >= 64, service >= 128, regexp >= 128, replacement >= 256.
  constexpr auto kStr128 = MakeNullTerminatedFilled<129>('n');
  constexpr auto kStr256 = MakeNullTerminatedFilled<257>('r');

  auto check_naptr_overflow = [&](const char* flags, const char* svc, const char* rx, const char* repl) noexcept -> bool {
    const std::size_t idx = pkt.RrCount(RecordSection::Answer);
    auto rr = pkt.RrAdd(RecordSection::Answer, "naptr.example.com", DnsType::NAPTR, DnsClass::IN, 60);
    if (!rr) return false;
    if (ares_dns_rr_set_str(*rr, ARES_RR_NAPTR_FLAGS, flags) != ARES_SUCCESS ||
        ares_dns_rr_set_str(*rr, ARES_RR_NAPTR_SERVICES, svc) != ARES_SUCCESS ||
        ares_dns_rr_set_str(*rr, ARES_RR_NAPTR_REGEXP, rx) != ARES_SUCCESS ||
        ares_dns_rr_set_str(*rr, ARES_RR_NAPTR_REPLACEMENT, repl) != ARES_SUCCESS) {
      return false;
    }
    auto out = pkt.ExtractRrAt<NaptrRecord>(RecordSection::Answer, idx);
    return !out && out.error().AsAresStatus() == AresStatus::BadResp;
  };

  if (!check_naptr_overflow(kStr64.data(), "SIP+D2U", "", "_sip.example.com")) return false;
  if (!check_naptr_overflow("s", kStr128.data(), "", "_sip.example.com")) return false;
  if (!check_naptr_overflow("s", "SIP+D2U", kStr128.data(), "_sip.example.com")) return false;
  if (!check_naptr_overflow("s", "SIP+D2U", "", kStr256.data())) return false;

  // 5. HINFO overflow guards: cpu >= 128 and os >= 128 rejected with Ebadresp.
  auto hinfo_cpu_rr = pkt.RrAdd(RecordSection::Answer, "hinfo1.example.com", DnsType::HINFO, DnsClass::IN, 60);
  if (!hinfo_cpu_rr) return false;
  if (ares_dns_rr_set_str(*hinfo_cpu_rr, ARES_RR_HINFO_CPU, kStr128.data()) != ARES_SUCCESS ||
      ares_dns_rr_set_str(*hinfo_cpu_rr, ARES_RR_HINFO_OS, "LINUX") != ARES_SUCCESS) {
    return false;
  }
  auto hinfo_cpu_out = pkt.ExtractRrAt<HinfoRecord>(RecordSection::Answer, pkt.RrCount(RecordSection::Answer) - 1);
  if (hinfo_cpu_out || hinfo_cpu_out.error().AsAresStatus() != AresStatus::BadResp) return false;

  auto hinfo_os_rr = pkt.RrAdd(RecordSection::Answer, "hinfo2.example.com", DnsType::HINFO, DnsClass::IN, 60);
  if (!hinfo_os_rr) return false;
  if (ares_dns_rr_set_str(*hinfo_os_rr, ARES_RR_HINFO_CPU, "X86-64") != ARES_SUCCESS ||
      ares_dns_rr_set_str(*hinfo_os_rr, ARES_RR_HINFO_OS, kStr128.data()) != ARES_SUCCESS) {
    return false;
  }
  auto hinfo_os_out = pkt.ExtractRrAt<HinfoRecord>(RecordSection::Answer, pkt.RrCount(RecordSection::Answer) - 1);
  if (hinfo_os_out || hinfo_os_out.error().AsAresStatus() != AresStatus::BadResp) return false;

  // 6. Name-type fields >= 256 chars (CNAME and MX exchange) rejected with Ebadresp.
  auto cname_rr = pkt.RrAdd(RecordSection::Answer, "cname.example.com", DnsType::CNAME, DnsClass::IN, 60);
  if (!cname_rr) return false;
  if (ares_dns_rr_set_str(*cname_rr, ARES_RR_CNAME_CNAME, kStr256.data()) != ARES_SUCCESS) {
    return false;
  }
  auto cname_out = pkt.ExtractRrAt<CnameRecord>(RecordSection::Answer, pkt.RrCount(RecordSection::Answer) - 1);
  if (cname_out || cname_out.error().AsAresStatus() != AresStatus::BadResp) return false;

  auto mx_rr = pkt.RrAdd(RecordSection::Answer, "mx.example.com", DnsType::MX, DnsClass::IN, 60);
  if (!mx_rr) return false;
  if (ares_dns_rr_set_u16(*mx_rr, ARES_RR_MX_PREFERENCE, 10) != ARES_SUCCESS ||
      ares_dns_rr_set_str(*mx_rr, ARES_RR_MX_EXCHANGE, kStr256.data()) != ARES_SUCCESS) {
    return false;
  }
  auto mx_out = pkt.ExtractRrAt<MxRecord>(RecordSection::Answer, pkt.RrCount(RecordSection::Answer) - 1);
  if (mx_out || mx_out.error().AsAresStatus() != AresStatus::BadResp) return false;

  // Insert path chunks a TXT above one 255-octet character-string.
  std::array<char, 300> wide_bytes{};
  wide_bytes.fill('w');
  auto wide_text = TxtBuffer::Copy(std::string_view{wide_bytes.data(), wide_bytes.size()});
  if (!wide_text) return false;
  const TxtRecord wide{.text = std::move(*wide_text), .ttl = 30};
  if (!pkt.AddRr(RecordSection::Answer, "txtwide.example.com", wide)) return false;
  auto wide_out = pkt.ExtractRrAt<TxtRecord>(RecordSection::Answer, pkt.RrCount(RecordSection::Answer) - 1);
  if (!wide_out || wide_out->text != wide.text) return false;

  return true;
}

struct[[= notes::Answer]][[= notes::Type(DnsType::A)]] ProbeA {
  IpAddress addr[[= notes::Field(ARES_RR_A_ADDR)]];
  std::uint32_t ttl[[= notes::Ttl]];
};

// An RRSIG beside an A must not hide the address or fail the whole answer section.
[[nodiscard]] bool UnknownRrDoesNotHideAddress() noexcept {
  constexpr std::array<unsigned char, 61> kWire{{
      0x00, 0x01, 0x84, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
      'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
      0x2e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00,
      0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x0a,
  }};
  auto parsed = DnsRecord::ParseWire(std::span<const unsigned char>{kWire});
  if (!parsed) return false;
  const DnsRecordRef view = parsed->AsRef();
  if (view.RrCount(RecordSection::Answer) != 2) return false;
  const auto expect = IpAddress::FromV4({192, 0, 2, 10});
  bool saw_a = false;
  for (std::size_t i = 0; i < view.RrCount(RecordSection::Answer); ++i) {
    auto item = view.ExtractRrAt<RecordItem>(RecordSection::Answer, i);
    if (!item) {
      if (!item.error().IsNotFound()) return false;
      continue;
    }
    if (item->rtype != DnsType::A) return false;
    const auto* addr = std::get_if<ARecord>(&item->data);
    if (addr == nullptr || addr->addr != expect) return false;
    saw_a = true;
  }
  if (!saw_a) return false;
  auto exact = view.ExtractRrAt<ARecord>(RecordSection::Answer, 1);
  if (!exact || exact->ttl != 60 || exact->addr != expect) return false;
  auto mismatch = view.ExtractRrAt<ARecord>(RecordSection::Answer, 0);
  if (mismatch || mismatch.error().AsAresStatus() != AresStatus::BadResp) return false;
  auto reflected = ExtractRecord<ProbeA>(view);
  if (!reflected || reflected->ttl != 60 || reflected->addr != expect) return false;

  std::array<unsigned char, sizeof(kWire)> ds_wire{{}};
  std::memcpy(ds_wire.data(), kWire.data(), sizeof(kWire));
  for (unsigned char& byte : ds_wire) {
    if (byte == 0x2e) {
      byte = 0x2b;
      break;
    }
  }
  auto ds_parsed = DnsRecord::ParseWire(std::span<const unsigned char>{ds_wire});
  if (!ds_parsed) return false;
  auto past_ds = ds_parsed->ExtractRrAt<ARecord>(RecordSection::Answer, 1);
  return past_ds && past_ds->ttl == 60 && past_ds->addr == expect;
}

[[nodiscard]] bool TxtWireBound() noexcept {
  auto pkt = DnsRecord::CreateQuery("txtbound.example", DnsType::TXT, DnsClass::IN, 1);
  if (!pkt) return false;
  std::array<char, 65280> raw{};
  raw.fill('y');
  auto fit = TxtBuffer::Copy(std::string_view{raw.data(), 65279});
  if (!fit) return false;
  if (!pkt->AddRr(RecordSection::Answer, "txtbound.example", TxtRecord{.text = std::move(*fit), .ttl = 30})) return false;
  auto over = TxtBuffer::Copy(std::string_view{raw.data(), raw.size()});
  if (!over) return false;
  auto rejected = pkt->AddRr(RecordSection::Answer, "txtbound.example", TxtRecord{.text = std::move(*over), .ttl = 30});
  return !rejected && rejected.error().category == ErrorCategory::InvalidInput;
}

}  // namespace
}  // namespace cares

int main() {
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) return 1;
  const bool ok = cares::QueryCreateMoveAndToOwned() && cares::BoundaryAndNameGuards() &&
                  cares::PreValidationAndAtomicRollback() && cares::ExtractionOverflowBoundaries() &&
                  cares::UnknownRrDoesNotHideAddress() && cares::TxtWireBound();
  ares_library_cleanup();
  return ok ? 0 : 1;
}
