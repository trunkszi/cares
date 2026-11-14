#include <array>
#include <cares/query_table/query_table.hpp>
#include <cstdio>
#include <source_location>
#include <span>
#include <string_view>

namespace {

int g_failed = 0;

inline void Check(bool ok, const std::source_location where = std::source_location::current()) {
  if (ok) return;
  std::fprintf(stderr, "FAIL %s:%u\n", where.file_name(), where.line());
  ++g_failed;
}

struct Buf {
  std::array<std::byte, 512> data{};
  std::size_t len{0};
  void Byte(unsigned value) { data[len++] = std::byte{static_cast<unsigned char>(value)}; }
  void U16(unsigned value) {
    Byte(value >> 8u);
    Byte(value & 0xFFu);
  }
  void Header(unsigned qdcount) {
    U16(0x1234);
    U16(0);
    U16(qdcount);
    U16(0);
    U16(0);
    U16(0);
  }
  void Chars(std::string_view text) {
    for (char ch : text) Byte(static_cast<unsigned char>(ch));
  }
  [[nodiscard]] std::span<const std::byte> Span() const { return {data.data(), len}; }
};

struct[[= cares::notes::QueryRoute("example.com", cares::DnsType::A)]] WwwA {};
struct[[= cares::notes::QueryRoute("example.com", cares::DnsType::MX)]] WwwMx {};
struct[[= cares::notes::QueryRoute("www.example.com.", cares::DnsType::AAAA, cares::DnsClass::IN)]] WwwAaaa {};

struct Hit {
  int id{-1};
  template <typename Route>
  constexpr void operator()(const cares::FirstQuestionWire &) noexcept {
    if constexpr (std::is_same_v<Route, WwwA>) id = 1;
    if constexpr (std::is_same_v<Route, WwwMx>) id = 2;
    if constexpr (std::is_same_v<Route, WwwAaaa>) id = 3;
  }
};

void SwarMatchesScalar() {
  for (int value = 0; value < 256; ++value) {
    const auto scalar = cares::query_detail::AsciiLower(static_cast<unsigned char>(value));
    for (int shift = 0; shift < 8; ++shift) {
      const std::uint64_t word = static_cast<std::uint64_t>(value) << static_cast<unsigned>(shift * 8);
      const auto folded = cares::query_detail::SwarAsciiLower(word);
      const auto got = static_cast<unsigned char>((folded >> static_cast<unsigned>(shift * 8)) & 0xFFu);
      Check(got == scalar);
    }
  }
  const std::uint64_t mixed = 0x5A41006100415A41ULL;
  Check(cares::query_detail::SwarAsciiLower(mixed) == 0x7A61006100617A61ULL);
}

void EncodeAndCompare() {
  const auto encoded = cares::EncodeQname("Example.COM.");
  Check(encoded.ok == 1);
  Check(encoded.len == 13);
  Check(encoded.wire[0] == 7);
  Check(encoded.wire[1] == static_cast<unsigned char>('E'));
  const cares::DnsQnameWireView view{std::as_bytes(encoded.Wire())};
  Check(view.EqualsPresentation("example.com"));
  Check(view.EqualsPresentation("EXAMPLE.com."));
  Check(!view.EqualsPresentation("example.org"));
  Check(!view.EqualsPresentation(""));
  const auto root = cares::EncodeQname(".");
  Check(root.ok == 1 && root.len == 1 && root.wire[0] == 0);
  Check(cares::EncodeQname("example..com").ok == 0);
  Check(cares::EncodeQname(".example").ok == 0);
}

Buf ExampleQuery(unsigned qtype) {
  Buf packet;
  packet.Header(1);
  packet.Byte(7);
  packet.Chars("ExAmPle");
  packet.Byte(3);
  packet.Chars("com");
  packet.Byte(0);
  packet.U16(qtype);
  packet.U16(1);
  return packet;
}

void ParseAcceptsUncompressed() {
  const Buf packet = ExampleQuery(1);
  const auto parsed = cares::ParseFirstQuestionWire(packet.Span());
  Check(parsed.has_value());
  if (!parsed) return;
  Check(parsed->qtype == cares::DnsType::A);
  Check(parsed->qclass == cares::DnsClass::IN);
  Check(parsed->qname_wire.size() == 13);
  Check(std::to_integer<unsigned char>(parsed->qname_wire[1]) == static_cast<unsigned>('E'));
  cares::DnsQnameWireView view{parsed->qname_wire};
  Check(view.EqualsPresentation("example.com"));
}

void CompressionRejected() {
  Buf leading;
  leading.Header(1);
  leading.Byte(0xC0);
  leading.Byte(0x0C);
  leading.U16(1);
  leading.U16(1);
  const auto leading_parsed = cares::ParseFirstQuestionWire(leading.Span());
  Check(!leading_parsed.has_value());
  Check(leading_parsed.error() == cares::Error::BadName());

  Buf middle;
  middle.Header(1);
  middle.Byte(3);
  middle.Chars("www");
  middle.Byte(0xC0);
  middle.Byte(0x0C);
  middle.U16(1);
  middle.U16(1);
  const auto middle_parsed = cares::ParseFirstQuestionWire(middle.Span());
  Check(!middle_parsed.has_value());
  Check(middle_parsed.error() == cares::Error::BadName());

  Buf reserved40;
  reserved40.Header(1);
  reserved40.Byte(0x40);
  reserved40.U16(1);
  reserved40.U16(1);
  Check(cares::ParseFirstQuestionWire(reserved40.Span()).error() == cares::Error::BadName());

  Buf reserved80;
  reserved80.Header(1);
  reserved80.Byte(0x80);
  reserved80.U16(1);
  reserved80.U16(1);
  Check(cares::ParseFirstQuestionWire(reserved80.Span()).error() == cares::Error::BadName());
}

void PayloadHighBitKept() {
  Buf packet;
  packet.Header(1);
  packet.Byte(1);
  packet.Byte(0xC0);
  packet.Byte(0);
  packet.U16(1);
  packet.U16(1);
  const auto parsed = cares::ParseFirstQuestionWire(packet.Span());
  Check(parsed.has_value());
  if (!parsed) return;
  Check(parsed->qname_wire.size() == 3);
  Check(std::to_integer<unsigned char>(parsed->qname_wire[1]) == 0xC0);
}

void TruncationRejected() {
  Buf short_header;
  short_header.U16(1);
  Check(cares::ParseFirstQuestionWire(short_header.Span()).error() == cares::Error::BadResponse());

  Buf no_question;
  no_question.Header(0);
  Check(cares::ParseFirstQuestionWire(no_question.Span()).error() == cares::Error::BadResponse());

  Buf no_type;
  no_type.Header(1);
  no_type.Byte(0);
  Check(cares::ParseFirstQuestionWire(no_type.Span()).error() == cares::Error::BadResponse());

  Buf cut_label;
  cut_label.Header(1);
  cut_label.Byte(3);
  cut_label.Chars("ab");
  Check(cares::ParseFirstQuestionWire(cut_label.Span()).error() == cares::Error::BadName());
}

void DispatchHitsRoute() {
  using Table = cares::QueryTable<WwwA, WwwMx, WwwAaaa>;
  static_assert(Table::kRouteCount == 3);
  const Buf a_query = ExampleQuery(1);
  Hit a_hit;
  const auto a_result = Table::DispatchWireQuestion(a_query.Span(), a_hit);
  Check(a_result.has_value());
  Check(a_hit.id == 1);
  Check(a_result && *a_result == 0);

  const Buf mx_query = ExampleQuery(15);
  Hit mx_hit;
  const auto mx_result = Table::DispatchWireQuestion(mx_query.Span(), mx_hit);
  Check(mx_result.has_value());
  Check(mx_hit.id == 2);
  Check(mx_result && *mx_result == 1);

  Hit miss;
  const Buf ns_query = ExampleQuery(2);
  const auto miss_result = Table::DispatchWireQuestion(ns_query.Span(), miss);
  Check(!miss_result.has_value());
  Check(miss_result.error() == cares::Error::NotFound());
  Check(miss.id == -1);

  Buf compressed = ExampleQuery(1);
  compressed.data[12] = std::byte{0xC0};
  Hit ignored;
  const auto bad = Table::DispatchWireQuestion(compressed.Span(), ignored);
  Check(bad.error() == cares::Error::BadName());
  Check(ignored.id == -1);
}

void DispatchTrailingDot() {
  using Table = cares::QueryTable<WwwA, WwwMx, WwwAaaa>;
  Buf packet;
  packet.Header(1);
  packet.Byte(3);
  packet.Chars("WwW");
  packet.Byte(7);
  packet.Chars("example");
  packet.Byte(3);
  packet.Chars("com");
  packet.Byte(0);
  packet.U16(28);
  packet.U16(1);
  Hit hit;
  const auto result = Table::DispatchWireQuestion(packet.Span(), hit);
  Check(result.has_value());
  Check(hit.id == 3);
  Check(result.has_value() && *result == 2);
}

void RootAndLabel63() {
  Buf root;
  root.Header(1);
  root.Byte(0);
  root.U16(1);
  root.U16(1);
  const auto parsed = cares::ParseFirstQuestionWire(root.Span());
  Check(parsed.has_value());
  Check(parsed && parsed->qname_wire.size() == 1);

  Buf label;
  label.Header(1);
  label.Byte(63);
  for (int index = 0; index < 63; ++index) label.Byte(static_cast<unsigned>('a'));
  label.Byte(0);
  label.U16(1);
  label.U16(1);
  Check(cares::ParseFirstQuestionWire(label.Span()).has_value());
}

}  // namespace

int main() {
  SwarMatchesScalar();
  EncodeAndCompare();
  ParseAcceptsUncompressed();
  CompressionRejected();
  PayloadHighBitKept();
  TruncationRejected();
  DispatchHitsRoute();
  DispatchTrailingDot();
  RootAndLabel63();
  if (g_failed != 0) {
    std::fprintf(stderr, "%d checks failed\n", g_failed);
    return 1;
  }
  return 0;
}
