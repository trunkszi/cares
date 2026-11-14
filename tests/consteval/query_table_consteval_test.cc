#include <array>
#include <cares/query_table/query_table.hpp>
#include <cstddef>
#include <span>

struct[[= cares::notes::QueryRoute("example.com", cares::DnsType::A)]] ConstA {};
struct[[= cares::notes::QueryRoute("mail.example.com", cares::DnsType::MX, cares::DnsClass::IN)]] ConstMx {};

struct Hit {
  int id{0};
  template <typename Route>
  constexpr void operator()(const cares::FirstQuestionWire &) noexcept {
    if constexpr (std::is_same_v<Route, ConstA>) id = 11;
    if constexpr (std::is_same_v<Route, ConstMx>) id = 22;
  }
};

constexpr std::array<std::byte, 29> ExamplePacket() {
  std::array<std::byte, 29> packet{};
  packet[5] = std::byte{1};
  const char *name =
      "\x07"
      "example"
      "\x03"
      "com";
  for (std::size_t index = 0; index < 13; ++index) {
    packet[12 + index] = std::byte{static_cast<unsigned char>(name[index])};
  }
  packet[26] = std::byte{1};
  packet[28] = std::byte{1};
  return packet;
}

constexpr int DispatchExample() {
  constexpr auto kPacket = ExamplePacket();
  Hit hit;
  const auto result = cares::QueryTable<ConstA, ConstMx>::DispatchWireQuestion(std::span<const std::byte>{kPacket}, hit);
  if (!result) return -1;
  return hit.id * 100 + static_cast<int>(*result);
}

constexpr bool RejectsPointer() {
  std::array<std::byte, 16> packet{};
  packet[5] = std::byte{1};
  packet[12] = std::byte{0xC0};
  packet[13] = std::byte{0x0C};
  const auto parsed = cares::ParseFirstQuestionWire(std::span<const std::byte>{packet});
  return !parsed && parsed.error() == cares::Error::BadName();
}

constexpr bool KeepsPayloadPointerByte() {
  std::array<std::byte, 19> packet{};
  packet[5] = std::byte{1};
  packet[12] = std::byte{1};
  packet[13] = std::byte{0xC0};
  packet[14] = std::byte{0};
  packet[16] = std::byte{1};
  packet[18] = std::byte{1};
  const auto parsed = cares::ParseFirstQuestionWire(std::span<const std::byte>{packet});
  return parsed.has_value() && parsed->qname_wire.size() == 3 && std::to_integer<unsigned char>(parsed->qname_wire[1]) == 0xC0;
}

static_assert(cares::QueryTable<ConstA, ConstMx>::kRouteCount == 2);
static_assert(cares::QueryTable<ConstA, ConstMx>::kRoutes[0].qtype == cares::DnsType::A);
static_assert(cares::QueryTable<ConstA, ConstMx>::kRoutes[1].qtype == cares::DnsType::MX);
static_assert(cares::QueryTable<ConstA, ConstMx>::kRoutes[0].wire_len == 13);
static_assert(DispatchExample() == 1100);
static_assert(RejectsPointer());
static_assert(KeepsPayloadPointerByte());
static_assert(cares::EncodeQname("example.com.").ok == 1);
static_assert(cares::EncodeQname("example.com.").len == cares::EncodeQname("example.com").len);

struct[[= cares::notes::QueryRoute("n00.example", cares::DnsType::A)]] R00 {};
struct[[= cares::notes::QueryRoute("n01.example", cares::DnsType::A)]] R01 {};
struct[[= cares::notes::QueryRoute("n02.example", cares::DnsType::A)]] R02 {};
struct[[= cares::notes::QueryRoute("n03.example", cares::DnsType::A)]] R03 {};
struct[[= cares::notes::QueryRoute("n04.example", cares::DnsType::A)]] R04 {};
struct[[= cares::notes::QueryRoute("n05.example", cares::DnsType::A)]] R05 {};
struct[[= cares::notes::QueryRoute("n06.example", cares::DnsType::A)]] R06 {};
struct[[= cares::notes::QueryRoute("n07.example", cares::DnsType::A)]] R07 {};
struct[[= cares::notes::QueryRoute("n08.example", cares::DnsType::A)]] R08 {};
struct[[= cares::notes::QueryRoute("n09.example", cares::DnsType::A)]] R09 {};
struct[[= cares::notes::QueryRoute("n10.example", cares::DnsType::A)]] R10 {};
struct[[= cares::notes::QueryRoute("n11.example", cares::DnsType::A)]] R11 {};
struct[[= cares::notes::QueryRoute("n12.example", cares::DnsType::A)]] R12 {};
struct[[= cares::notes::QueryRoute("n13.example", cares::DnsType::A)]] R13 {};
struct[[= cares::notes::QueryRoute("n14.example", cares::DnsType::A)]] R14 {};
struct[[= cares::notes::QueryRoute("n15.example", cares::DnsType::A)]] R15 {};
struct[[= cares::notes::QueryRoute("n16.example", cares::DnsType::A)]] R16 {};
struct[[= cares::notes::QueryRoute("n17.example", cares::DnsType::A)]] R17 {};
struct[[= cares::notes::QueryRoute("n18.example", cares::DnsType::A)]] R18 {};
struct[[= cares::notes::QueryRoute("n19.example", cares::DnsType::A)]] R19 {};
struct[[= cares::notes::QueryRoute("n20.example", cares::DnsType::A)]] R20 {};
struct[[= cares::notes::QueryRoute("n21.example", cares::DnsType::A)]] R21 {};
struct[[= cares::notes::QueryRoute("n22.example", cares::DnsType::A)]] R22 {};
struct[[= cares::notes::QueryRoute("n23.example", cares::DnsType::A)]] R23 {};
struct[[= cares::notes::QueryRoute("n24.example", cares::DnsType::A)]] R24 {};
struct[[= cares::notes::QueryRoute("n25.example", cares::DnsType::A)]] R25 {};
struct[[= cares::notes::QueryRoute("n26.example", cares::DnsType::A)]] R26 {};
struct[[= cares::notes::QueryRoute("n27.example", cares::DnsType::A)]] R27 {};
struct[[= cares::notes::QueryRoute("n28.example", cares::DnsType::A)]] R28 {};
struct[[= cares::notes::QueryRoute("n29.example", cares::DnsType::A)]] R29 {};
struct[[= cares::notes::QueryRoute("n30.example", cares::DnsType::A)]] R30 {};
struct[[= cares::notes::QueryRoute("n31.example", cares::DnsType::A)]] R31 {};

struct WideHit {
  int id{0};
  template <typename Route>
  constexpr void operator()(const cares::FirstQuestionWire &) noexcept {
    if constexpr (std::is_same_v<Route, R00>) id = 7;
  }
};

constexpr std::array<std::byte, 29> Route00Packet() {
  std::array<std::byte, 29> packet{};
  packet[5] = std::byte{1};
  const std::array<unsigned char, 13> name{{3, 'n', '0', '0', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}};
  for (std::size_t index = 0; index < sizeof(name); ++index) packet[12 + index] = std::byte{name[index]};
  packet[26] = std::byte{1};
  packet[28] = std::byte{1};
  return packet;
}

constexpr int DispatchRoute00() {
  constexpr auto kPacket = Route00Packet();
  WideHit hit;
  const auto result = cares::QueryTable<R00, R01, R02, R03, R04, R05, R06, R07, R08, R09, R10, R11, R12, R13, R14, R15, R16,
                                        R17, R18, R19, R20, R21, R22, R23, R24, R25, R26, R27, R28, R29, R30,
                                        R31>::DispatchWireQuestion(std::span<const std::byte>{kPacket}, hit);
  if (!result || hit.id != 7) return -1;
  return static_cast<int>(*result);
}

static_assert(cares::QueryTable<R00, R01, R02, R03, R04, R05, R06, R07, R08, R09, R10, R11, R12, R13, R14, R15, R16, R17, R18,
                                R19, R20, R21, R22, R23, R24, R25, R26, R27, R28, R29, R30, R31>::kRouteCount == 32);
static_assert(DispatchRoute00() == 0);

int main() { return DispatchExample() == 1100 && DispatchRoute00() == 0 ? 0 : 1; }
