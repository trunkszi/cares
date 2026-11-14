#pragma once
#include <arpa/inet.h>
#include <netinet/in.h>

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace cares {

enum class IpFamily : std::uint8_t {
  Unspec = 0,
  Ipv4 = 4,
  Ipv6 = 6,
  DualStack = 10,
};

using Ipv4Bytes = std::array<std::uint8_t, 4>;
using Ipv6Bytes = std::array<std::uint8_t, 16>;

struct IpAddress {
  IpFamily family{IpFamily::Ipv4};
  std::uint32_t scope_id{0};
  union {
    Ipv4Bytes v4{};
    Ipv6Bytes v6;
  };

  [[nodiscard]] static constexpr IpAddress FromV4(Ipv4Bytes bytes) noexcept;
  [[nodiscard]] static constexpr IpAddress FromV4HostOrder(std::uint32_t host_u32) noexcept;
  [[nodiscard]] static constexpr IpAddress FromV6(Ipv6Bytes bytes, std::uint32_t scope = 0) noexcept;
  [[nodiscard]] constexpr bool IsV4() const noexcept { return family == IpFamily::Ipv4; }
  [[nodiscard]] constexpr bool IsV6() const noexcept { return family == IpFamily::Ipv6; }
  [[nodiscard]] std::size_t FormatTo(std::span<char> buf) const noexcept;
  friend constexpr bool operator==(const IpAddress& a, const IpAddress& b) noexcept;
};

struct SockAddrValue {
  sockaddr_storage storage{};
  socklen_t len{0};
};

struct SocketAddress {
  IpAddress ip{};
  std::uint16_t port{0};

  [[nodiscard]] sockaddr_storage ToSockAddr() const noexcept;
  [[nodiscard]] constexpr socklen_t SockAddrLen() const noexcept {
    return ip.IsV4() ? static_cast<socklen_t>(sizeof(sockaddr_in))
                     : (ip.IsV6() ? static_cast<socklen_t>(sizeof(sockaddr_in6)) : 0);
  }
  [[nodiscard]] SockAddrValue ToSockAddrValue() const noexcept { return {.storage = ToSockAddr(), .len = SockAddrLen()}; }
  [[nodiscard]] static SocketAddress FromSockAddr(const sockaddr* sa) noexcept;
  friend constexpr bool operator==(const SocketAddress&, const SocketAddress&) noexcept = default;
};

using HostAddress = IpAddress;

struct ServerEndpoint {
  IpAddress ip{};
  std::uint16_t port{53};
  bool use_tcp{false};
};

struct SearchDomain {
  std::array<char, 128> name{};
  std::uint8_t len{0};
  [[nodiscard]] constexpr std::string_view View() const noexcept { return {name.data(), len}; }
};

struct HostResult {
  std::array<char, 256> canonical_name{};
  std::uint16_t canonical_len{0};
  std::array<IpAddress, 16> addresses{};
  std::uint8_t address_count{0};
  [[nodiscard]] constexpr std::string_view CanonicalName() const noexcept { return {canonical_name.data(), canonical_len}; }
  [[nodiscard]] constexpr std::span<const IpAddress> Addresses() const noexcept { return {addresses.data(), address_count}; }
};

struct AddressInfoNode {
  IpAddress ip{};
  std::uint16_t port{0};
  std::uint32_t ttl{0};
  int socktype{0};
  int protocol{0};
};

struct AddressInfoCname {
  std::array<char, 128> alias{};
  std::uint8_t alias_len{0};
  std::array<char, 128> name{};
  std::uint8_t name_len{0};
  std::uint32_t ttl{0};
};

struct AddressInfoResult {
  std::array<char, 256> name{};
  std::uint16_t name_len{0};
  std::array<AddressInfoNode, 16> nodes{};
  std::uint8_t node_count{0};
  std::array<AddressInfoCname, 4> cnames{};
  std::uint8_t cname_count{0};
  [[nodiscard]] constexpr std::span<const AddressInfoNode> Nodes() const noexcept { return {nodes.data(), node_count}; }
};

struct NameInfoResult {
  std::array<char, 256> node{};
  std::uint16_t node_len{0};
  std::array<char, 64> service{};
  std::uint8_t service_len{0};
  [[nodiscard]] constexpr std::string_view Node() const noexcept { return {node.data(), node_len}; }
  [[nodiscard]] constexpr std::string_view Service() const noexcept { return {service.data(), service_len}; }
};

constexpr IpAddress IpAddress::FromV4(Ipv4Bytes bytes) noexcept {
  return {.family = IpFamily::Ipv4, .scope_id = 0, .v4 = bytes};
}
constexpr IpAddress IpAddress::FromV4HostOrder(std::uint32_t host_u32) noexcept {
  return FromV4({static_cast<std::uint8_t>(host_u32 >> 24u), static_cast<std::uint8_t>(host_u32 >> 16u),
                 static_cast<std::uint8_t>(host_u32 >> 8u), static_cast<std::uint8_t>(host_u32)});
}
constexpr IpAddress IpAddress::FromV6(Ipv6Bytes bytes, std::uint32_t scope) noexcept {
  return {.family = IpFamily::Ipv6, .scope_id = scope, .v6 = bytes};
}
constexpr bool operator==(const IpAddress& a, const IpAddress& b) noexcept {
  if (a.family != b.family || a.scope_id != b.scope_id) return false;
  if (a.IsV4()) return a.v4 == b.v4;
  if (a.IsV6()) return a.v6 == b.v6;
  return true;
}
inline std::size_t IpAddress::FormatTo(std::span<char> buf) const noexcept {
  if (!IsV4() && !IsV6()) return 0;
  std::array<char, INET6_ADDRSTRLEN> text{};
  const void* bytes = IsV4() ? static_cast<const void*>(v4.data()) : static_cast<const void*>(v6.data());
  if (inet_ntop(IsV4() ? AF_INET : AF_INET6, bytes, text.data(), text.size()) == nullptr) return 0;
  const auto length = std::strlen(text.data());
  if (buf.size() < length + 1) return 0;
  std::memcpy(buf.data(), text.data(), length + 1);
  return length;
}
namespace detail {
// Socket port fields are big-endian on the wire.
[[nodiscard]] constexpr std::uint16_t Net16(std::uint16_t value) noexcept {
  if constexpr (std::endian::native == std::endian::little) return std::byteswap(value);
  return value;
}
}  // namespace detail
inline sockaddr_storage SocketAddress::ToSockAddr() const noexcept {
  sockaddr_storage storage{};
  if (ip.IsV4()) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = detail::Net16(port);
    std::memcpy(&addr.sin_addr, ip.v4.data(), ip.v4.size());
    std::memcpy(&storage, &addr, sizeof(addr));
  } else if (ip.IsV6()) {
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = detail::Net16(port);
    addr.sin6_scope_id = ip.scope_id;
    std::memcpy(&addr.sin6_addr, ip.v6.data(), ip.v6.size());
    std::memcpy(&storage, &addr, sizeof(addr));
  }
  return storage;
}
inline SocketAddress SocketAddress::FromSockAddr(const sockaddr* sa) noexcept {
  if (sa != nullptr && sa->sa_family == AF_INET) {
    sockaddr_in addr{};
    std::memcpy(&addr, sa, sizeof(addr));
    Ipv4Bytes bytes{};
    std::memcpy(bytes.data(), &addr.sin_addr, bytes.size());
    return {IpAddress::FromV4(bytes), detail::Net16(addr.sin_port)};
  }
  if (sa != nullptr && sa->sa_family == AF_INET6) {
    sockaddr_in6 addr{};
    std::memcpy(&addr, sa, sizeof(addr));
    Ipv6Bytes bytes{};
    std::memcpy(bytes.data(), &addr.sin6_addr, bytes.size());
    return {IpAddress::FromV6(bytes, addr.sin6_scope_id), detail::Net16(addr.sin6_port)};
  }
  return {IpAddress{.family = IpFamily::Unspec, .scope_id = 0, .v4 = {}}, 0};
}

}  // namespace cares
