#include <array>
#include <cares/types/host_types.hpp>
#include <string_view>
int main() {
  auto ip = cares::IpAddress::FromV4HostOrder(0x7f000001);
  cares::SocketAddress endpoint{ip, 65535};
  const auto v4_value = endpoint.ToSockAddrValue();
  auto storage = endpoint.ToSockAddr();
  auto length = endpoint.SockAddrLen();
  if (v4_value.len != length) return 8;
  if (cares::SocketAddress::FromSockAddr(reinterpret_cast<const sockaddr*>(&v4_value.storage)) != endpoint) return 9;
  if (length != sizeof(sockaddr_in)) return 1;
  if (cares::SocketAddress::FromSockAddr(reinterpret_cast<const sockaddr*>(&storage)) != endpoint) return 2;
  std::array<char, 64> text{};
  auto n = ip.FormatTo(text);
  if (std::string_view(text.data(), n) != "127.0.0.1") return 3;
  if (ip.FormatTo(std::span<char>(text.data(), 3)) != 0) return 4;
  cares::Ipv6Bytes bytes{};
  bytes[15] = 1;
  cares::SocketAddress v6{cares::IpAddress::FromV6(bytes, 8), 443};
  storage = v6.ToSockAddr();
  length = v6.SockAddrLen();
  if (length != sizeof(sockaddr_in6)) return 5;
  if (cares::SocketAddress::FromSockAddr(reinterpret_cast<const sockaddr*>(&storage)) != v6) return 6;
  n = v6.ip.FormatTo(text);
  if (std::string_view(text.data(), n) != "::1") return 7;
  constexpr cares::IpAddress kZero{};
  static_assert(kZero == cares::IpAddress::FromV4({0, 0, 0, 0}));
  return 0;
}
