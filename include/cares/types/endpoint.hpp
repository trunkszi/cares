#pragma once
#include <array>
#include <cares/error/ares_error.hpp>
#include <cares/types/host_types.hpp>
#include <cstdint>
#include <string_view>
#include <uarch/primitives.hpp>

namespace cares {

enum class EndpointScheme : std::uint8_t {
  None = 0,
  Http = 1,
  Https = 2,
  Ws = 3,
  Wss = 4,
  Grpc = 5,
  Grpcs = 6,
  Tcp = 7,
  Udp = 8,
};

struct ParsedEndpoint {
  EndpointScheme scheme{EndpointScheme::None};
  std::string_view host{};
  // 0 is uninitialized. An omitted port needs a non-zero default_port; an explicit host:0 is rejected.
  std::uint16_t port{0};
  bool is_ipv6_bracketed{false};
};

using Endpoint = SocketAddress;
using EndpointList = uarch::inplace_vector<Endpoint, 16>;

[[nodiscard]] constexpr Result<ParsedEndpoint> ParseEndpoint(std::string_view target, std::uint16_t default_port = 0) noexcept;
[[nodiscard]] Result<IpAddress> ParseIpLiteral(std::string_view host) noexcept;

inline Result<IpAddress> ParseIpLiteral(std::string_view host) noexcept {
  if (host.empty() || host.size() >= INET6_ADDRSTRLEN || host.find('\0') != std::string_view::npos)
    return std::unexpected(Error::BadName());
  std::array<char, INET6_ADDRSTRLEN> text{};
  std::memcpy(text.data(), host.data(), host.size());
  Ipv4Bytes v4{};
  if (inet_pton(AF_INET, text.data(), v4.data()) == 1) return IpAddress::FromV4(v4);
  Ipv6Bytes v6{};
  if (inet_pton(AF_INET6, text.data(), v6.data()) == 1) return IpAddress::FromV6(v6);
  return std::unexpected(Error::BadName());
}
constexpr Result<ParsedEndpoint> ParseEndpoint(std::string_view target, std::uint16_t default_port) noexcept {
  if (target.empty()) return std::unexpected(Error::BadName());
  for (char ch : target) {
    if (static_cast<unsigned char>(ch) <= 32 || ch == 127) return std::unexpected(Error::BadName());
  }
  ParsedEndpoint result{};
  auto authority = target;
  const auto scheme_end = target.find("://");
  if (scheme_end != std::string_view::npos) {
    const auto scheme = target.substr(0, scheme_end);
    if (scheme == "http") {
      result.scheme = EndpointScheme::Http;
      result.port = 80;
    } else if (scheme == "https") {
      result.scheme = EndpointScheme::Https;
      result.port = 443;
    } else if (scheme == "ws") {
      result.scheme = EndpointScheme::Ws;
      result.port = 80;
    } else if (scheme == "wss") {
      result.scheme = EndpointScheme::Wss;
      result.port = 443;
    } else if (scheme == "grpc") {
      result.scheme = EndpointScheme::Grpc;
      result.port = 80;
    } else if (scheme == "grpcs") {
      result.scheme = EndpointScheme::Grpcs;
      result.port = 443;
    } else if (scheme == "tcp")
      result.scheme = EndpointScheme::Tcp;
    else if (scheme == "udp")
      result.scheme = EndpointScheme::Udp;
    else
      return std::unexpected(Error::InvalidArgument());
    authority.remove_prefix(scheme_end + 3);
  }
  if (result.port == 0) result.port = default_port;
  if (authority.empty() || authority.find_first_of("/@?#\\") != std::string_view::npos)
    return std::unexpected(Error::BadName());
  std::string_view port_text{};
  bool explicit_port = false;
  if (authority.front() == '[') {
    const auto close = authority.find(']');
    if (close == std::string_view::npos) return std::unexpected(Error::BadName());
    result.host = authority.substr(1, close - 1);
    result.is_ipv6_bracketed = true;
    auto ip = ParseIpLiteral(result.host);
    if (!ip || !ip->IsV6()) return std::unexpected(Error::BadName());
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':') return std::unexpected(Error::BadName());
      explicit_port = true;
      port_text = authority.substr(close + 2);
    }
  } else {
    if (authority.find_first_of("[]") != std::string_view::npos) return std::unexpected(Error::BadName());
    const auto first = authority.find(':');
    const auto last = authority.rfind(':');
    if (first != std::string_view::npos && first != last) {
      auto ip = ParseIpLiteral(authority);
      if (!ip || !ip->IsV6()) return std::unexpected(Error::BadName());
      result.host = authority;
    } else if (first != std::string_view::npos) {
      result.host = authority.substr(0, first);
      port_text = authority.substr(first + 1);
      explicit_port = true;
    } else
      result.host = authority;
  }
  if (result.host.empty()) return std::unexpected(Error::BadName());
  if (explicit_port) {
    if (port_text.empty()) return std::unexpected(Error::InvalidArgument());
    std::uint32_t port = 0;
    for (char ch : port_text) {
      if (ch < '0' || ch > '9') return std::unexpected(Error::InvalidArgument());
      port = port * 10u + static_cast<std::uint32_t>(ch - '0');
      if (port > 65535u) return std::unexpected(Error::InvalidArgument());
    }
    result.port = static_cast<std::uint16_t>(port);
  }
  if (result.port == 0) return std::unexpected(Error::InvalidArgument());
  return result;
}

}  // namespace cares
