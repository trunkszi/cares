#include <array>
#include <cares/types/endpoint.hpp>
int main() {
  for (auto target : {"http://host/path", "", "host:", "host:0", "host:65536", "host:-1", "host:12x", "[::1", "[bad]:53",
                      "a@b:80", "host:9999999999999999", "a b:53"}) {
    if (cares::ParseEndpoint(target, 53)) return 1;
  }
  struct SchemeCase {
    std::string_view target;
    std::string_view explicit_target;
    std::uint16_t port;
    cares::EndpointScheme scheme;
  };
  constexpr std::array<SchemeCase, 6> kSchemes{{
      {"http://h", "http://h:1234", 80, cares::EndpointScheme::Http},
      {"https://h", "https://h:1234", 443, cares::EndpointScheme::Https},
      {"ws://h", "ws://h:1234", 80, cares::EndpointScheme::Ws},
      {"wss://h", "wss://h:1234", 443, cares::EndpointScheme::Wss},
      {"grpc://h", "grpc://h:1234", 80, cares::EndpointScheme::Grpc},
      {"grpcs://h", "grpcs://h:1234", 443, cares::EndpointScheme::Grpcs},
  }};
  for (const auto& test : kSchemes) {
    for (std::uint16_t fallback : {std::uint16_t{0}, std::uint16_t{9000}}) {
      const auto result = cares::ParseEndpoint(test.target, fallback);
      if (!result || result->port != test.port || result->scheme != test.scheme || result->host != "h") return 13;
      const auto explicit_port = cares::ParseEndpoint(test.explicit_target, fallback);
      if (!explicit_port || explicit_port->port != 1234 || explicit_port->scheme != test.scheme) return 13;
    }
  }
  struct RejectCase {
    std::string_view target;
    std::uint16_t default_port;
    cares::Error error;
  };
  constexpr std::array<RejectCase, 10> kRejections{{
      {"ftp://h:1", 0, cares::Error::InvalidArgument()},
      {"tcp://h", 0, cares::Error::InvalidArgument()},
      {"udp://h", 0, cares::Error::InvalidArgument()},
      {std::string_view("h\0x", 3), 53, cares::Error::BadName()},
      {"h:", 53, cares::Error::InvalidArgument()},
      {"h:0", 53, cares::Error::InvalidArgument()},
      {"h:65536", 53, cares::Error::InvalidArgument()},
      {"h:-1", 53, cares::Error::InvalidArgument()},
      {"", 53, cares::Error::BadName()},
      {"h", 0, cares::Error::InvalidArgument()},
  }};
  for (const auto& test : kRejections) {
    const auto result = cares::ParseEndpoint(test.target, test.default_port);
    if (result || result.error() != test.error) return 13;
  }
  struct LiteralCase {
    std::string_view target;
    std::uint16_t default_port;
    std::uint16_t port;
  };
  constexpr std::array<LiteralCase, 2> kLiterals{{{"[::1]", 8080, 8080}, {"[::1]:9000", 8080, 9000}}};
  for (const auto& test : kLiterals) {
    const auto result = cares::ParseEndpoint(test.target, test.default_port);
    if (!result || result->host != "::1" || result->port != test.port || !result->is_ipv6_bracketed) return 14;
  }
  for (std::string_view target : {"tcp://h", "udp://h", "h"}) {
    const auto fallback = cares::ParseEndpoint(target, 8080);
    if (!fallback || fallback->port != 8080) return 15;
  }
  const auto a = cares::ParseEndpoint("https://example.org");
  if (!a || a->host != "example.org" || a->port != 443 || a->scheme != cares::EndpointScheme::Https) return 2;
  const auto b = cares::ParseEndpoint("[::1]:9000");
  if (!b || b->host != "::1" || b->port != 9000 || !b->is_ipv6_bracketed) return 3;
  if (!cares::ParseEndpoint("::1", 53)) return 4;
  if (!cares::ParseEndpoint("host", 4001)) return 5;
  if (cares::ParseEndpoint("host")) return 6;
  if (cares::ParseIpLiteral("example.org")) return 7;
  if (!cares::ParseIpLiteral("127.0.0.1") || !cares::ParseIpLiteral("::1")) return 8;
  if (cares::ParseIpLiteral(std::string_view("127.0.0.1\0evil", 14))) return 9;
  return 0;
}
