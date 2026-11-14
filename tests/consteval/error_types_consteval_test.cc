#include <algorithm>
#include <array>
#include <cares/error/ares_error.hpp>
#include <cares/types/dns_types.hpp>
#include <cares/types/endpoint.hpp>
#include <cares/types/query_handle.hpp>
#include <concepts>
#include <type_traits>
#include <uarch/primitives.hpp>

template <typename T>
concept ErrorResult = requires(T result) {
  { result.error() } -> std::same_as<cares::Error&>;
  { result.has_value() } -> std::same_as<bool>;
};
static_assert(ErrorResult<cares::Result<int>>);
static_assert(std::same_as<cares::EndpointList, uarch::inplace_vector<cares::Endpoint, 16>>);
static_assert(uarch::NoPadding<cares::Error> && uarch::RegisterPassable<cares::Error>);
static_assert(uarch::NoPadding<cares::QueryHandle> && uarch::RegisterPassable<cares::QueryHandle>);
static_assert(sizeof(cares::Error) == 8 && alignof(cares::Error) == 8);
static_assert(sizeof(cares::QueryHandle) == 8 && alignof(cares::QueryHandle) == 8);
static_assert(cares::Error::FromAres(ARES_ETIMEOUT).IsRetryable());
static_assert(cares::Error::FromAres(ARES_ENOTFOUND).IsNotFound());
static_assert(cares::ParseEndpoint("host:65535")->port == 65535);
static_assert(!cares::ParseEndpoint("host:65536"));
static_assert(!cares::ParseEndpoint("host:0"));
static_assert(cares::QueryHandle::Pack(1, 2, 3).raw == 0x0000000300020001ULL);
static_assert(cares::QueryHandle::Pack(1, 2) < cares::QueryHandle::Pack(2, 2));
consteval bool ErrorContract() {
  using cares::Error;
  using cares::ErrorCategory;
  using cares::ErrorSource;
  struct UringCase {
    uring::UringErrorCode code;
    ErrorCategory category;
  };
  constexpr std::array<UringCase, 7> kCases{{
      {uring::UringErrorCode::kSqRingFull, ErrorCategory::ResourceExhausted},
      {uring::UringErrorCode::kSlabExhausted, ErrorCategory::ResourceExhausted},
      {uring::UringErrorCode::kGenerationExhausted, ErrorCategory::ResourceExhausted},
      {uring::UringErrorCode::kDrainTimeout, ErrorCategory::Transient},
      {uring::UringErrorCode::kCanceled, ErrorCategory::Cancelled},
      {uring::UringErrorCode::kAgain, ErrorCategory::Transient},
      {uring::UringErrorCode::kInvalid, ErrorCategory::InvalidInput},
  }};
  for (const auto& test : kCases) {
    const auto result = Error::FromUring(test.code);
    if (result.source != ErrorSource::Uring || result.category != test.category ||
        result.raw_code != std::to_underlying(test.code))
      return false;
  }
  return Error::Timeout().category == ErrorCategory::Transient && Error::NotFound().category == ErrorCategory::NotFound &&
         Error::Cancelled().category == ErrorCategory::Cancelled &&
         Error::InvalidArgument().category == ErrorCategory::InvalidInput &&
         Error::CapacityExhausted().category == ErrorCategory::ResourceExhausted;
}
static_assert(ErrorContract());

consteval bool EndpointContract() {
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
      if (!result || result->port != test.port || result->scheme != test.scheme || result->host != "h") return false;
      const auto explicit_port = cares::ParseEndpoint(test.explicit_target, fallback);
      if (!explicit_port || explicit_port->port != 1234 || explicit_port->scheme != test.scheme) return false;
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
  return std::ranges::all_of(kRejections, [](const auto& test) {
    const auto result = cares::ParseEndpoint(test.target, test.default_port);
    return !result && result.error() == test.error;
  });
}
static_assert(EndpointContract());

int main() { return 0; }
