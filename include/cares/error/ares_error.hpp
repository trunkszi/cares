#pragma once
#include <ares.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <string_view>
#include <uring/error/uring_error.hpp>
#include <utility>

namespace cares {

enum class ErrorSource : std::uint8_t {
  None = 0,
  Ares = 1,
  Uring = 2,
  Contract = 3,
  System = 4,
};

enum class AresStatus : std::int32_t {
  Success = ARES_SUCCESS,
  NoData = ARES_ENODATA,
  FormErr = ARES_EFORMERR,
  ServFail = ARES_ESERVFAIL,
  NotFound = ARES_ENOTFOUND,
  NotImp = ARES_ENOTIMP,
  Refused = ARES_EREFUSED,
  BadQuery = ARES_EBADQUERY,
  BadName = ARES_EBADNAME,
  BadFamily = ARES_EBADFAMILY,
  BadResp = ARES_EBADRESP,
  ConnRefused = ARES_ECONNREFUSED,
  Timeout = ARES_ETIMEOUT,
  Eof = ARES_EOF,
  File = ARES_EFILE,
  NoMem = ARES_ENOMEM,
  Destruction = ARES_EDESTRUCTION,
  BadStr = ARES_EBADSTR,
  BadFlags = ARES_EBADFLAGS,
  NoName = ARES_ENONAME,
  BadHints = ARES_EBADHINTS,
  NotInitialized = ARES_ENOTINITIALIZED,
  LoadIpHlpApi = ARES_ELOADIPHLPAPI,
  AddrGetNetworkParams = ARES_EADDRGETNETWORKPARAMS,
  Cancelled = ARES_ECANCELLED,
  Service = ARES_ESERVICE,
  NoServer = ARES_ENOSERVER,
};

enum class ErrorCategory : std::uint8_t {
  None = 0,
  Transient = 1,
  NotFound = 2,
  Permanent = 3,
  Cancelled = 4,
  ResourceExhausted = 5,
  InvalidInput = 6,
  IoError = 7,
};

struct alignas(8) Error {
  ErrorSource source{ErrorSource::None};
  ErrorCategory category{ErrorCategory::None};
  std::int16_t reserved{0};
  std::int32_t raw_code{0};

  [[nodiscard]] static constexpr Error FromAres(int status) noexcept;
  [[nodiscard]] static constexpr Error FromUring(uring::UringErrorCode err) noexcept;
  [[nodiscard]] static constexpr Error FromErrno(int err_no) noexcept;
  [[nodiscard]] static constexpr Error InvalidArgument(std::int32_t code = ARES_EBADQUERY) noexcept;
  [[nodiscard]] static constexpr Error CapacityExhausted() noexcept;
  [[nodiscard]] static constexpr Error Cancelled() noexcept;
  [[nodiscard]] static constexpr Error NotFound() noexcept;
  [[nodiscard]] static constexpr Error BadName() noexcept;
  [[nodiscard]] static constexpr Error BadResponse() noexcept;
  [[nodiscard]] static constexpr Error Timeout() noexcept;

  [[nodiscard]] constexpr bool IsOk() const noexcept { return source == ErrorSource::None && raw_code == 0; }
  [[nodiscard]] constexpr bool IsRetryable() const noexcept { return category == ErrorCategory::Transient; }
  [[nodiscard]] constexpr bool IsNotFound() const noexcept { return category == ErrorCategory::NotFound; }
  [[nodiscard]] constexpr bool IsCancelled() const noexcept { return category == ErrorCategory::Cancelled; }
  // errno 1..26 overlaps ARES_ENODATA..ARES_ESERVICE. Only an Ares-sourced code is a status.
  [[nodiscard]] constexpr std::optional<AresStatus> AsAresStatus() const noexcept {
    if (source != ErrorSource::Ares) return std::nullopt;
    return static_cast<AresStatus>(raw_code);
  }
  [[nodiscard]] std::string_view Message() const noexcept;
  friend constexpr bool operator==(const Error&, const Error&) noexcept = default;
};
static_assert(sizeof(Error) == 8);

template <typename T>
using Result = std::expected<T, Error>;

constexpr Error Error::FromAres(int status) noexcept {
  if (status == ARES_SUCCESS) return {};
  ErrorCategory category = ErrorCategory::Permanent;
  switch (status) {
    case ARES_ENODATA:
    case ARES_ENOTFOUND:
    case ARES_ENONAME:
      category = ErrorCategory::NotFound;
      break;
    case ARES_ETIMEOUT:
    case ARES_ESERVFAIL:
    case ARES_ECONNREFUSED:
    case ARES_EOF:
      category = ErrorCategory::Transient;
      break;
    case ARES_ECANCELLED:
    case ARES_EDESTRUCTION:
      category = ErrorCategory::Cancelled;
      break;
    case ARES_ENOMEM:
      category = ErrorCategory::ResourceExhausted;
      break;
    case ARES_EBADQUERY:
    case ARES_EBADNAME:
    case ARES_EBADFAMILY:
    case ARES_EBADSTR:
    case ARES_EBADFLAGS:
    case ARES_EBADHINTS:
    case ARES_ESERVICE:
      category = ErrorCategory::InvalidInput;
      break;
    case ARES_EFILE:
      category = ErrorCategory::IoError;
      break;
    default:
      break;
  }
  return {.source = ErrorSource::Ares, .category = category, .raw_code = status};
}
constexpr Error Error::FromErrno(int err_no) noexcept {
  if (err_no == 0) return {};
  auto category = ErrorCategory::IoError;
  switch (err_no) {
    case EAGAIN:
    case EINTR:
    case ETIMEDOUT:
    case ECONNREFUSED:
      category = ErrorCategory::Transient;
      break;
    case ENOMEM:
    case ENOBUFS:
    case ENOSPC:
    case EMFILE:
    case ENFILE:
      category = ErrorCategory::ResourceExhausted;
      break;
    case ECANCELED:
      category = ErrorCategory::Cancelled;
      break;
    case EINVAL:
      category = ErrorCategory::InvalidInput;
      break;
    case ENOENT:
      category = ErrorCategory::NotFound;
      break;
    default:
      break;
  }
  return {.source = ErrorSource::System, .category = category, .raw_code = err_no};
}
constexpr Error Error::FromUring(uring::UringErrorCode err) noexcept {
  auto result = FromErrno(std::to_underlying(err));
  if (result.IsOk()) return result;
  result.source = ErrorSource::Uring;
  switch (err) {
    case uring::UringErrorCode::kSqRingFull:
    case uring::UringErrorCode::kSlabExhausted:
    case uring::UringErrorCode::kGenerationExhausted:
      result.category = ErrorCategory::ResourceExhausted;
      break;
    case uring::UringErrorCode::kDrainTimeout:
      result.category = ErrorCategory::Transient;
      break;
    default:
      break;
  }
  return result;
}
constexpr Error Error::InvalidArgument(std::int32_t code) noexcept {
  return {.source = ErrorSource::Contract, .category = ErrorCategory::InvalidInput, .raw_code = code};
}
constexpr Error Error::CapacityExhausted() noexcept {
  return {.source = ErrorSource::Contract, .category = ErrorCategory::ResourceExhausted, .raw_code = ARES_ENOMEM};
}
constexpr Error Error::Cancelled() noexcept { return FromAres(ARES_ECANCELLED); }
constexpr Error Error::NotFound() noexcept { return FromAres(ARES_ENOTFOUND); }
constexpr Error Error::BadName() noexcept { return FromAres(ARES_EBADNAME); }
constexpr Error Error::BadResponse() noexcept { return FromAres(ARES_EBADRESP); }
constexpr Error Error::Timeout() noexcept { return FromAres(ARES_ETIMEOUT); }
inline std::string_view Error::Message() const noexcept {
  if (IsOk()) return "success";
  if (source == ErrorSource::Ares) return ares_strerror(raw_code);
  if (source == ErrorSource::System) {
    if (raw_code > 0) return std::strerror(raw_code);
    return "invalid argument";
  }
  if (source == ErrorSource::Uring) {
    if (raw_code > 0 && raw_code <= 133) return std::strerror(raw_code);
    return uring::ErrorName(static_cast<uring::UringErrorCode>(raw_code));
  }
  if (category == ErrorCategory::ResourceExhausted) return "capacity exhausted";
  return "invalid argument";
}

}  // namespace cares
