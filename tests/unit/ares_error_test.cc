#include <array>
#include <cares/error/ares_error.hpp>
#include <cerrno>
int main() {
  if (!cares::Error::FromAres(ARES_SUCCESS).IsOk()) return 1;
  if (!cares::Error::FromAres(ARES_ETIMEOUT).IsRetryable()) return 2;
  if (!cares::Error::FromAres(ARES_ENODATA).IsNotFound()) return 3;
  if (!cares::Error::FromAres(ARES_ECANCELLED).IsCancelled()) return 4;
  if (cares::Error::FromAres(ARES_EBADNAME).category != cares::ErrorCategory::InvalidInput) return 5;
  if (cares::Error::FromErrno(EAGAIN).raw_code != EAGAIN) return 6;
  if (!cares::Error::FromErrno(0).IsOk()) return 7;
  if (cares::Error::FromAres(12345).raw_code != 12345) return 8;
  if (cares::Error::CapacityExhausted().category != cares::ErrorCategory::ResourceExhausted) return 9;
  if (cares::Error::BadName().Message().empty()) return 10;
  using cares::Error;
  using cares::ErrorCategory;
  using cares::ErrorSource;
  struct UringCase {
    uring::UringErrorCode code;
    ErrorCategory category;
  };
  const std::array<UringCase, 7> cases{{
      {uring::UringErrorCode::kSqRingFull, ErrorCategory::ResourceExhausted},
      {uring::UringErrorCode::kSlabExhausted, ErrorCategory::ResourceExhausted},
      {uring::UringErrorCode::kGenerationExhausted, ErrorCategory::ResourceExhausted},
      {uring::UringErrorCode::kDrainTimeout, ErrorCategory::Transient},
      {uring::UringErrorCode::kCanceled, ErrorCategory::Cancelled},
      {uring::UringErrorCode::kAgain, ErrorCategory::Transient},
      {uring::UringErrorCode::kInvalid, ErrorCategory::InvalidInput},
  }};
  for (const auto& test : cases) {
    const auto result = Error::FromUring(test.code);
    if (result.source != ErrorSource::Uring || result.category != test.category ||
        result.raw_code != std::to_underlying(test.code))
      return 11;
  }
  const std::array<Error, 5> factories{
      {Error::Timeout(), Error::NotFound(), Error::Cancelled(), Error::InvalidArgument(), Error::CapacityExhausted()}};
  const std::array<ErrorCategory, 5> categories{{ErrorCategory::Transient, ErrorCategory::NotFound, ErrorCategory::Cancelled,
                                                 ErrorCategory::InvalidInput, ErrorCategory::ResourceExhausted}};
  for (std::size_t i = 0; i < std::size(factories); ++i) {
    if (factories[i].category != categories[i]) return 12;
  }
  if (Error::BadName().Message() != "Misformatted domain name") return 13;
  if (Error::FromUring(uring::UringErrorCode::kSqRingFull).Message() != "submission queue full") return 14;
  if (Error::FromUring(uring::UringErrorCode::kAgain).Message().empty()) return 15;
  if (Error::InvalidArgument().Message() != "invalid argument") return 16;
  if (Error::CapacityExhausted().Message() != "capacity exhausted") return 17;
  if (Error::CapacityExhausted() != Error::CapacityExhausted()) return 18;
  if (Error::CapacityExhausted() == Error::FromAres(ARES_ENOMEM)) return 19;
  if (Error::CapacityExhausted() == Error::FromUring(uring::UringErrorCode::kSlabExhausted)) return 20;
  if (Error::CapacityExhausted().source != ErrorSource::Contract) return 21;
  if (Error::CapacityExhausted().AsAresStatus().has_value()) return 22;
  if (Error::FromErrno(ENOMEM).AsAresStatus().has_value()) return 23;
  if (Error::FromUring(uring::UringErrorCode::kInvalid).AsAresStatus().has_value()) return 24;
  const auto bad_string = Error::FromAres(ARES_EBADSTR);
  if (bad_string.category != ErrorCategory::InvalidInput || bad_string.AsAresStatus() != cares::AresStatus::BadStr) return 25;
  return 0;
}
