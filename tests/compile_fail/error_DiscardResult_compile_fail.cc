// expected-error: ignoring return value.*nodiscard
#include <cares/error/ares_error.hpp>
void Discard() { cares::Error::BadName(); }
