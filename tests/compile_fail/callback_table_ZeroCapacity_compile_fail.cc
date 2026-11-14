// expected-error: capacity must be in 1\.\.=64
#include <cares/channel/callback_table.hpp>
#include <cstddef>

using Forced = cares::CallbackTable<0>;
constexpr std::size_t kForce = sizeof(Forced);
