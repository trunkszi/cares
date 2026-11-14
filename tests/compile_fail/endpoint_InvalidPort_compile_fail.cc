// expected-error: static assertion failed.*invalid endpoint port
#include <cares/types/endpoint.hpp>
static_assert(cares::ParseEndpoint("host:65536").has_value(), "invalid endpoint port");
