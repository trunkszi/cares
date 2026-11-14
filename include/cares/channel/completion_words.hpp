/** @file @brief Eight-byte query phase word packed with `uarch::BitWord`. */
#pragma once

#include <cstdint>
#include <uarch/primitives.hpp>

namespace cares {

/** @brief Lifecycle of one in-flight callback slot. */
enum class QueryPhase : std::uint8_t {
  Empty = 0,
  Submitted = 1,
  Completed = 2,
  Cancelled = 3,
  Reclaimed = 4,
};

/** @brief Disjoint fields of one query-state register. */
struct QueryStateSpec {
  using Word = std::uint64_t;
  [[= uarch::Field{0, 3}]] QueryPhase phase;
  [[= uarch::Field{3, 13}]] std::uint16_t status_code;
  [[= uarch::Field{16, 16}]] std::uint16_t generation;
  [[= uarch::Field{32, 32}]] std::uint32_t qid;
};

using QueryStateWord = uarch::BitWord<QueryStateSpec>;
static_assert(sizeof(QueryStateWord) == 8);

}  // namespace cares
