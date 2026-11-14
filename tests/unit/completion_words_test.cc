#include <cares/channel/completion_words.hpp>
#include <cstdint>
#include <cstdio>
#include <utility>

namespace {

int g_failed = 0;

void Check(bool ok, const char* name) {
  if (!ok) {
    std::fprintf(stderr, "FAIL %s\n", name);
    ++g_failed;
  }
}

constexpr cares::QueryStateWord Packed() {
  cares::QueryStateWord word{};
  word = word.try_with<^^cares::QueryStateSpec::phase>(cares::QueryPhase::Reclaimed).value();
  word = word.try_with<^^cares::QueryStateSpec::status_code>(26).value();
  word = word.try_with<^^cares::QueryStateSpec::generation>(0xABCD).value();
  word = word.try_with<^^cares::QueryStateSpec::qid>(0x12345678u).value();
  return word;
}

void PackRoundtrip() {
  constexpr auto kPacked = Packed();
  static_assert(kPacked.get<^^cares::QueryStateSpec::phase>() == cares::QueryPhase::Reclaimed);
  static_assert(kPacked.get<^^cares::QueryStateSpec::status_code>() == 26);
  static_assert(kPacked.get<^^cares::QueryStateSpec::generation>() == 0xABCD);
  static_assert(kPacked.get<^^cares::QueryStateSpec::qid>() == 0x12345678u);
  constexpr auto kRaw = kPacked.raw();
  static_assert((kRaw & 0x7ULL) == static_cast<std::uint64_t>(cares::QueryPhase::Reclaimed));
  static_assert(((kRaw >> 3) & 0x1FFFULL) == 26ULL);
  static_assert(((kRaw >> 16) & 0xFFFFULL) == 0xABCDULL);
  static_assert((kRaw >> 32) == 0x12345678ULL);
  Check(kPacked.get<^^cares::QueryStateSpec::qid>() == 0x12345678u, "qid");
}

void LayoutIsEightBytes() {
  Check(sizeof(cares::QueryStateWord) == 8, "size");
  Check(sizeof(uarch::BitWord<cares::QueryStateSpec>) == sizeof(std::uint64_t), "bitword");
}

void StatusOverflowRejected() {
  cares::QueryStateWord word{};
  word = word.try_with<^^cares::QueryStateSpec::status_code>(1).value();
  const auto huge = word.try_with<^^cares::QueryStateSpec::status_code>(70000);
  const auto negative = word.try_with<^^cares::QueryStateSpec::status_code>(-1);
  Check(!huge && !negative, "rejected");
  Check(word.get<^^cares::QueryStateSpec::status_code>() == 1, "unchanged");
}

}  // namespace

int main() {
  PackRoundtrip();
  LayoutIsEightBytes();
  StatusOverflowRejected();
  if (g_failed != 0) {
    std::fprintf(stderr, "completion_words_test failed %d\n", g_failed);
    return 1;
  }
  std::fprintf(stdout, "ok completion_words_test\n");
  return 0;
}
