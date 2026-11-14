#include <ares.h>

#include <array>
#include <cares/resolver/dns_cache.hpp>
#include <cares/resolver/poll_table.hpp>

namespace {

consteval int PollAndCache() {
  static_assert(sizeof(cares::PollSlotWord) == 8);
  static_assert(alignof(cares::PollSlotWord) == 8);
  static_assert(uarch::NoPadding<cares::PollSlotWord> && uarch::RegisterPassable<cares::PollSlotWord>);

  cares::PollSlotWord word{};
  word = word.with<^^cares::PollSlotSpec::fd_bits>(static_cast<std::uint16_t>(3));
  word = word.with<^^cares::PollSlotSpec::in_use>(true);
  word = word.wrapping_add_top_field<^^cares::PollSlotSpec::generation>(1);
  if (word.get<^^cares::PollSlotSpec::fd_bits>() != 3 || !word.test<^^cares::PollSlotSpec::in_use>()) return 1;
  if (word.get<^^cares::PollSlotSpec::generation>() == 0) return 2;

  const auto folded = cares::NormalizeHost("A.Example.");
  if (!folded.has_value() || folded->View() != "a.example") return 5;

  cares::DnsCache<8> cache{cares::DnsCacheConfig{.min_ttl_sec = 1, .max_ttl_sec = 10, .negative_ttl_sec = 2}};
  const cares::IpAddress ip = cares::IpAddress::FromV4({1, 2, 3, 4});
  const std::array<cares::IpAddress, 1> ips{{ip}};
  cache.InsertPositive("A.Example.", ips, 5, 1000);
  const auto probe = cache.Lookup("a.example", 53, 1000);
  if (!probe.has_value() || !probe->has_value() || probe->value().size() != 1 || probe->value()[0].port != 53) return 6;
  if (!probe->value()[0].ip.IsV4() || probe->value()[0].ip.v4[0] != 1) return 7;

  cares::StaticHostTable<8> hosts;
  const auto parsed = hosts.ParseHosts("1.2.3.4 alias.Example. alias\n");
  if (!parsed.has_value() || *parsed < 2) return 8;
  const auto found = hosts.Lookup("ALIAS", 9);
  if (!found.has_value() || found->size() != 1 || (*found)[0].port != 9) return 9;
  return 0;
}

static_assert(PollAndCache() == 0);

}  // namespace

int main() { return PollAndCache(); }
