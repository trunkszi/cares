#include <ares.h>

#include <array>
#include <cares/channel/options.hpp>
#include <cstdio>
#include <string_view>

namespace {

int g_failed = 0;

void Check(bool ok, const char* name) {
  if (!ok) {
    std::fprintf(stderr, "FAIL %s\n", name);
    ++g_failed;
  }
}

cares::Error SlabFull() { return cares::Error::CapacityExhausted(); }

constexpr cares::ChannelOptions Sample() {
  cares::ChannelOptions options{};
  static_cast<void>(options.WithTimeoutMs(1500).WithTries(3).WithNdots(2).WithUdpMaxQueries(8).WithEdnsPsz(1232).WithFlag(
      static_cast<std::uint32_t>(ARES_FLAG_NOSEARCH)));
  cares::ServerEndpoint endpoint;
  endpoint.ip = cares::IpAddress::FromV4(cares::Ipv4Bytes{8, 8, 8, 8});
  endpoint.port = 5353;
  endpoint.use_tcp = true;
  if (!options.AddServer(endpoint)) return {};
  if (!options.AddSearchDomain("example.com")) return {};
  if (!options.SetResolvconfPath("/etc/resolv.conf")) return {};
  if (!options.SetHostsPath("/etc/hosts")) return {};
  return options;
}

constexpr cares::ChannelOptions kSample = Sample();

static_assert(kSample.timeout_ms == 1500);
static_assert(kSample.tries == 3);
static_assert(kSample.ndots == 2);
static_assert(kSample.udp_max_queries == 8);
static_assert(kSample.edns_psz == 1232);
static_assert(kSample.servers.size() == 1);
static_assert(kSample.servers[0].port == 5353);
static_assert(kSample.servers[0].use_tcp);
static_assert(kSample.search_domains.size() == 1);
static_assert(kSample.search_domains[0].len == 11);
static_assert(kSample.search_domains[0].name[11] == '\0');
static_assert(kSample.resolvconf_path.size() == 16);
static_assert(kSample.hosts_path.size() == 10);
static_assert((kSample.flags & static_cast<std::uint32_t>(ARES_FLAG_EDNS | ARES_FLAG_STAYOPEN | ARES_FLAG_NOSEARCH)) ==
              static_cast<std::uint32_t>(ARES_FLAG_EDNS | ARES_FLAG_STAYOPEN | ARES_FLAG_NOSEARCH));

void DefaultsMatchContract() {
  const cares::ChannelOptions options{};
  Check(options.timeout_ms == 2000, "timeout");
  Check(options.tries == 2, "tries");
  Check(options.ndots == 1, "ndots");
  Check(options.udp_max_queries == 0, "udp");
  Check(options.edns_psz == 4096, "edns");
  Check(options.flags == static_cast<std::uint32_t>(ARES_FLAG_EDNS | ARES_FLAG_STAYOPEN), "flags");
  Check(options.servers.empty() && options.search_domains.empty(), "lists");
  Check(options.resolvconf_path.is_empty() && options.hosts_path.is_empty(), "paths");
}

void BuildersStoreValues() {
  const cares::ChannelOptions options = Sample();
  Check(options.resolvconf_path.as_string_view() == "/etc/resolv.conf", "resolv");
  Check(options.hosts_path.as_string_view() == "/etc/hosts", "hosts");
  Check(options.search_domains[0].View() == "example.com", "domain");
}

void ServerOverflowRejects() {
  cares::ChannelOptions options;
  cares::ServerEndpoint endpoint;
  endpoint.ip = cares::IpAddress::FromV4(cares::Ipv4Bytes{1, 2, 3, 4});
  for (int i = 0; i < 8; ++i) Check(options.AddServer(endpoint).has_value(), "push");
  Check(options.servers.size() == 8, "eight");
  endpoint.port = 99;
  const auto ninth = options.AddServer(endpoint);
  Check(!ninth && ninth.error() == SlabFull(), "ninth");
  Check(options.servers.size() == 8 && options.servers[7].port == 53, "unchanged");
}

void PathBounds() {
  cares::ChannelOptions options;
  std::array<char, 256> bytes{{}};
  for (char& byte : bytes) byte = 'a';
  const auto too_long = options.SetResolvconfPath(std::string_view{bytes.data(), 256});
  Check(!too_long && too_long.error() == SlabFull(), "path_256");
  Check(options.resolvconf_path.is_empty(), "unchanged");
  const auto embedded = options.SetHostsPath(std::string_view{"ab\0c", 4});
  Check(!embedded && embedded.error() == cares::Error::InvalidArgument(), "nul");
  Check(options.hosts_path.is_empty(), "nul_unchanged");
  cares::ChannelOptions fit;
  const auto stored = fit.SetHostsPath(std::string_view{bytes.data(), 255});
  Check(stored.has_value(), "path_255");
  Check(fit.hosts_path.size() == 255, "len_255");
  Check(fit.hosts_path.bytes[255] == '\0', "trailing_nul");
  const auto cleared = fit.SetHostsPath({});
  Check(cleared.has_value() && fit.hosts_path.is_empty(), "clear");
}

void SearchDomainRules() {
  cares::ChannelOptions options;
  const auto one = options.AddSearchDomain("lab.internal");
  Check(one.has_value() && options.search_domains[0].View() == "lab.internal", "copied");
  Check(options.search_domains[0].name[12] == '\0', "domain_nul");
  std::array<char, 129> huge{{}};
  for (char& byte : huge) byte = 'd';
  const auto too_long = options.AddSearchDomain(std::string_view{huge.data(), 128});
  Check(!too_long && too_long.error() == SlabFull(), "len_128");
  Check(options.search_domains.size() == 1, "count_stays");
  std::array<char, 127> exact{{}};
  for (char& byte : exact) byte = 'e';
  cares::ChannelOptions wide;
  const auto fitted = wide.AddSearchDomain(std::string_view{exact.data(), 127});
  Check(fitted.has_value(), "len_127");
  Check(wide.search_domains[0].len == 127 && wide.search_domains[0].name[127] == '\0', "nul_127");
  const auto embedded = options.AddSearchDomain(std::string_view{"a\0b", 3});
  Check(!embedded && embedded.error() == cares::Error::FromAres(ARES_EBADNAME), "embedded");
  const auto empty = options.AddSearchDomain({});
  Check(!empty && empty.error() == cares::Error::FromAres(ARES_EBADNAME), "empty");
  cares::ChannelOptions full;
  for (int i = 0; i < 6; ++i) Check(full.AddSearchDomain("a.b").has_value(), "six");
  const auto seventh = full.AddSearchDomain("c.d");
  Check(!seventh && seventh.error() == SlabFull() && full.search_domains.size() == 6, "seventh");
}

}  // namespace

int main() {
  DefaultsMatchContract();
  BuildersStoreValues();
  ServerOverflowRejects();
  PathBounds();
  SearchDomainRules();
  if (g_failed != 0) {
    std::fprintf(stderr, "options_test failed %d\n", g_failed);
    return 1;
  }
  std::fprintf(stdout, "ok options_test\n");
  return 0;
}
