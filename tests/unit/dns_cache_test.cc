#include <unistd.h>

#include <algorithm>
#include <array>
#include <cares/channel/channel_core.hpp>
#include <cares/resolver/dns_cache.hpp>
#include <cares/resolver/resolver_answer.hpp>
#include <cares/resolver/resolver_detail.hpp>
#include <cstdio>
#include <cstdlib>
#include <format>

namespace {

struct TempFile {
  std::array<char, 512> path{{}};
  int fd{-1};
  ~TempFile() {
    if (fd >= 0) ::close(fd);
    if (path[0] != '\0') ::unlink(path.data());
  }
  TempFile() = default;
  TempFile(const TempFile&) = delete ("temp path is owned");
  TempFile& operator=(const TempFile&) = delete ("temp path is owned");
};

[[nodiscard]] int OpenTemp(TempFile& file, const char* stem) noexcept {
  const char* root = std::getenv("TMPDIR");
  if (root == nullptr || root[0] == '\0') root = ".";
  const auto name = std::format("{}/cares-{}-{}-XXXXXX", root, stem, ::getpid());
  if (name.size() >= file.path.size()) return -1;
  std::copy(name.begin(), name.end(), file.path.begin());
  file.path[name.size()] = '\0';
  file.fd = ::mkstemp(file.path.data());
  if (file.fd < 0) file.path[0] = '\0';
  return file.fd;
}

constexpr cares::IpAddress kAddr = cares::IpAddress::FromV4({9, 9, 9, 9});
constexpr cares::IpAddress kAlias = cares::IpAddress::FromV4({1, 1, 1, 1});

constexpr std::uint64_t kNs = 1000000000ULL;

int PositiveHitsThenExpires() {
  cares::DnsCache<16> cache{cares::DnsCacheConfig{.min_ttl_sec = 1, .max_ttl_sec = 100, .negative_ttl_sec = 5}};
  const std::array<cares::IpAddress, 1> ips{{kAddr}};
  cache.InsertPositive("Cache.Example.", ips, 10, kNs);
  const auto hit = cache.Lookup("cache.example", 53, kNs);
  if (!hit || !hit->has_value() || hit->value().size() != 1 || hit->value()[0].port != 53) return __LINE__;
  if (!hit->value()[0].ip.IsV4() || hit->value()[0].ip.v4[0] != 9) return __LINE__;
  const auto expired = cache.Lookup("cache.example", 53, kNs + 10 * kNs);
  if (expired.has_value()) return __LINE__;
  cache.InsertPositive("zero.example", ips, 0, 1);
  if (cache.Lookup("zero.example", 1, 1).has_value()) return __LINE__;
  return 0;
}

int NegativeBlocksUntilTtl() {
  cares::DnsCache<16> cache{cares::DnsCacheConfig{.min_ttl_sec = 1, .max_ttl_sec = 100, .negative_ttl_sec = 4}};
  cache.InsertNegative("missing.example", cares::Error::NotFound(), 50);
  const auto blocked = cache.Lookup("missing.example", 53, 50);
  if (!blocked.has_value() || blocked->has_value() || blocked->error() != cares::Error::NotFound()) return __LINE__;
  const auto later = cache.Lookup("missing.example", 53, 50 + 4 * kNs);
  if (later.has_value()) return __LINE__;
  return 0;
}

int ClampHonorsMinMax() {
  cares::DnsCache<16> cache{cares::DnsCacheConfig{.min_ttl_sec = 10, .max_ttl_sec = 20, .negative_ttl_sec = 1}};
  const std::array<cares::IpAddress, 1> ips{{kAddr}};
  cache.InsertPositive("clamp.example", ips, 1, 0);
  if (!cache.Lookup("clamp.example", 1, 10 * kNs - 1).has_value()) return __LINE__;
  if (cache.Lookup("clamp.example", 1, 10 * kNs).has_value()) return __LINE__;
  cache.InsertPositive("clamp.example", ips, 1000, 0);
  if (!cache.Lookup("clamp.example", 1, 20 * kNs - 1).has_value()) return __LINE__;
  if (cache.Lookup("clamp.example", 1, 20 * kNs).has_value()) return __LINE__;
  return 0;
}

int EvictDropsOldest() {
  cares::DnsCache<4> cache{cares::DnsCacheConfig{.min_ttl_sec = 1, .max_ttl_sec = 100, .negative_ttl_sec = 5}};
  const std::array<cares::IpAddress, 1> ips{{kAddr}};
  cache.InsertPositive("a.example", ips, 30, 10);
  cache.InsertPositive("b.example", ips, 30, 10);
  cache.InsertPositive("c.example", ips, 30, 10);
  cache.InsertPositive("d.example", ips, 30, 10);
  cache.InsertPositive("e.example", ips, 30, 10);
  if (cache.Size() != 4) return __LINE__;
  if (cache.Lookup("a.example", 1, 10).has_value()) return __LINE__;
  if (!cache.Lookup("e.example", 1, 10).has_value()) return __LINE__;
  cache.Invalidate("E.example.");
  if (cache.Lookup("e.example", 1, 10).has_value()) return __LINE__;
  return 0;
}

int NormalizeFoldsCaseAndDot() {
  const auto key = cares::NormalizeHost("AbC.");
  if (!key || key->View() != "abc") return __LINE__;
  if (cares::NormalizeHost(".").has_value()) return __LINE__;
  if (cares::NormalizeHost("bad name").has_value()) return __LINE__;
  if (cares::NormalizeHost("a..b").has_value()) return __LINE__;
  std::array<char, 80> long_label{{}};
  for (std::size_t i = 0; i < 64; ++i) long_label[i] = 'a';
  long_label[64] = '.';
  long_label[65] = 'b';
  long_label[66] = '\0';
  if (cares::NormalizeHost(long_label.data()).has_value()) return __LINE__;
  if (!cares::NormalizeHost("a.b").has_value()) return __LINE__;
  return 0;
}

int HostsParsesAliases() {
  cares::StaticHostTable<16> table;
  const auto count = table.ParseHosts("# comment\n\n1.1.1.1 primary.Example. extra\n::1 local\n");
  if (!count || *count != 3) return __LINE__;
  const auto v4 = table.Lookup("EXTRA.", 80, cares::IpFamily::Ipv4);
  if (!v4 || v4->size() != 1 || (*v4)[0].port != 80 || !(*v4)[0].ip.IsV4()) return __LINE__;
  const auto v6 = table.Lookup("local", 1, cares::IpFamily::Ipv6);
  if (!v6 || v6->size() != 1 || !(*v6)[0].ip.IsV6()) return __LINE__;
  if (!table.Insert("manual.example", kAlias)) return __LINE__;
  if (table.Size() < 3) return __LINE__;
  return 0;
}

int HostsFullReturnsExhausted() {
  cares::StaticHostTable<4> table;
  const auto parsed =
      table.ParseHosts("1.0.0.1 a.example\n1.0.0.2 b.example\n1.0.0.3 c.example\n1.0.0.4 d.example\n1.0.0.5 e.example\n");
  if (parsed.has_value() || parsed.error() != cares::Error::CapacityExhausted()) return __LINE__;
  return 0;
}

int HostsMappedV4() {
  cares::StaticHostTable<16> table;
  const auto count = table.ParseHosts("::ffff:192.0.2.1 mapped.example\n");
  if (!count || *count != 1) return __LINE__;
  const auto hit = table.Lookup("mapped.example", 53, cares::IpFamily::Ipv6);
  if (!hit || hit->size() != 1 || !(*hit)[0].ip.IsV6()) return __LINE__;
  if ((*hit)[0].ip.v6[10] != 0xff || (*hit)[0].ip.v6[12] != 192 || (*hit)[0].ip.v6[15] != 1) return __LINE__;
  return 0;
}

int TransientNotNegativeCached() {
  cares::DnsCache<16> cache{cares::DnsCacheConfig{.min_ttl_sec = 1, .max_ttl_sec = 30, .negative_ttl_sec = 5}};
  struct Node {
    cares::DualStackWord state{};
    cares::Error error{};
    cares::EndpointList endpoints{};
    std::array<cares::IpAddress, 16> addresses{};
    std::uint8_t address_count{0};
    std::array<char, 256> host{};
    std::uint8_t host_len{0};
    std::uint16_t port{0};
    std::uint32_t min_ttl{0xffffffffu};
  };
  Node node{};
  const auto name = std::to_array("mix.example");
  node.host_len = static_cast<std::uint8_t>(sizeof(name) - 1);
  for (std::uint8_t i = 0; i < node.host_len; ++i) node.host[i] = name[i];
  node.state = cares::detail::InitNodeWord({}, 0, true, true);
  node.state = cares::detail::MarkNodeError(node.state);
  node.error = cares::detail::PreferFamilyError(cares::Error::Timeout(), cares::Error::NotFound());
  if (!node.error.IsRetryable() || node.error.IsNotFound()) return __LINE__;
  const auto now = cares::detail::NowNs();
  cares::detail::StoreNodeInCache(node, true, &cache);
  if (cache.Lookup("mix.example", 53, now).has_value()) return __LINE__;
  node.error = cares::detail::PreferFamilyError(cares::Error::NotFound(), cares::Error::NotFound());
  if (!node.error.IsNotFound()) return __LINE__;
  cares::detail::StoreNodeInCache(node, true, &cache);
  const auto neg = cache.Lookup("mix.example", 53, cares::detail::NowNs());
  if (!neg || neg->has_value() || neg->error() != cares::Error::NotFound()) return __LINE__;
  for (const int status : {ARES_EREFUSED, ARES_EFORMERR, ARES_EBADRESP, ARES_ENOMEM, ARES_EFILE, ARES_ECANCELLED}) {
    const auto real_error = cares::Error::FromAres(status);
    for (const bool no_data_first : {false, true}) {
      cares::DnsCache<16> mixed_cache{};
      const auto no_data = cares::Error::FromAres(ARES_ENODATA);
      node.error = no_data_first ? cares::detail::PreferFamilyError(no_data, real_error)
                                 : cares::detail::PreferFamilyError(real_error, no_data);
      if (node.error != real_error) return __LINE__;
      cares::detail::StoreNodeInCache(node, true, &mixed_cache);
      if (mixed_cache.Lookup("mix.example", 53, cares::detail::NowNs())) return __LINE__;
      if (cares::detail::PreferFamilyError(node.error, cares::Error::Timeout()) != cares::Error::Timeout()) return __LINE__;
      if (cares::detail::PreferFamilyError(cares::Error::Timeout(), node.error) != cares::Error::Timeout()) return __LINE__;
    }
  }
  node.addresses[0] = kAddr;
  node.address_count = 1;
  node.min_ttl = 30;
  for (const auto error : {cares::Error::Timeout(), cares::Error::FromAres(ARES_ESERVFAIL),
                           cares::Error::FromAres(ARES_ENODATA), cares::Error::NotFound()}) {
    cares::DnsCache<16> partial_cache{};
    node.error = error;
    cares::detail::StoreNodeInCache(node, true, &partial_cache);
    const auto hit = partial_cache.Lookup("mix.example", 53, cares::detail::NowNs());
    if (error.IsRetryable()) {
      if (hit) return __LINE__;
    } else if (!hit || !hit->has_value() || hit->value().size() != 1) {
      return __LINE__;
    }
  }
  return 0;
}

int ClaimSharesNeedObserver() {
  int ring_a = 0;
  int ring_b = 0;
  bool ready_a = false;
  bool ready_b = true;
  if (!cares::detail::ClaimProactor(&ring_a, 2, &ready_a)) return __LINE__;
  if (cares::detail::ClaimProactor(&ring_a, 2, &ready_b)) return __LINE__;
  if (cares::detail::ClaimProactor(&ring_a, 4, &ready_b)) return __LINE__;
  ready_a = true;
  if (!cares::detail::ClaimProactor(&ring_a, 4, &ready_b)) return __LINE__;
  if (!cares::detail::ClaimProactor(&ring_b, 2, &ready_a)) return __LINE__;
  cares::detail::ReleaseProactor(&ring_a, 2);
  cares::detail::ReleaseProactor(&ring_a, 4);
  cares::detail::ReleaseProactor(&ring_b, 2);
  if (!cares::detail::ClaimProactor(&ring_a, 2, &ready_a)) return __LINE__;
  cares::detail::ReleaseProactor(&ring_a, 2);
  return 0;
}

int LoadKeepsPrefix() {
  TempFile file;
  if (OpenTemp(file, "hosts") < 0) return __LINE__;
  std::array<char, 8300> body{{}};
  const auto line = std::to_array("9.9.9.9 kept.example\n");
  const auto line_len = sizeof(line) - 1;
  for (std::size_t i = 0; i < line_len; ++i) body[i] = line[i];
  for (std::size_t i = line_len; i < sizeof(body); ++i) body[i] = 'x';
  const auto wrote = ::write(file.fd, body.data(), sizeof(body));
  if (wrote < 0 || static_cast<std::size_t>(wrote) != sizeof(body)) return __LINE__;
  if (::close(file.fd) != 0) return __LINE__;
  file.fd = -1;
  cares::StaticHostTable<16> table;
  const auto loaded = table.LoadHostsFile(file.path.data());
  if (!loaded || *loaded != 1) return __LINE__;
  if (!table.Lookup("kept.example", 1).has_value()) return __LINE__;
  return 0;
}

struct CacheNode {
  cares::DualStackWord state{};
  cares::Error error{};
  cares::EndpointList endpoints{};
  std::array<cares::IpAddress, 16> addresses{};
  std::uint8_t address_count{0};
  std::array<char, 256> host{};
  std::uint8_t host_len{0};
  std::uint16_t port{0};
  std::uint32_t min_ttl{0xffffffffu};
};

void FillHost(CacheNode* node, const char* name) {
  node->host_len = 0;
  while (name[node->host_len] != '\0' && node->host_len < node->host.size()) {
    node->host[node->host_len] = name[node->host_len];
    ++node->host_len;
  }
}

cares::CnameRecord MakeCname(const char* target, std::uint32_t ttl) {
  cares::CnameRecord cname{};
  cname.ttl = ttl;
  while (target[cname.len] != '\0' && cname.len < cname.cname.size()) {
    cname.cname[cname.len] = target[cname.len];
    ++cname.len;
  }
  return cname;
}

int CnameChainCapsCacheTtl() {
  cares::DnsCache<16> cache{cares::DnsCacheConfig{.min_ttl_sec = 1, .max_ttl_sec = 3600, .negative_ttl_sec = 5}};
  auto pkt = cares::DnsRecord::CreateQuery("alias.example", cares::DnsType::A, cares::DnsClass::IN, 1);
  if (!pkt) return __LINE__;
  const auto cname = MakeCname("target.example", 2);
  const cares::ARecord addr{.addr = cares::IpAddress::FromV4({192, 0, 2, 10}), .ttl = 3600};
  if (!pkt->AddRr(cares::RecordSection::Answer, "alias.example", cname)) return __LINE__;
  if (!pkt->AddRr(cares::RecordSection::Answer, "target.example", addr)) return __LINE__;
  CacheNode node{};
  FillHost(&node, "alias.example");
  node.port = 53;
  node.state = cares::detail::InitNodeWord({}, 0, true, false);
  cares::detail::RememberAnswers(&node, pkt->AsRef(), cares::IpFamily::Ipv4);
  if (node.min_ttl != 2 || node.address_count != 1) return __LINE__;
  cares::detail::StoreNodeInCache(node, true, &cache);
  const auto after = cares::detail::NowNs();
  if (!cache.Lookup("alias.example", 53, after).has_value()) return __LINE__;
  if (cache.Lookup("alias.example", 53, after + 2 * kNs).has_value()) return __LINE__;
  return 0;
}

int CnameZeroNotCached() {
  cares::DnsCache<16> cache{cares::DnsCacheConfig{.min_ttl_sec = 1, .max_ttl_sec = 3600, .negative_ttl_sec = 5}};
  auto pkt = cares::DnsRecord::CreateQuery("alias0.example", cares::DnsType::A, cares::DnsClass::IN, 2);
  if (!pkt) return __LINE__;
  const auto cname = MakeCname("target0.example", 0);
  const cares::ARecord addr{.addr = cares::IpAddress::FromV4({192, 0, 2, 11}), .ttl = 3600};
  if (!pkt->AddRr(cares::RecordSection::Answer, "alias0.example", cname)) return __LINE__;
  if (!pkt->AddRr(cares::RecordSection::Answer, "target0.example", addr)) return __LINE__;
  CacheNode node{};
  FillHost(&node, "alias0.example");
  node.port = 53;
  node.state = cares::detail::InitNodeWord({}, 1, true, false);
  cares::detail::RememberAnswers(&node, pkt->AsRef(), cares::IpFamily::Ipv4);
  if (node.min_ttl != 0 || node.address_count != 1) return __LINE__;
  cares::detail::StoreNodeInCache(node, true, &cache);
  const auto after = cares::detail::NowNs();
  if (cache.Lookup("alias0.example", 53, after).has_value()) return __LINE__;
  return 0;
}

int JobGenerationReusesSlot() {
  cares::DualStackWord word{};
  uarch::Bitmap64 free_bits = uarch::Bitmap64::from_raw(1);
  for (int cycle = 0; cycle < 70001; ++cycle) {
    if (!free_bits.test(0)) return __LINE__;
    free_bits = free_bits.clear(0);
    word = cares::detail::InitNodeWord(word, 0, true, false);
    const auto gen = cares::detail::NodeGeneration(word);
    if (gen == 0 || cares::detail::NodeEpoch(word) != gen) return __LINE__;
    word = cares::detail::RetireNodeWord(word);
    free_bits = free_bits.set(0);
    if (cares::detail::NodeLive(word)) return __LINE__;
  }
  if (!free_bits.test(0)) return __LINE__;
  word = word.with<^^cares::DualStackWordSpec::generation>(0xFFFEu);
  const auto wrapped = cares::detail::BumpNodeGeneration(word);
  if (cares::detail::NodeGeneration(wrapped) != 1u || cares::detail::NodeEpoch(wrapped) != 1u) return __LINE__;
  return 0;
}

int HostsFamilyMissAuthoritative() {
  cares::StaticHostTable<16> table;
  if (!table.Insert("v4only.example", cares::IpAddress::FromV4({192, 0, 2, 9}))) return __LINE__;
  const auto v6 = table.Lookup("v4only.example", 53, cares::IpFamily::Ipv6);
  if (!v6 || !v6->empty()) return __LINE__;
  const auto v4 = table.Lookup("v4only.example", 53, cares::IpFamily::Ipv4);
  if (!v4 || v4->size() != 1) return __LINE__;
  if (table.Lookup("absent.example", 53, cares::IpFamily::Ipv6).has_value()) return __LINE__;
  cares::DnsCache<16> cache{cares::DnsCacheConfig{.min_ttl_sec = 1, .max_ttl_sec = 30, .negative_ttl_sec = 1}};
  const cares::IpAddress v6addr = cares::IpAddress::FromV6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
  cache.InsertPositive("v4only.example", std::span<const cares::IpAddress>{&v6addr, 1}, 30, 10);
  cares::ParsedEndpoint parsed{};
  parsed.host = "v4only.example";
  parsed.port = 53;
  const auto fast = cares::detail::LookupFastPath(parsed, cares::IpFamily::Ipv6, true, table, &cache);
  if (!fast || fast->has_value() || fast->error() != cares::Error::NotFound()) return __LINE__;
  return 0;
}

int ExtractKeepsTypedError() {
  auto pkt = cares::DnsRecord::CreateQuery("mix.example", cares::DnsType::ANY, cares::DnsClass::IN, 7);
  if (!pkt) return __LINE__;
  const cares::ARecord addr{.addr = cares::IpAddress::FromV4({192, 0, 2, 8}), .ttl = 30};
  if (!pkt->AddRr(cares::RecordSection::Answer, "mix.example", addr)) return __LINE__;
  auto missing = cares::detail::ExtractFromWire<cares::TxtRecord>(pkt->AsRef());
  if (missing || missing.error() != cares::Error::NotFound()) return __LINE__;
  auto txt = pkt->RrAdd(cares::RecordSection::Answer, "mix.example", cares::DnsType::TXT, cares::DnsClass::IN, 30);
  if (!txt) return __LINE__;
  std::array<unsigned char, 255> chunk{};
  chunk.fill('t');
  for (int n = 0; n < 256; ++n) {
    if (ares_dns_rr_add_abin(*txt, ARES_RR_TXT_DATA, chunk.data(), chunk.size()) != ARES_SUCCESS) return __LINE__;
  }
  auto bad = cares::detail::ExtractFromWire<cares::TxtRecord>(pkt->AsRef());
  if (bad || bad.error() != cares::Error::BadResponse()) return __LINE__;
  auto good = cares::detail::ExtractFromWire<cares::ARecord>(pkt->AsRef());
  if (!good || good->ttl != 30u) return __LINE__;
  return 0;
}

int CopyTextRejectsInteriorNul() {
  const std::array<char, 3> raw{{'a', '\0', 'b'}};
  auto copied = cares::detail::CopyText<256>(std::string_view{raw.data(), 3});
  if (copied || copied.error() != cares::Error::BadName()) return __LINE__;
  auto ok = cares::detail::CopyText<256>("ok.example");
  if (!ok || ok->len != 10) return __LINE__;
  return 0;
}

int LoadReadsFile() {
  TempFile file;
  if (OpenTemp(file, "hosts") < 0) return __LINE__;
  const auto line = std::to_array("9.9.9.9 file-host.example alias-host\n");
  const auto wrote = ::write(file.fd, line.data(), sizeof(line) - 1);
  if (wrote < 0 || static_cast<std::size_t>(wrote) != sizeof(line) - 1) return __LINE__;
  if (::close(file.fd) != 0) return __LINE__;
  file.fd = -1;
  cares::StaticHostTable<16> table;
  const auto loaded = table.LoadHostsFile(file.path.data());
  if (!loaded || *loaded != 2) return __LINE__;
  const auto hit = table.Lookup("file-host.example", 53);
  if (!hit || hit->empty()) return __LINE__;
  const auto rejected = table.LoadHostsFile("");
  if (rejected.has_value() || rejected.error() != cares::Error::InvalidArgument()) return __LINE__;
  return 0;
}

}  // namespace

int main() {
  const std::array<int, 18> tests{{PositiveHitsThenExpires(), NegativeBlocksUntilTtl(), ClampHonorsMinMax(), EvictDropsOldest(),
                                   NormalizeFoldsCaseAndDot(), HostsParsesAliases(), HostsFullReturnsExhausted(),
                                   HostsMappedV4(), TransientNotNegativeCached(), ClaimSharesNeedObserver(), LoadKeepsPrefix(),
                                   LoadReadsFile(), CnameChainCapsCacheTtl(), CnameZeroNotCached(), JobGenerationReusesSlot(),
                                   HostsFamilyMissAuthoritative(), ExtractKeepsTypedError(), CopyTextRejectsInteriorNul()}};
  for (int line : tests) {
    if (line != 0) {
      std::fprintf(stderr, "dns_cache_test failed at line %d\n", line);
      return line;
    }
  }
  return 0;
}
