/** @file @brief Preallocated static hosts table and TTL DNS cache. */
#pragma once

#include <array>
#include <bit>
#include <cares/error/ares_error.hpp>
#include <cares/types/endpoint.hpp>
#include <cares/types/host_types.hpp>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <uarch/uarch.hpp>
#include <utility>

namespace cares {

/** @brief Normalized host key. One trailing dot is removed and ASCII letters are folded. */
struct HostKey {
  std::array<char, 256> bytes{};
  std::uint8_t len{0};

  [[nodiscard]] constexpr std::string_view View() const noexcept { return {bytes.data(), len}; }
  [[nodiscard]] constexpr bool Equals(const HostKey& other) const noexcept {
    if (len != other.len) return false;
    for (std::uint8_t i = 0; i < len; ++i) {
      if (bytes[i] != other.bytes[i]) return false;
    }
    return true;
  }
};

/**
 * @brief Fold ASCII and strip one trailing dot.
 * Empty labels and labels longer than 63 octets are rejected, matching QNAME encoding.
 * Whitespace cannot appear in a host key.
 */
[[nodiscard]] constexpr std::optional<HostKey> NormalizeHost(std::string_view host) noexcept {
  if (!host.empty() && host.back() == '.') host.remove_suffix(1);
  if (host.empty() || host.size() > 255) return std::nullopt;
  HostKey key{};
  std::size_t label = 0;
  std::size_t out = 0;
  for (const char byte : host) {
    const auto raw = static_cast<unsigned char>(byte);
    if (raw <= 0x20u || raw == 0x7fu) return std::nullopt;
    if (raw == '.') {
      if (label == 0 || label > 63) return std::nullopt;
      label = 0;
      key.bytes[out++] = '.';
      continue;
    }
    ++label;
    if (label > 63) return std::nullopt;
    const auto folded = (raw >= 'A' && raw <= 'Z') ? static_cast<unsigned char>(raw - 'A' + 'a') : raw;
    key.bytes[out++] = static_cast<char>(folded);
  }
  if (label == 0 || label > 63) return std::nullopt;
  key.len = static_cast<std::uint8_t>(out);
  return key;
}

namespace detail {

[[nodiscard]] constexpr int HexValue(char ch) noexcept {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

[[nodiscard]] constexpr std::optional<Ipv4Bytes> ParseV4(std::string_view text) noexcept {
  Ipv4Bytes out{};
  std::size_t index = 0;
  for (int octet = 0; octet < 4; ++octet) {
    if (index >= text.size()) return std::nullopt;
    unsigned value = 0;
    int digits = 0;
    while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
      value = value * 10u + static_cast<unsigned>(text[index] - '0');
      ++digits;
      ++index;
      if (value > 255u || digits > 3) return std::nullopt;
    }
    if (digits == 0) return std::nullopt;
    out[static_cast<std::size_t>(octet)] = static_cast<std::uint8_t>(value);
    if (octet < 3) {
      if (index >= text.size() || text[index] != '.') return std::nullopt;
      ++index;
    }
  }
  if (index != text.size()) return std::nullopt;
  return out;
}

[[nodiscard]] constexpr std::optional<Ipv6Bytes> ParseV6(std::string_view text) noexcept {
  if (text.empty() || text.size() > 45) return std::nullopt;
  std::array<int, 8> groups{};
  int count = 0;
  int compress_at = -1;
  std::size_t index = 0;
  if (text[0] == ':') {
    if (text.size() < 2 || text[1] != ':') return std::nullopt;
    compress_at = 0;
    index = 2;
  }
  while (index < text.size()) {
    if (text[index] == ':') {
      if (compress_at >= 0) return std::nullopt;
      compress_at = count;
      ++index;
      if (index >= text.size()) break;
      continue;
    }
    if (count >= 8) return std::nullopt;
    std::size_t token = index;
    bool dotted = false;
    while (token < text.size() && text[token] != ':') {
      dotted = dotted || text[token] == '.';
      ++token;
    }
    if (dotted) {
      if (count > 6) return std::nullopt;
      const auto v4 = ParseV4(text.substr(index, token - index));
      if (!v4.has_value() || token != text.size()) return std::nullopt;
      groups[static_cast<std::size_t>(count++)] = (static_cast<int>((*v4)[0]) << 8) | static_cast<int>((*v4)[1]);
      groups[static_cast<std::size_t>(count++)] = (static_cast<int>((*v4)[2]) << 8) | static_cast<int>((*v4)[3]);
      break;
    }
    int value = 0;
    int digits = 0;
    while (index < text.size() && digits < 4) {
      const int hex = HexValue(text[index]);
      if (hex < 0) break;
      value = (value << 4) | hex;
      ++digits;
      ++index;
    }
    if (digits == 0) return std::nullopt;
    groups[static_cast<std::size_t>(count)] = value;
    ++count;
    if (index >= text.size()) break;
    if (text[index] != ':') return std::nullopt;
    ++index;
    if (index >= text.size()) return std::nullopt;
  }
  if (compress_at < 0) {
    if (count != 8) return std::nullopt;
  } else {
    const int tail = count - compress_at;
    if (tail < 0 || count > 7) return std::nullopt;
    const int zeros = 8 - count;
    std::array<int, 8> expanded{};
    for (int i = 0; i < compress_at; ++i) expanded[static_cast<std::size_t>(i)] = groups[static_cast<std::size_t>(i)];
    for (int i = 0; i < tail; ++i) {
      expanded[(static_cast<std::size_t>(compress_at) + static_cast<std::size_t>(zeros) + static_cast<std::size_t>(i))] =
          groups[(static_cast<std::size_t>(compress_at) + static_cast<std::size_t>(i))];
    }
    groups = expanded;
  }
  Ipv6Bytes out{};
  for (int i = 0; i < 8; ++i) {
    const auto value = groups[static_cast<std::size_t>(i)];
    out[(static_cast<std::size_t>(i) * 2)] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    out[(static_cast<std::size_t>(i) * 2 + 1)] = static_cast<std::uint8_t>(value & 0xff);
  }
  return out;
}

[[nodiscard]] constexpr std::optional<IpAddress> ParseIpToken(std::string_view text) noexcept {
  if (const auto v4 = ParseV4(text); v4.has_value()) return IpAddress::FromV4(*v4);
  if (const auto v6 = ParseV6(text); v6.has_value()) return IpAddress::FromV6(*v6);
  return std::nullopt;
}

template <std::size_t Cap>
[[nodiscard]] constexpr std::size_t Bucket(std::uint64_t hash) noexcept {
  static_assert(Cap > 0 && std::has_single_bit(Cap));
  constexpr unsigned kLog = std::countr_zero(Cap);
  return static_cast<std::size_t>(uarch::PowerOfTwo<kLog>::rem(hash));
}

inline constexpr std::size_t kProbeLimit = 4;

enum class SlotState : std::uint8_t { Empty = 0, Live = 1, Tomb = 2 };

template <std::size_t Cap>
[[nodiscard]] constexpr std::uint64_t HostHash(const HostKey& key) noexcept {
  return uarch::fnv1a64(key.View());
}

}  // namespace detail

/**
 * @brief Fixed host override table. Lookup probes a constant number of slots.
 * @tparam MaxHosts Power-of-two capacity, fully constructed with the table.
 */
template <std::size_t MaxHosts = 64>
class StaticHostTable {
 public:
  static_assert(MaxHosts >= 4 && std::has_single_bit(MaxHosts));
  static constexpr std::size_t kMaxAddresses = 16;

  constexpr StaticHostTable() noexcept = default;

  [[nodiscard]] constexpr std::size_t Size() const noexcept { return live_; }

  [[nodiscard]] constexpr Result<void> Insert(std::string_view host, IpAddress address) noexcept {
    const auto stored = Append(address, host);
    if (!stored.has_value()) return std::unexpected(stored.error());
    if (!*stored) return std::unexpected(Error::BadName());
    return {};
  }

  constexpr void Clear() noexcept {
    entries_.fill(Entry{});
    live_ = 0;
  }

  [[nodiscard]] constexpr std::optional<EndpointList> Lookup(std::string_view host, std::uint16_t port,
                                                             IpFamily family = IpFamily::DualStack) const noexcept {
    const auto key = NormalizeHost(host);
    if (!key.has_value()) return std::nullopt;
    const auto slot = FindLive(*key);
    if (!slot.has_value()) return std::nullopt;
    EndpointList list{};
    const auto& entry = entries_[*slot];
    for (std::uint8_t i = 0; i < entry.address_count; ++i) {
      const bool v4 = entry.addresses[i].IsV4();
      const bool v6 = entry.addresses[i].IsV6();
      const bool take = family == IpFamily::DualStack || family == IpFamily::Unspec || (family == IpFamily::Ipv4 && v4) ||
                        (family == IpFamily::Ipv6 && v6);
      if (take) static_cast<void>(list.try_push_back(Endpoint{entry.addresses[i], port}));
    }
    return list;
  }

  /** @brief Parse an /etc/hosts document. A failed insert is returned, not dropped. */
  [[nodiscard]] constexpr Result<std::size_t> ParseHosts(std::string_view text) noexcept {
    std::size_t names = 0;
    std::size_t cursor = 0;
    while (cursor < text.size()) {
      std::size_t end = cursor;
      while (end < text.size() && text[end] != '\n') ++end;
      auto line = text.substr(cursor, end - cursor);
      if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
      cursor = end < text.size() ? end + 1 : end;
      auto added = IngestLine(line);
      if (!added.has_value()) return std::unexpected(added.error());
      names += *added;
    }
    return names;
  }

  /**
   * @brief Read a hosts file into the fixed table.
   * A file longer than the 8 KiB window is parsed through the last complete line in that window.
   */
  [[nodiscard]] Result<std::size_t> LoadHostsFile(std::string_view path = "/etc/hosts") noexcept {
    if (path.empty() || path.size() >= 512) return std::unexpected(Error::InvalidArgument());
    std::array<char, 512> path_buf{};
    for (std::size_t i = 0; i < path.size(); ++i) path_buf[i] = path[i];
    std::FILE* file = std::fopen(path_buf.data(), "re");
    if (file == nullptr) return std::unexpected(Error::FromErrno(errno));
    std::array<char, 8192> body{};
    const auto read = std::fread(body.data(), 1, body.size(), file);
    const int err = std::ferror(file);
    char extra_byte = '\0';
    const auto extra = std::fread(&extra_byte, 1, 1, file);
    std::fclose(file);
    if (err != 0) return std::unexpected(Error::FromErrno(EIO));
    std::size_t keep = read;
    if (extra != 0) {
      while (keep > 0 && body[keep - 1] != '\n') --keep;
    }
    return ParseHosts(std::string_view{body.data(), keep});
  }

 private:
  struct Entry {
    HostKey key{};
    std::array<IpAddress, kMaxAddresses> addresses{};
    std::uint8_t address_count{0};
    detail::SlotState state{detail::SlotState::Empty};
  };

  [[nodiscard]] constexpr std::optional<std::size_t> FindLive(const HostKey& key) const noexcept {
    const auto start = detail::Bucket<MaxHosts>(detail::HostHash<MaxHosts>(key));
    for (std::size_t probe = 0; probe < detail::kProbeLimit && probe < MaxHosts; ++probe) {
      const auto index = (start + probe) & (MaxHosts - 1);
      const auto& entry = entries_[index];
      if (entry.state == detail::SlotState::Empty) return std::nullopt;
      if (entry.state == detail::SlotState::Live && entry.key.Equals(key)) return index;
    }
    return std::nullopt;
  }

  [[nodiscard]] constexpr std::optional<std::size_t> Place(const HostKey& key) noexcept {
    if (const auto existing = FindLive(key); existing.has_value()) return existing;
    const auto start = detail::Bucket<MaxHosts>(detail::HostHash<MaxHosts>(key));
    std::optional<std::size_t> tomb{};
    for (std::size_t probe = 0; probe < detail::kProbeLimit && probe < MaxHosts; ++probe) {
      const auto index = (start + probe) & (MaxHosts - 1);
      const auto state = entries_[index].state;
      if (state == detail::SlotState::Empty) return tomb.has_value() ? tomb : std::optional<std::size_t>{index};
      if (state == detail::SlotState::Tomb && !tomb.has_value()) tomb = index;
    }
    return tomb;
  }

  [[nodiscard]] constexpr Result<std::size_t> IngestLine(std::string_view line) noexcept {
    std::size_t index = 0;
    while (index < line.size() && (line[index] == ' ' || line[index] == '\t')) ++index;
    if (index >= line.size() || line[index] == '#') return 0;
    const auto ip_begin = index;
    while (index < line.size() && line[index] != ' ' && line[index] != '\t' && line[index] != '#') ++index;
    const auto ip = detail::ParseIpToken(line.substr(ip_begin, index - ip_begin));
    if (!ip.has_value()) return 0;
    std::size_t added = 0;
    while (index < line.size() && line[index] != '#') {
      while (index < line.size() && (line[index] == ' ' || line[index] == '\t')) ++index;
      if (index >= line.size() || line[index] == '#') break;
      const auto name_begin = index;
      while (index < line.size() && line[index] != ' ' && line[index] != '\t' && line[index] != '#') ++index;
      auto stored = Append(*ip, line.substr(name_begin, index - name_begin));
      if (!stored.has_value()) return std::unexpected(stored.error());
      if (*stored) ++added;
    }
    return added;
  }

  [[nodiscard]] constexpr Result<bool> Append(const IpAddress& ip, std::string_view host) noexcept {
    const auto key = NormalizeHost(host);
    if (!key.has_value()) return false;
    const auto slot = Place(*key);
    if (!slot.has_value()) return std::unexpected(Error::CapacityExhausted());
    auto& entry = entries_[*slot];
    if (entry.state != detail::SlotState::Live) {
      entry = Entry{};
      entry.key = *key;
      entry.state = detail::SlotState::Live;
      ++live_;
    }
    for (std::uint8_t i = 0; i < entry.address_count; ++i) {
      if (entry.addresses[i] == ip) return true;
    }
    if (entry.address_count >= kMaxAddresses) return std::unexpected(Error::CapacityExhausted());
    entry.addresses[entry.address_count] = ip;
    ++entry.address_count;
    return true;
  }

  std::array<Entry, MaxHosts> entries_{};
  std::size_t live_{0};
};

/** @brief TTL bounds applied to positive cache inserts. Negative entries use `negative_ttl_sec`. */
struct DnsCacheConfig {
  std::uint32_t min_ttl_sec{1};
  std::uint32_t max_ttl_sec{300};
  std::uint32_t negative_ttl_sec{5};
};

/**
 * @brief Direct-probed TTL cache. Storage is the object itself.
 * A full probe window drops an expired entry, or the oldest live entry when none has expired.
 * @tparam MaxEntries Power-of-two slot count.
 */
template <std::size_t MaxEntries = 256>
class DnsCache {
 public:
  static_assert(MaxEntries >= 4 && std::has_single_bit(MaxEntries));
  static constexpr std::size_t kMaxAddresses = 16;

  explicit constexpr DnsCache(DnsCacheConfig config = {}) noexcept : config_(config) {}

  [[nodiscard]] constexpr const DnsCacheConfig& Config() const noexcept { return config_; }
  [[nodiscard]] constexpr std::size_t Size() const noexcept { return live_; }

  [[nodiscard]] constexpr std::optional<Result<EndpointList>> Lookup(std::string_view host, std::uint16_t port,
                                                                     std::uint64_t now_ns) noexcept {
    const auto key = NormalizeHost(host);
    if (!key.has_value()) return std::nullopt;
    const auto slot = FindLive(*key, now_ns);
    if (!slot.has_value()) return std::nullopt;
    const auto& entry = entries_[*slot];
    if (entry.negative != 0) return std::optional<Result<EndpointList>>{std::unexpected(entry.error)};
    EndpointList list{};
    for (std::uint8_t i = 0; i < entry.address_count; ++i) list.try_push_back(Endpoint{entry.addresses[i], port});
    return list;
  }

  constexpr void InsertPositive(std::string_view host, std::span<const IpAddress> addresses, std::uint32_t ttl_sec,
                                std::uint64_t now_ns) noexcept {
    if (addresses.empty() || addresses.size() > kMaxAddresses) return;
    // A DNS TTL of zero means "do not cache" and is not raised to the configured floor.
    if (ttl_sec == 0) return;
    auto ttl = ttl_sec;
    if (config_.min_ttl_sec != 0 && ttl < config_.min_ttl_sec) ttl = config_.min_ttl_sec;
    if (config_.max_ttl_sec != 0 && ttl > config_.max_ttl_sec) ttl = config_.max_ttl_sec;
    Write(host, addresses, ttl, now_ns, false, {});
  }

  constexpr void InsertNegative(std::string_view host, Error err, std::uint64_t now_ns) noexcept {
    if (config_.negative_ttl_sec == 0) return;
    Write(host, {}, config_.negative_ttl_sec, now_ns, true, err);
  }

  constexpr void Invalidate(std::string_view host) noexcept {
    const auto key = NormalizeHost(host);
    if (!key.has_value()) return;
    const auto start = detail::Bucket<MaxEntries>(detail::HostHash<MaxEntries>(*key));
    for (std::size_t probe = 0; probe < detail::kProbeLimit && probe < MaxEntries; ++probe) {
      const auto index = (start + probe) & (MaxEntries - 1);
      const auto& entry = entries_[index];
      if (entry.state == detail::SlotState::Empty) return;
      if (entry.state == detail::SlotState::Live && entry.key.Equals(*key)) {
        Retire(index);
        return;
      }
    }
  }

  constexpr void Clear() noexcept {
    entries_.fill(Entry{});
    live_ = 0;
  }

 private:
  static constexpr std::uint64_t kNsPerSec = 1000000000ULL;

  struct Entry {
    HostKey key{};
    std::array<IpAddress, kMaxAddresses> addresses{};
    Error error{};
    std::uint64_t expiry_ns{0};
    std::uint64_t born{0};
    std::uint8_t address_count{0};
    std::uint8_t negative{0};
    detail::SlotState state{detail::SlotState::Empty};
  };

  [[nodiscard]] constexpr std::optional<std::size_t> FindLive(const HostKey& key, std::uint64_t now_ns) noexcept {
    const auto start = detail::Bucket<MaxEntries>(detail::HostHash<MaxEntries>(key));
    for (std::size_t probe = 0; probe < detail::kProbeLimit && probe < MaxEntries; ++probe) {
      const auto index = (start + probe) & (MaxEntries - 1);
      auto& entry = entries_[index];
      if (entry.state == detail::SlotState::Empty) return std::nullopt;
      if (entry.state != detail::SlotState::Live || !entry.key.Equals(key)) continue;
      if (now_ns >= entry.expiry_ns) {
        Retire(index);
        return std::nullopt;
      }
      return index;
    }
    return std::nullopt;
  }

  constexpr void Retire(std::size_t index) noexcept {
    if (entries_[index].state == detail::SlotState::Live && live_ > 0) --live_;
    entries_[index].state = detail::SlotState::Tomb;
    entries_[index].address_count = 0;
    entries_[index].negative = 0;
    entries_[index].error = {};
  }

  [[nodiscard]] constexpr std::optional<std::size_t> Select(const HostKey& key, std::uint64_t now_ns) noexcept {
    const auto start = detail::Bucket<MaxEntries>(detail::HostHash<MaxEntries>(key));
    std::optional<std::size_t> tomb{};
    std::optional<std::size_t> expired{};
    std::optional<std::size_t> oldest{};
    std::uint64_t oldest_born = ~std::uint64_t{0};
    for (std::size_t probe = 0; probe < detail::kProbeLimit && probe < MaxEntries; ++probe) {
      const auto index = (start + probe) & (MaxEntries - 1);
      auto& entry = entries_[index];
      if (entry.state == detail::SlotState::Live && entry.key.Equals(key)) return index;
      if (entry.state == detail::SlotState::Empty) return tomb.has_value() ? tomb : std::optional<std::size_t>{index};
      if (entry.state == detail::SlotState::Tomb) {
        if (!tomb.has_value()) tomb = index;
        continue;
      }
      if (now_ns >= entry.expiry_ns) {
        if (!expired.has_value()) expired = index;
        continue;
      }
      if (entry.born < oldest_born) {
        oldest_born = entry.born;
        oldest = index;
      }
    }
    if (tomb.has_value()) return tomb;
    if (expired.has_value()) return expired;
    return oldest;
  }

  constexpr void Write(std::string_view host, std::span<const IpAddress> addresses, std::uint32_t ttl_sec, std::uint64_t now_ns,
                       bool negative, Error err) noexcept {
    const auto key = NormalizeHost(host);
    if (!key.has_value()) return;
    const auto chosen = Select(*key, now_ns);
    if (!chosen.has_value()) return;
    auto& entry = entries_[*chosen];
    const bool was_live = entry.state == detail::SlotState::Live;
    entry = Entry{};
    entry.key = *key;
    const auto ttl_ns = uarch::saturating_mul(static_cast<std::uint64_t>(ttl_sec), kNsPerSec);
    entry.expiry_ns = uarch::saturating_add(now_ns, ttl_ns);
    entry.born = uarch::saturating_add(clock_, std::uint64_t{1});
    clock_ = entry.born;
    entry.negative = negative ? 1u : 0u;
    entry.error = negative ? err : Error{};
    entry.address_count = static_cast<std::uint8_t>(addresses.size());
    for (std::size_t i = 0; i < addresses.size(); ++i) entry.addresses[i] = addresses[i];
    entry.state = detail::SlotState::Live;
    if (!was_live) ++live_;
  }

  DnsCacheConfig config_{};
  std::array<Entry, MaxEntries> entries_{};
  std::uint64_t clock_{0};
  std::size_t live_{0};
};

}  // namespace cares
