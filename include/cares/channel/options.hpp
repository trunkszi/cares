/** @file @brief Fixed-capacity channel options with no heap storage. */
#pragma once

#include <ares.h>

#include <cares/error/ares_error.hpp>
#include <cares/types/host_types.hpp>
#include <cstdint>
#include <string_view>
#include <uarch/primitives.hpp>
#include <utility>

namespace cares {

/**
 * @brief Zero-heap inputs for one c-ares channel.
 * Search names and filesystem paths keep a trailing NUL so a later `char*` consumer can read them.
 * Values that do not fit are rejected; nothing is truncated.
 */
struct ChannelOptions {
  std::uint32_t timeout_ms{2000};
  std::uint32_t tries{2};
  std::uint32_t ndots{1};
  std::uint32_t udp_max_queries{0};
  std::uint16_t edns_psz{4096};
  std::uint32_t flags{ARES_FLAG_EDNS | ARES_FLAG_STAYOPEN};
  uarch::inplace_vector<ServerEndpoint, 8> servers{};
  uarch::inplace_vector<SearchDomain, 6> search_domains{};
  uarch::FixedAscii<256> resolvconf_path{};
  uarch::FixedAscii<256> hosts_path{};

  [[nodiscard]] constexpr ChannelOptions& WithTimeoutMs(std::uint32_t ms) noexcept {
    timeout_ms = ms;
    return *this;
  }
  [[nodiscard]] constexpr ChannelOptions& WithTries(std::uint32_t count) noexcept {
    tries = count;
    return *this;
  }
  [[nodiscard]] constexpr ChannelOptions& WithNdots(std::uint32_t count) noexcept {
    ndots = count;
    return *this;
  }
  [[nodiscard]] constexpr ChannelOptions& WithUdpMaxQueries(std::uint32_t max_q) noexcept {
    udp_max_queries = max_q;
    return *this;
  }
  [[nodiscard]] constexpr ChannelOptions& WithEdnsPsz(std::uint16_t size) noexcept {
    edns_psz = size;
    return *this;
  }
  [[nodiscard]] constexpr ChannelOptions& WithFlag(std::uint32_t flag) noexcept {
    flags |= flag;
    return *this;
  }

  [[nodiscard]] constexpr Result<void> AddServer(ServerEndpoint ep) noexcept {
    if (servers.try_push_back(ep) == nullptr) {
      return std::unexpected(Error::CapacityExhausted());
    }
    return {};
  }

  [[nodiscard]] constexpr Result<void> AddSearchDomain(std::string_view domain) noexcept {
    if (domain.empty() || domain.find('\0') != std::string_view::npos) {
      return std::unexpected(Error::FromAres(ARES_EBADNAME));
    }
    if (domain.size() >= 128 || search_domains.size() == 6) {
      return std::unexpected(Error::CapacityExhausted());
    }
    SearchDomain stored{};
    for (std::size_t i = 0; i < domain.size(); ++i) stored.name[i] = domain[i];
    stored.name[domain.size()] = '\0';
    stored.len = static_cast<std::uint8_t>(domain.size());
    if (search_domains.try_push_back(stored) == nullptr) {
      return std::unexpected(Error::CapacityExhausted());
    }
    return {};
  }

  [[nodiscard]] constexpr Result<void> SetResolvconfPath(std::string_view path) noexcept {
    auto stored = StorePath(path);
    if (!stored) return std::unexpected(stored.error());
    resolvconf_path = *stored;
    return {};
  }

  [[nodiscard]] constexpr Result<void> SetHostsPath(std::string_view path) noexcept {
    auto stored = StorePath(path);
    if (!stored) return std::unexpected(stored.error());
    hosts_path = *stored;
    return {};
  }

 private:
  [[nodiscard]] static constexpr Result<uarch::FixedAscii<256>> StorePath(std::string_view path) noexcept {
    if (path.find('\0') != std::string_view::npos) return std::unexpected(Error::InvalidArgument());
    if (path.size() >= 256) return std::unexpected(Error::CapacityExhausted());
    uarch::FixedAscii<256> stored{};
    for (std::size_t i = 0; i < path.size(); ++i) stored.bytes[i] = path[i];
    stored.bytes[path.size()] = '\0';
    return stored;
  }
};

}  // namespace cares
