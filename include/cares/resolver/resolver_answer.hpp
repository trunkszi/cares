/** @file
 *  @brief Answer ordering, cache admission, and pinned-pool lifetime for `cares::Resolver`.
 */
#pragma once

#include <ares.h>
#include <ares_dns_record.h>

#include <array>
#include <cares/error/ares_error.hpp>
#include <cares/record/dns_record.hpp>
#include <cares/record/record_extract.hpp>
#include <cares/resolver/dns_cache.hpp>
#include <cares/resolver/poll_table.hpp>
#include <cares/resolver/resolver_detail.hpp>
#include <cares/types/dns_types.hpp>
#include <cares/types/endpoint.hpp>
#include <cares/types/host_types.hpp>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <uring/uring.hpp>
#include <utility>

#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/lsan_interface.h>
#define CARES_HAS_LSAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#include <sanitizer/lsan_interface.h>
#define CARES_HAS_LSAN 1
#endif
#endif

namespace cares::detail {

[[nodiscard]] inline Error PreferFamilyError(Error current, Error incoming) noexcept;

template <typename Node>
inline void OrderAnswers(Node* node) noexcept;

template <typename Node>
inline void RememberAnswers(Node* node, const DnsRecordRef& record, IpFamily family) noexcept {
  if (node == nullptr) return;
  if (!record.IsValid() || record.Rcode() == DnsRcode::NxDomain) {
    node->state = MarkNodeError(node->state);
    node->error = PreferFamilyError(node->error, Error::NotFound());
    return;
  }
  const auto count = record.RrCount(RecordSection::Answer);
  for (std::size_t i = 0; i < count; ++i) {
    const auto* rr = record.RrRawAt(RecordSection::Answer, i);
    if (rr == nullptr) continue;
    const auto type = static_cast<DnsType>(ares_dns_rr_get_type(rr));
    const auto ttl = ares_dns_rr_get_ttl(rr);
    if (type == DnsType::CNAME) {
      if (ttl < node->min_ttl) node->min_ttl = ttl;
      continue;
    }
    std::optional<IpAddress> ip;
    if (type == DnsType::A) {
      if (const auto* addr = ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR); addr != nullptr) {
        Ipv4Bytes bytes{};
        std::memcpy(bytes.data(), addr, bytes.size());
        ip = IpAddress::FromV4(bytes);
      }
    } else if (type == DnsType::AAAA) {
      if (const auto* addr = ares_dns_rr_get_addr6(rr, ARES_RR_AAAA_ADDR); addr != nullptr) {
        Ipv6Bytes bytes{};
        std::memcpy(bytes.data(), addr->_S6_un._S6_u8, bytes.size());
        ip = IpAddress::FromV6(bytes);
      }
    }
    if (!ip.has_value() || !FamilyAccepts(family, *ip)) continue;
    bool duplicate = false;
    for (std::uint8_t n = 0; n < node->address_count; ++n) duplicate = duplicate || node->addresses[n] == *ip;
    if (duplicate || node->address_count >= node->addresses.size()) continue;
    node->addresses[node->address_count++] = *ip;
    if (ttl < node->min_ttl) node->min_ttl = ttl;
  }
  OrderAnswers(node);
}

template <std::size_t MaxSockets>
[[nodiscard]] inline std::uint16_t HandlePollCqe(std::span<PollArm, MaxSockets> arms, PollTable<MaxSockets>* polls,
                                                 std::span<ares_fd_events_t, MaxSockets> ready, std::uint16_t ready_count,
                                                 uring::UserDataToken token, std::int32_t result) noexcept {
  for (std::uint16_t slot = 0; slot < arms.size(); ++slot) {
    auto& arm = arms[slot];
    if (arm.remove_live && arm.remove.raw() != 0 && SameToken(token, arm.remove)) {
      arm.remove_live = false;
      return ready_count;
    }
    if (!arm.poll_live || arm.poll.raw() == 0 || !SameToken(token, arm.poll)) continue;
    const bool was_cancelled = arm.cancel_requested || result == -ECANCELED;
    arm.poll_live = false;
    arm.cancel_requested = false;
    arm.cancel_retry = false;
    if (!was_cancelled && polls != nullptr) {
      if (auto event = polls->OnPollCqe(slot, arm.generation, result); event && ready_count < ready.size()) {
        ready[ready_count].fd = event->fd;
        ready[ready_count].events = event->events;
        ++ready_count;
      }
    }
    return ready_count;
  }
  return ready_count;
}

template <std::size_t MaxStaticHosts, std::size_t MaxCacheEntries>
[[nodiscard]] inline std::optional<Result<EndpointList>> LookupFastPath(const ParsedEndpoint& parsed, IpFamily family,
                                                                        bool enable_cache,
                                                                        const StaticHostTable<MaxStaticHosts>& hosts,
                                                                        DnsCache<MaxCacheEntries>* cache) noexcept {
  if (auto ip = ParseIpLiteral(parsed.host); ip) {
    if (!FamilyAccepts(family, *ip)) return Result<EndpointList>{std::unexpected(Error::NotFound())};
    EndpointList list{};
    if (!list.try_push_back(Endpoint{*ip, parsed.port})) {
      return Result<EndpointList>{std::unexpected(Error::CapacityExhausted())};
    }
    return list;
  }
  if (auto hit = hosts.Lookup(parsed.host, parsed.port, family); hit) {
    if (hit->empty()) return Result<EndpointList>{std::unexpected(Error::NotFound())};
    return std::move(*hit);
  }
  if (enable_cache && cache != nullptr) {
    if (auto hit = cache->Lookup(parsed.host, parsed.port, NowNs()); hit) return std::move(*hit);
  }
  return std::nullopt;
}

template <typename Node, std::size_t MaxCacheEntries>
inline void StoreNodeInCache(const Node& node, bool enable_cache, DnsCache<MaxCacheEntries>* cache) noexcept {
  if (!enable_cache || cache == nullptr || node.host_len == 0) return;
  const auto host = std::string_view{node.host.data(), node.host_len};
  if (node.address_count == 0) {
    if (NodeSawError(node.state) && node.error.IsNotFound() && !node.error.IsRetryable()) {
      cache->InsertNegative(host, node.error, NowNs());
    }
    return;
  }
  // A host-keyed entry must not hide a family that can succeed on retry.
  if (NodeSawError(node.state) && !node.error.IsNotFound()) return;
  if (node.min_ttl == 0) return;
  const auto ttl = node.min_ttl == 0xffffffffu ? 0u : node.min_ttl;
  if (ttl == 0) return;
  cache->InsertPositive(host, std::span<const IpAddress>{node.addresses.data(), node.address_count}, ttl, NowNs());
}

template <typename RecordT>
[[nodiscard]] inline Result<RecordT> ExtractFromWire(const DnsRecordRef& ref) noexcept {
  if constexpr (requires { RecordT::kDnsType; }) {
    const auto count = ref.RrCount(RecordSection::Answer);
    for (std::size_t i = 0; i < count; ++i) {
      const auto* rr = ref.RrRawAt(RecordSection::Answer, i);
      if (rr == nullptr) continue;
      if (static_cast<DnsType>(ares_dns_rr_get_type(rr)) != RecordT::kDnsType) continue;
      return ref.template ExtractRrAt<RecordT>(RecordSection::Answer, i);
    }
    return std::unexpected(Error::NotFound());
  } else {
    return ExtractRecord<RecordT>(ref);
  }
}

[[nodiscard]] inline Error PreferFamilyError(Error current, Error incoming) noexcept {
  if (current.IsOk()) return incoming;
  if (incoming.IsOk()) return current;
  if (incoming.IsRetryable()) return incoming;
  if (current.IsRetryable()) return current;
  if (!current.IsNotFound() && incoming.IsNotFound()) return current;
  return incoming;
}

[[nodiscard]] inline bool AddressRanksAfter(const IpAddress& lhs, const IpAddress& rhs) noexcept {
  const bool lhs_v4 = lhs.IsV4();
  if (lhs_v4 != rhs.IsV4()) return rhs.IsV4();
  if (lhs_v4) return std::memcmp(lhs.v4.data(), rhs.v4.data(), lhs.v4.size()) > 0;
  return std::memcmp(lhs.v6.data(), rhs.v6.data(), lhs.v6.size()) > 0;
}

/// Family, then address bytes. Completion order would otherwise freeze into the cache.
template <typename Node>
inline void OrderAnswers(Node* node) noexcept {
  if (node == nullptr) return;
  for (std::uint8_t i = 1; i < node->address_count; ++i) {
    const IpAddress saved = node->addresses[i];
    std::uint8_t j = i;
    while (j > 0 && AddressRanksAfter(node->addresses[j - 1], saved)) {
      node->addresses[j] = node->addresses[j - 1];
      --j;
    }
    node->addresses[j] = saved;
  }
  node->endpoints.clear();
  for (std::uint8_t i = 0; i < node->address_count; ++i) {
    static_cast<void>(node->endpoints.try_push_back(Endpoint{node->addresses[i], node->port}));
  }
}

struct StepGate {
  bool* flag{nullptr};
  explicit StepGate(bool* flag) noexcept : flag(flag) {
    if (flag != nullptr) *flag = true;
  }
  ~StepGate() {
    if (flag != nullptr) *flag = false;
  }
  StepGate(const StepGate&) = delete ("step gate is a scope flag");
  StepGate& operator=(const StepGate&) = delete ("step gate is a scope flag");
};

/// A deferred TIMEOUT SQE still names TimerArm::spec. Keep the pool until process exit.
template <typename T>
inline void LeakPinnedObject(std::unique_ptr<T>& owned) noexcept {
  T* const leaked = owned.release();
  if (leaked == nullptr) return;
#if defined(CARES_HAS_LSAN)
  __lsan_ignore_object(static_cast<const void*>(leaked));
#else
  static_cast<void>(leaked);
#endif
}

[[nodiscard]] inline Result<void> RejectReentrant(bool) noexcept {
  return std::unexpected(Error::FromUring(uring::UringErrorCode::kInvalid));
}

[[nodiscard]] inline bool HostsOverflowOptional(const Error& err, bool default_path) noexcept {
  if (err == Error::CapacityExhausted()) return true;
  return default_path && err == Error::FromErrno(ENOENT);
}

}  // namespace cares::detail

#undef CARES_HAS_LSAN
