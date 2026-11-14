/** @file @brief Generational in-flight callback slab. Slots stay occupied until c-ares calls back. */
#pragma once

#include <ares.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <array>
#include <bit>
#include <cares/channel/completion_words.hpp>
#include <cares/channel/socket_bridge.hpp>
#include <cares/error/ares_error.hpp>
#include <cares/record/dns_record.hpp>
#include <cares/types/host_types.hpp>
#include <cares/types/query_handle.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <tuple>
#include <type_traits>
#include <uarch/primitives.hpp>
#include <utility>

namespace cares {

using DnsRecCallback = Delegate<void(Result<DnsRecordRef>)>;
using HostCallback = Delegate<void(Result<HostResult>)>;
using AddrInfoCallback = Delegate<void(Result<AddressInfoResult>)>;
using NameInfoCallback = Delegate<void(Result<NameInfoResult>)>;

namespace detail {

struct PublishPin {
  void* table{nullptr};
  bool alive{true};
  PublishPin* prev{nullptr};
  explicit PublishPin(void* owner) noexcept : table(owner), prev(PublishStack()) { PublishStack() = this; }
  ~PublishPin() { PublishStack() = prev; }
  PublishPin(const PublishPin&) = delete ("publish pin is a stack link");
  PublishPin& operator=(const PublishPin&) = delete ("publish pin is a stack link");

  [[nodiscard]] static PublishPin*& PublishStack() noexcept {
    thread_local PublishPin* top = nullptr;
    return top;
  }
};

inline void NotePublishDestroyed(void* table) noexcept {
  for (PublishPin* pin = PublishPin::PublishStack(); pin != nullptr; pin = pin->prev) {
    if (pin->table == table) pin->alive = false;
  }
}

[[nodiscard]] inline constexpr std::uint16_t HostOrderPort(std::uint16_t net) noexcept {
  if constexpr (std::endian::native == std::endian::big) return net;
  return std::byteswap(net);
}

}  // namespace detail

enum class CallbackKind : std::uint8_t {
  None = 0,
  DnsRec = 1,
  Host = 2,
  AddrInfo = 3,
  NameInfo = 4,
};

/**
 * @brief Preallocated callback slab.
 * @pre Destroy or drain every `ares_channel_t` that still holds a `SlotContextPtr` before destroying this table.
 * The c-ares argument is the slot address, not a generation token, and each callback runs once.
 * Generation wraps from `0xFFFE` to 1. Generation 0 is never issued, so a wrap cannot alias `QueryHandle{}`.
 */
template <std::size_t MaxInflight = 64>
class CallbackTable {
  static_assert(MaxInflight > 0 && MaxInflight <= 64, "CallbackTable capacity must be in 1..=64");

 public:
  constexpr CallbackTable() noexcept {
    if constexpr (MaxInflight < 64) reserved_ = uarch::Bitmap64::from_raw(~std::uint64_t{0} << MaxInflight);
    for (std::size_t index = 0; index < MaxInflight; ++index) {
      slots_[index].owner = this;
      slots_[index].index = static_cast<std::uint16_t>(index);
    }
  }

  CallbackTable(const CallbackTable&) = delete ("callback slots are address-stable");
  CallbackTable& operator=(const CallbackTable&) = delete ("callback slots are address-stable");
  CallbackTable(CallbackTable&&) = delete ("callback slots are address-stable");
  CallbackTable& operator=(CallbackTable&&) = delete ("callback slots are address-stable");
  ~CallbackTable() { detail::NotePublishDestroyed(this); }

  [[nodiscard]] Result<QueryHandle> AllocateDnsRec(DnsRecCallback cb) noexcept { return Allocate<CallbackKind::DnsRec>(cb); }
  [[nodiscard]] Result<QueryHandle> AllocateHost(HostCallback cb) noexcept { return Allocate<CallbackKind::Host>(cb); }
  [[nodiscard]] Result<QueryHandle> AllocateAddrInfo(AddrInfoCallback cb) noexcept {
    return Allocate<CallbackKind::AddrInfo>(cb);
  }
  [[nodiscard]] Result<QueryHandle> AllocateNameInfo(NameInfoCallback cb) noexcept {
    return Allocate<CallbackKind::NameInfo>(cb);
  }

  void BindQid(QueryHandle handle, unsigned short qid) noexcept {
    Slot* slot = Match(handle);
    if (slot == nullptr) return;
    slot->qid = qid;
    StoreState(*slot);
  }

  [[nodiscard]] void* SlotContextPtr(QueryHandle handle) noexcept { return Match(handle); }
  [[nodiscard]] bool CancelSlot(QueryHandle handle) noexcept {
    Slot* slot = Match(handle);
    if (slot == nullptr || slot->phase != QueryPhase::Submitted) return false;
    slot->ClearCallback();
    slot->phase = QueryPhase::Cancelled;
    slot->last_status = ARES_ECANCELLED;
    StoreState(*slot);
    return true;
  }
  [[nodiscard]] bool IsValid(QueryHandle handle) const noexcept { return Match(handle) != nullptr; }
  [[nodiscard]] constexpr std::size_t ActiveCount() const noexcept { return active_bitmap_.count(); }

  /** @brief Drop user delegates. Occupied slots wait for the c-ares callback to release them. */
  void ReclaimAllAborted() noexcept {
    auto mask = active_bitmap_;
    while (const auto bit = mask.lowest_one()) {
      mask = mask.clear(*bit);
      if (*bit >= MaxInflight) break;
      Slot& slot = slots_[*bit];
      if (slot.phase != QueryPhase::Submitted && slot.phase != QueryPhase::Cancelled) continue;
      slot.ClearCallback();
      slot.phase = QueryPhase::Reclaimed;
      StoreState(slot);
    }
  }

  static void AresDnsRecCallback(void* arg, ares_status_t status, [[maybe_unused]] std::size_t timeouts,
                                 const ares_dns_record_t* dnsrec) noexcept {
    if (arg == nullptr) return;
    auto* slot = static_cast<Slot*>(arg);
    if (slot->owner == nullptr) return;
    if (!Ready(*slot, CallbackKind::DnsRec)) {
      slot->owner->Release(*slot);
      return;
    }
    Result<DnsRecordRef> decoded = std::unexpected(Error::FromAres(static_cast<int>(status)));
    if (status == ARES_SUCCESS) {
      decoded = dnsrec == nullptr ? std::unexpected(Error::BadResponse()) : Result<DnsRecordRef>{DnsRecordRef{dnsrec}};
    }
    slot->owner->Publish(*slot, slot->storage.dns, std::move(decoded), static_cast<int>(status));
  }

  static void AresHostCallback(void* arg, int status, [[maybe_unused]] int timeouts, struct hostent* hostent) noexcept {
    if (arg == nullptr) return;
    auto* slot = static_cast<Slot*>(arg);
    if (slot->owner == nullptr) return;
    if (!Ready(*slot, CallbackKind::Host)) {
      slot->owner->Release(*slot);
      return;
    }
    Result<HostResult> decoded = std::unexpected(Error::FromAres(status));
    if (status == ARES_SUCCESS) decoded = DecodeHost(hostent);
    slot->owner->Publish(*slot, slot->storage.host, std::move(decoded), status);
  }

  static void AresAddrInfoCallback(void* arg, int status, [[maybe_unused]] int timeouts,
                                   struct ares_addrinfo* result) noexcept {
    if (arg == nullptr) {
      if (result != nullptr) ares_freeaddrinfo(result);
      return;
    }
    auto* slot = static_cast<Slot*>(arg);
    if (slot->owner == nullptr) {
      if (result != nullptr) ares_freeaddrinfo(result);
      return;
    }
    const bool ready = Ready(*slot, CallbackKind::AddrInfo);
    Result<AddressInfoResult> decoded = std::unexpected(Error::FromAres(status));
    if (ready && status == ARES_SUCCESS) decoded = DecodeAddrInfo(result);
    if (result != nullptr) ares_freeaddrinfo(result);
    if (!ready) {
      slot->owner->Release(*slot);
      return;
    }
    slot->owner->Publish(*slot, slot->storage.addr, std::move(decoded), status);
  }

  static void AresNameInfoCallback(void* arg, int status, [[maybe_unused]] int timeouts, char* node, char* service) noexcept {
    if (arg == nullptr) return;
    auto* slot = static_cast<Slot*>(arg);
    if (slot->owner == nullptr) return;
    if (!Ready(*slot, CallbackKind::NameInfo)) {
      slot->owner->Release(*slot);
      return;
    }
    Result<NameInfoResult> decoded = std::unexpected(Error::FromAres(status));
    if (status == ARES_SUCCESS) decoded = DecodeNameInfo(node, service);
    slot->owner->Publish(*slot, slot->storage.name, std::move(decoded), status);
  }

 private:
  union Storage {
    DnsRecCallback dns;
    HostCallback host;
    AddrInfoCallback addr;
    NameInfoCallback name;
    constexpr Storage() noexcept : host{} {}
  };

  struct Slot {
    CallbackTable* owner{nullptr};
    std::uint16_t index{0};
    std::uint16_t generation{0};
    unsigned short qid{0};
    QueryPhase phase{QueryPhase::Empty};
    CallbackKind kind{CallbackKind::None};
    int last_status{0};
    QueryStateWord state{};
    Storage storage{};

    void ClearCallback() noexcept {
      switch (kind) {
        case CallbackKind::DnsRec:
          storage.dns = {};
          break;
        case CallbackKind::Host:
          storage.host = {};
          break;
        case CallbackKind::AddrInfo:
          storage.addr = {};
          break;
        case CallbackKind::NameInfo:
          storage.name = {};
          break;
        case CallbackKind::None:
          break;
      }
    }
  };

  template <std::size_t N>
  struct TextBuf {
    std::array<char, N> bytes{};
    std::uint16_t len{0};
  };

  struct SockEndpoint {
    IpAddress ip{};
    std::uint16_t port{0};
  };

  template <CallbackKind Kind, typename Callback>
  [[nodiscard]] Result<QueryHandle> Allocate(Callback callback) noexcept {
    if (uarch::unlikely(!callback)) return std::unexpected(Error::InvalidArgument());
    const auto index = (active_bitmap_ | retired_bitmap_ | reserved_).lowest_zero();
    if (uarch::unlikely(!index || *index >= MaxInflight)) {
      if (active_bitmap_.is_empty() && !retired_bitmap_.is_empty()) {
        return std::unexpected(Error::FromUring(uring::UringErrorCode::kGenerationExhausted));
      }
      return std::unexpected(Error::CapacityExhausted());
    }
    Slot& slot = slots_[*index];
    if (slot.generation == 0) slot.generation = 1;
    slot.phase = QueryPhase::Submitted;
    slot.kind = Kind;
    slot.qid = 0;
    slot.last_status = ARES_SUCCESS;
    if constexpr (Kind == CallbackKind::DnsRec) {
      std::construct_at(&slot.storage.dns, callback);
    } else if constexpr (Kind == CallbackKind::Host) {
      std::construct_at(&slot.storage.host, callback);
    } else if constexpr (Kind == CallbackKind::AddrInfo) {
      std::construct_at(&slot.storage.addr, callback);
    } else if constexpr (Kind == CallbackKind::NameInfo) {
      std::construct_at(&slot.storage.name, callback);
    }
    StoreState(slot);
    active_bitmap_ = active_bitmap_.set(*index);
    return QueryHandle::Pack(slot.index, slot.generation, 0);
  }

  [[nodiscard]] static bool Ready(const Slot& slot, CallbackKind kind) noexcept {
    return slot.phase == QueryPhase::Submitted && slot.kind == kind;
  }

  [[nodiscard]] Slot* Match(QueryHandle handle) noexcept { return const_cast<Slot*>(std::as_const(*this).Match(handle)); }

  [[nodiscard]] const Slot* Match(QueryHandle handle) const noexcept {
    const auto index = handle.Slot();
    if (index >= MaxInflight) return nullptr;
    const Slot& slot = slots_[index];
    if (slot.generation != handle.Generation() || slot.phase == QueryPhase::Empty) return nullptr;
    return &slot;
  }

  void StoreState(Slot& slot) noexcept {
    QueryStateWord word{};
    if (auto next = word.try_with<^^QueryStateSpec::phase>(slot.phase)) word = *next;
    if (slot.last_status >= 0 && slot.last_status <= 0x1FFF) {
      if (auto next = word.try_with<^^QueryStateSpec::status_code>(slot.last_status)) word = *next;
    }
    if (auto next = word.try_with<^^QueryStateSpec::generation>(slot.generation)) word = *next;
    if (auto next = word.try_with<^^QueryStateSpec::qid>(static_cast<std::uint32_t>(slot.qid))) word = *next;
    slot.state = word;
  }

  void Release(Slot& slot) noexcept {
    if (slot.phase == QueryPhase::Empty) return;
    slot.ClearCallback();
    slot.kind = CallbackKind::None;
    active_bitmap_ = active_bitmap_.clear(slot.index);
    if (slot.generation >= static_cast<std::uint16_t>(0xFFFE))
      slot.generation = 1;
    else
      slot.generation = static_cast<std::uint16_t>(slot.generation + 1U);
    slot.phase = QueryPhase::Empty;
    slot.qid = 0;
    slot.last_status = 0;
    slot.state = {};
  }

  template <typename Callback, typename T>
  void Publish(Slot& slot, Callback& callback, Result<T>&& decoded, int status) noexcept {
    detail::PublishPin pin{this};
    Callback user = callback;
    slot.ClearCallback();
    slot.last_status = status;
    slot.phase = QueryPhase::Completed;
    StoreState(slot);
    if (user) user(std::move(decoded));
    if (!pin.alive) return;
    Release(slot);
  }

  template <std::size_t N>
  [[nodiscard]] static std::optional<TextBuf<N>> CopyText(const char* text) noexcept {
    TextBuf<N> out{};
    if (text == nullptr) return out;
    std::size_t count = 0;
    while (text[count] != '\0') {
      if (count == N) return std::nullopt;
      ++count;
    }
    for (std::size_t i = 0; i < count; ++i) out.bytes[i] = text[i];
    out.len = static_cast<std::uint16_t>(count);
    return out;
  }

  [[nodiscard]] static Result<HostResult> DecodeHost(const struct hostent* host) noexcept {
    if (host == nullptr) return std::unexpected(Error::BadResponse());
    const bool v4 = host->h_addrtype == AF_INET && host->h_length == 4;
    const bool v6 = host->h_addrtype == AF_INET6 && host->h_length == 16;
    if (!v4 && !v6) return std::unexpected(Error::BadResponse());
    std::size_t count = 0;
    if (host->h_addr_list != nullptr) {
      while (host->h_addr_list[count] != nullptr) {
        ++count;
        if (count > HostResult{}.addresses.size()) return std::unexpected(Error::CapacityExhausted());
      }
    }
    auto name = CopyText<std::tuple_size_v<decltype(HostResult{}.canonical_name)>>(host->h_name);
    if (!name) return std::unexpected(Error::CapacityExhausted());
    HostResult decoded{};
    decoded.canonical_name = name->bytes;
    decoded.canonical_len = name->len;
    for (std::size_t i = 0; i < count; ++i) {
      if (v4) {
        Ipv4Bytes raw{};
        std::memcpy(raw.data(), host->h_addr_list[i], raw.size());
        decoded.addresses[i] = IpAddress::FromV4(raw);
      } else {
        Ipv6Bytes raw{};
        std::memcpy(raw.data(), host->h_addr_list[i], raw.size());
        decoded.addresses[i] = IpAddress::FromV6(raw, 0);
      }
    }
    decoded.address_count = static_cast<std::uint8_t>(count);
    return decoded;
  }

  [[nodiscard]] static Result<SockEndpoint> IpFromSockaddr(const sockaddr* address) noexcept {
    if (address == nullptr) return std::unexpected(Error::BadResponse());
    if (address->sa_family == AF_INET) {
      sockaddr_in v4{};
      std::memcpy(&v4, address, sizeof(v4));
      Ipv4Bytes raw{};
      std::memcpy(raw.data(), &v4.sin_addr, raw.size());
      return SockEndpoint{.ip = IpAddress::FromV4(raw), .port = detail::HostOrderPort(v4.sin_port)};
    }
    if (address->sa_family == AF_INET6) {
      sockaddr_in6 v6{};
      std::memcpy(&v6, address, sizeof(v6));
      Ipv6Bytes raw{};
      std::memcpy(raw.data(), &v6.sin6_addr, raw.size());
      return SockEndpoint{.ip = IpAddress::FromV6(raw, v6.sin6_scope_id), .port = detail::HostOrderPort(v6.sin6_port)};
    }
    return std::unexpected(Error::BadResponse());
  }

  [[nodiscard]] static Result<AddressInfoResult> DecodeAddrInfo(const ares_addrinfo* info) noexcept {
    if (info == nullptr) return AddressInfoResult{};
    std::size_t nodes = 0;
    for (const ares_addrinfo_node* node = info->nodes; node != nullptr; node = node->ai_next) {
      ++nodes;
      if (nodes > AddressInfoResult{}.nodes.size()) return std::unexpected(Error::CapacityExhausted());
    }
    std::size_t cnames = 0;
    for (const ares_addrinfo_cname* cname = info->cnames; cname != nullptr; cname = cname->next) {
      ++cnames;
      if (cnames > AddressInfoResult{}.cnames.size()) return std::unexpected(Error::CapacityExhausted());
    }
    auto name = CopyText<std::tuple_size_v<decltype(AddressInfoResult{}.name)>>(info->name);
    if (!name) return std::unexpected(Error::CapacityExhausted());
    AddressInfoResult decoded{};
    decoded.name = name->bytes;
    decoded.name_len = name->len;
    std::size_t index = 0;
    for (const ares_addrinfo_node* node = info->nodes; node != nullptr; node = node->ai_next, ++index) {
      if (node->ai_ttl < 0) return std::unexpected(Error::BadResponse());
      auto endpoint = IpFromSockaddr(node->ai_addr);
      if (!endpoint) return std::unexpected(endpoint.error());
      AddressInfoNode stored{};
      stored.ip = endpoint->ip;
      stored.port = endpoint->port;
      stored.ttl = static_cast<std::uint32_t>(node->ai_ttl);
      stored.socktype = node->ai_socktype;
      stored.protocol = node->ai_protocol;
      decoded.nodes[index] = stored;
    }
    decoded.node_count = static_cast<std::uint8_t>(nodes);
    index = 0;
    for (const ares_addrinfo_cname* cname = info->cnames; cname != nullptr; cname = cname->next, ++index) {
      if (cname->ttl < 0) return std::unexpected(Error::BadResponse());
      auto alias = CopyText<std::tuple_size_v<decltype(AddressInfoCname{}.alias)>>(cname->alias);
      auto target = CopyText<std::tuple_size_v<decltype(AddressInfoCname{}.name)>>(cname->name);
      if (!alias || !target) return std::unexpected(Error::CapacityExhausted());
      AddressInfoCname stored{};
      stored.alias = alias->bytes;
      stored.alias_len = static_cast<std::uint8_t>(alias->len);
      stored.name = target->bytes;
      stored.name_len = static_cast<std::uint8_t>(target->len);
      stored.ttl = static_cast<std::uint32_t>(cname->ttl);
      decoded.cnames[index] = stored;
    }
    decoded.cname_count = static_cast<std::uint8_t>(cnames);
    return decoded;
  }

  [[nodiscard]] static Result<NameInfoResult> DecodeNameInfo(const char* node, const char* service) noexcept {
    auto node_text = CopyText<std::tuple_size_v<decltype(NameInfoResult{}.node)>>(node);
    auto service_text = CopyText<std::tuple_size_v<decltype(NameInfoResult{}.service)>>(service);
    if (!node_text || !service_text) return std::unexpected(Error::CapacityExhausted());
    NameInfoResult decoded{};
    decoded.node = node_text->bytes;
    decoded.node_len = node_text->len;
    decoded.service = service_text->bytes;
    decoded.service_len = static_cast<std::uint8_t>(service_text->len);
    return decoded;
  }

  std::array<Slot, MaxInflight> slots_{};
  uarch::Bitmap64 active_bitmap_{};
  uarch::Bitmap64 retired_bitmap_{};
  uarch::Bitmap64 reserved_{};
};

static_assert(sizeof(DnsRecCallback) == 16);
static_assert(std::is_trivially_copyable_v<DnsRecCallback>);
static_assert(std::is_trivially_copyable_v<HostCallback>);

}  // namespace cares
