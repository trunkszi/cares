/** @file @brief Single c-ares channel: one ares_init_options, then query submission. */
#pragma once

#include <ares.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <array>
#include <cares/channel/callback_table.hpp>
#include <cares/channel/library_guard.hpp>
#include <cares/channel/options.hpp>
#include <cares/channel/socket_bridge.hpp>
#include <cares/channel/timer_state.hpp>
#include <cares/error/ares_error.hpp>
#include <cares/record/dns_record.hpp>
#include <cares/types/dns_types.hpp>
#include <cares/types/host_types.hpp>
#include <cares/types/query_handle.hpp>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <uarch/uarch.hpp>
#include <utility>

namespace cares {

namespace detail {

template <std::size_t N>
struct BoundedText {
  std::array<char, N> bytes{};
  std::uint8_t len{0};
};

template <std::size_t N>
[[nodiscard]] inline Result<BoundedText<N>> CopyText(std::string_view text) noexcept {
  if (text.contains('\0')) return std::unexpected(Error::BadName());
  if (text.size() >= N || text.size() > 255) return std::unexpected(Error::BadName());
  BoundedText<N> copied{};
  for (std::size_t i = 0; i < text.size(); ++i) copied.bytes[i] = text[i];
  copied.bytes[text.size()] = '\0';
  copied.len = static_cast<std::uint8_t>(text.size());
  return copied;
}

struct ServerCsv {
  std::array<char, 512> text{};
  std::size_t len{0};
  bool any_server{false};
  bool all_tcp{true};
};

/** @brief Append one server. The previous csv is taken by value so the length is not an out-parameter. */
[[nodiscard]] inline Result<ServerCsv> AppendServer(ServerCsv csv, const ServerEndpoint& server) noexcept {
  std::array<char, 64> ip{};
  const auto written = server.ip.FormatTo(ip);
  if (written == 0 || written >= ip.size()) return std::unexpected(Error::InvalidArgument());
  const bool v6 = server.ip.IsV6();
  if (csv.len + written + (v6 ? 2u : 0u) + 8u >= csv.text.size()) return std::unexpected(Error::InvalidArgument());
  if (csv.len != 0) csv.text[csv.len++] = ',';
  if (v6) csv.text[csv.len++] = '[';
  for (std::size_t i = 0; i < written; ++i) csv.text[csv.len++] = ip[i];
  if (v6) csv.text[csv.len++] = ']';
  if (server.port != 0) {
    csv.text[csv.len++] = ':';
    std::array<char, 8> port_buf{};
    const auto port = std::to_chars(port_buf.data(), port_buf.data() + port_buf.size(), static_cast<unsigned>(server.port));
    if (port.ec != std::errc{}) return std::unexpected(Error::InvalidArgument());
    for (char* cursor = port_buf.data(); cursor != port.ptr; ++cursor) csv.text[csv.len++] = *cursor;
  }
  csv.text[csv.len] = '\0';
  csv.any_server = true;
  csv.all_tcp = csv.all_tcp && server.use_tcp;
  return csv;
}

struct PreparedOptions {
  int mask{ARES_OPT_SOCK_STATE_CB};
  int flags{ARES_FLAG_NO_DFLT_SVR};
  int timeout_ms{0};
  int tries{0};
  int ndots{0};
  int udp_max_queries{0};
  int edns_psz{0};
  bool use_timeout{false};
  bool use_tries{false};
  bool use_ndots{false};
  bool use_udp{false};
  bool use_edns{false};
  ServerCsv csv{};
  std::array<std::array<char, 128>, 6> domains{};
  int domain_count{0};
  std::array<char, 256> resolvconf{};
  std::uint16_t resolvconf_len{0};
  std::array<char, 256> hosts{};
  std::uint16_t hosts_len{0};
};

[[nodiscard]] inline bool FitsInt(std::uint32_t value) noexcept { return value <= static_cast<std::uint32_t>(0x7fffffff); }

[[nodiscard]] inline Result<PreparedOptions> PrepareOptions(const ChannelOptions& options) noexcept {
  if (!FitsInt(options.timeout_ms) || !FitsInt(options.tries) || !FitsInt(options.ndots) || !FitsInt(options.udp_max_queries) ||
      !FitsInt(options.flags)) {
    return std::unexpected(Error::InvalidArgument());
  }
  PreparedOptions prepared{};
  prepared.timeout_ms = static_cast<int>(options.timeout_ms);
  prepared.use_timeout = true;
  prepared.mask |= ARES_OPT_TIMEOUTMS;
  prepared.tries = static_cast<int>(options.tries);
  prepared.use_tries = true;
  prepared.mask |= ARES_OPT_TRIES;
  prepared.ndots = static_cast<int>(options.ndots);
  prepared.use_ndots = true;
  prepared.mask |= ARES_OPT_NDOTS;
  if (options.udp_max_queries != 0) {
    prepared.udp_max_queries = static_cast<int>(options.udp_max_queries);
    prepared.use_udp = true;
    prepared.mask |= ARES_OPT_UDP_MAX_QUERIES;
  }
  prepared.edns_psz = static_cast<int>(options.edns_psz);
  prepared.use_edns = true;
  prepared.mask |= ARES_OPT_EDNSPSZ;
  ServerCsv csv{};
  for (const ServerEndpoint& server : options.servers) {
    auto next = AppendServer(csv, server);
    if (!next.has_value()) return std::unexpected(next.error());
    csv = *next;
  }
  prepared.csv = csv;
  if (prepared.csv.any_server && prepared.csv.all_tcp) prepared.flags |= ARES_FLAG_USEVC;
  prepared.flags |= static_cast<int>(options.flags);
  prepared.mask |= ARES_OPT_FLAGS;
  for (const SearchDomain& domain : options.search_domains) {
    if (prepared.domain_count >= 6) return std::unexpected(Error::CapacityExhausted());
    const auto view = domain.View();
    if (view.empty() || view.size() >= prepared.domains[0].size()) return std::unexpected(Error::BadName());
    auto& dest = prepared.domains[static_cast<std::size_t>(prepared.domain_count)];
    for (std::size_t n = 0; n < view.size(); ++n) dest[n] = view[n];
    dest[view.size()] = '\0';
    ++prepared.domain_count;
  }
  const auto resolvconf = options.resolvconf_path.as_string_view();
  if (!resolvconf.empty()) {
    if (resolvconf.size() >= prepared.resolvconf.size()) return std::unexpected(Error::InvalidArgument());
    for (std::size_t n = 0; n < resolvconf.size(); ++n) prepared.resolvconf[n] = resolvconf[n];
    prepared.resolvconf[resolvconf.size()] = '\0';
    prepared.resolvconf_len = static_cast<std::uint16_t>(resolvconf.size());
  }
  const auto hosts = options.hosts_path.as_string_view();
  if (!hosts.empty()) {
    if (hosts.size() >= prepared.hosts.size()) return std::unexpected(Error::InvalidArgument());
    for (std::size_t n = 0; n < hosts.size(); ++n) prepared.hosts[n] = hosts[n];
    prepared.hosts[hosts.size()] = '\0';
    prepared.hosts_len = static_cast<std::uint16_t>(hosts.size());
  }
  return prepared;
}

[[nodiscard]] inline int AddressFamily(IpFamily family) noexcept {
  switch (family) {
    case IpFamily::Ipv4:
      return AF_INET;
    case IpFamily::Ipv6:
      return AF_INET6;
    case IpFamily::DualStack:
    case IpFamily::Unspec:
      return AF_UNSPEC;
  }
  return AF_UNSPEC;
}

}  // namespace detail

/**
 * @brief Owns one ares_channel_t created by a single ares_init_options call.
 *
 * The callback slab and socket bridge live in one heap block. c-ares stores those
 * addresses for the life of the channel, and moving ChannelCore only moves the pointer.
 *
 * @tparam MaxInflight In-flight callback slots. The occupancy mask is one Bitmap64.
 */
template <std::size_t MaxInflight = 64>
class ChannelCore {
 public:
  static_assert(MaxInflight > 0 && MaxInflight <= 64);

  ChannelCore() noexcept = default;
  ChannelCore(const ChannelCore&) = delete ("channel owns one ares_channel_t");
  ChannelCore& operator=(const ChannelCore&) = delete ("channel owns one ares_channel_t");

  ChannelCore(ChannelCore&& other) noexcept
      : stable_(std::move(other.stable_)), channel_(std::exchange(other.channel_, nullptr)), guard_(std::move(other.guard_)) {}

  ChannelCore& operator=(ChannelCore&& other) noexcept {
    if (this != &other) {
      Destroy();
      stable_ = std::move(other.stable_);
      channel_ = std::exchange(other.channel_, nullptr);
      guard_ = std::move(other.guard_);
    }
    return *this;
  }

  ~ChannelCore() { Destroy(); }

  /** @brief System resolvers. Exactly one ares_init_options, masked with ARES_OPT_SOCK_STATE_CB. */
  [[nodiscard]] static Result<ChannelCore> FromSystem(SocketStateObserver observer = {}) noexcept {
    return Open(nullptr, std::move(observer), true);
  }

  /** @brief Configured channel. One ares_init_options, then ares_set_servers_csv when servers are set. */
  [[nodiscard]] static Result<ChannelCore> Create(const ChannelOptions& options, SocketStateObserver observer = {}) noexcept {
    return Open(&options, std::move(observer), false);
  }

  void SetSocketObserver(SocketStateObserver observer) noexcept {
    if (stable_ != nullptr) stable_->bridge.SetObserver(std::move(observer));
  }

  [[nodiscard]] Result<QueryHandle> SubmitDnsRec(const DnsRecordRef& record, DnsRecCallback callback) noexcept {
    if (!record.IsValid()) return std::unexpected(Error::InvalidArgument());
    auto question = record.QuestionAt(0);
    if (!question.has_value()) return std::unexpected(question.error());
    return SubmitQuery(question->Name(), question->qclass, question->qtype, callback);
  }

  [[nodiscard]] Result<QueryHandle> SubmitQuery(std::string_view name, DnsClass qclass, DnsType qtype,
                                                DnsRecCallback callback) noexcept {
    const auto owned = detail::CopyText<256>(name);
    if (!owned) return std::unexpected(owned.error());
    auto handle = ArmDns(callback);
    if (!handle.has_value()) return std::unexpected(handle.error());
    unsigned short qid = 0;
    const auto status =
        ares_query_dnsrec(channel_, owned->bytes.data(), static_cast<ares_dns_class_t>(std::to_underlying(qclass)),
                          static_cast<ares_dns_rec_type_t>(std::to_underlying(qtype)),
                          CallbackTable<MaxInflight>::AresDnsRecCallback, SlotArg(*handle), &qid);
    return FinishStatus(*handle, status, qid);
  }

  [[nodiscard]] Result<QueryHandle> SubmitSearch(std::string_view name, DnsClass qclass, DnsType qtype,
                                                 DnsRecCallback callback) noexcept {
    auto record = DnsRecord::CreateQuery(name, qtype, qclass);
    if (!record.has_value()) return std::unexpected(record.error());
    auto handle = ArmDns(callback);
    if (!handle.has_value()) return std::unexpected(handle.error());
    const auto status =
        ares_search_dnsrec(channel_, record->Raw(), CallbackTable<MaxInflight>::AresDnsRecCallback, SlotArg(*handle));
    return FinishStatus(*handle, status, 0);
  }

  [[nodiscard]] Result<QueryHandle> SubmitSend(std::span<const std::byte> raw_query, DnsRecCallback callback) noexcept {
    auto record = DnsRecord::ParseWire(raw_query);
    if (!record.has_value()) return std::unexpected(record.error());
    auto handle = ArmDns(callback);
    if (!handle.has_value()) return std::unexpected(handle.error());
    unsigned short qid = 0;
    const auto status =
        ares_send_dnsrec(channel_, record->Raw(), CallbackTable<MaxInflight>::AresDnsRecCallback, SlotArg(*handle), &qid);
    return FinishStatus(*handle, status, qid);
  }

  [[nodiscard]] Result<QueryHandle> SubmitHostByName(std::string_view name, int family, HostCallback callback) noexcept {
    if (family != AF_INET && family != AF_INET6 && family != AF_UNSPEC) return std::unexpected(Error::InvalidArgument());
    const auto owned = detail::CopyText<256>(name);
    if (!owned) return std::unexpected(owned.error());
    auto handle = ArmHost(callback);
    if (!handle.has_value()) return std::unexpected(handle.error());
    ares_gethostbyname(channel_, owned->bytes.data(), family, CallbackTable<MaxInflight>::AresHostCallback, SlotArg(*handle));
    return *handle;
  }

  [[nodiscard]] Result<QueryHandle> SubmitHostByAddr(const IpAddress& address, HostCallback callback) noexcept {
    const bool v4 = address.IsV4();
    const bool v6 = address.IsV6();
    if (!v4 && !v6) return std::unexpected(Error::InvalidArgument());
    auto handle = ArmHost(callback);
    if (!handle.has_value()) return std::unexpected(handle.error());
    if (v4) {
      ares_gethostbyaddr(channel_, address.v4.data(), 4, AF_INET, CallbackTable<MaxInflight>::AresHostCallback,
                         SlotArg(*handle));
    } else {
      ares_gethostbyaddr(channel_, address.v6.data(), 16, AF_INET6, CallbackTable<MaxInflight>::AresHostCallback,
                         SlotArg(*handle));
    }
    return *handle;
  }

  [[nodiscard]] Result<QueryHandle> SubmitAddressInfo(std::string_view node, std::string_view service, IpFamily family,
                                                      AddrInfoCallback callback) noexcept {
    std::optional<detail::BoundedText<256>> node_buf;
    std::optional<detail::BoundedText<64>> service_buf;
    if (!node.empty()) {
      auto copied = detail::CopyText<256>(node);
      if (!copied) return std::unexpected(copied.error());
      node_buf = *copied;
    }
    if (!service.empty()) {
      auto copied = detail::CopyText<64>(service);
      if (!copied) return std::unexpected(copied.error());
      service_buf = *copied;
    }
    auto handle = ArmAddr(callback);
    if (!handle.has_value()) return std::unexpected(handle.error());
    ares_addrinfo_hints hints{};
    hints.ai_family = detail::AddressFamily(family);
    ares_getaddrinfo(channel_, node_buf.has_value() ? node_buf->bytes.data() : nullptr,
                     service_buf.has_value() ? service_buf->bytes.data() : nullptr, &hints,
                     CallbackTable<MaxInflight>::AresAddrInfoCallback, SlotArg(*handle));
    return *handle;
  }

  [[nodiscard]] Result<QueryHandle> SubmitNameInfo(const SocketAddress& address, int flags,
                                                   NameInfoCallback callback) noexcept {
    auto handle = ArmName(callback);
    if (!handle.has_value()) return std::unexpected(handle.error());
    const auto storage = address.ToSockAddr();
    ares_getnameinfo(channel_, reinterpret_cast<const sockaddr*>(&storage), address.SockAddrLen(), flags,
                     CallbackTable<MaxInflight>::AresNameInfoCallback, SlotArg(*handle));
    return *handle;
  }

  [[nodiscard]] bool CancelQuery(QueryHandle handle) noexcept {
    if (stable_ == nullptr) return false;
    return stable_->callbacks.CancelSlot(handle);
  }

  void ProcessFd(ares_socket_t read_fd, ares_socket_t write_fd) noexcept {
    if (channel_ != nullptr) ares_process_fd(channel_, read_fd, write_fd);
  }

  [[nodiscard]] Result<void> ProcessBatch(std::span<const ares_fd_events_t> events) noexcept {
    if (channel_ == nullptr) return std::unexpected(Error::FromAres(ARES_ENOTINITIALIZED));
    const auto status = ares_process_fds(channel_, events.data(), events.size(), ARES_PROCESS_FLAG_SKIP_NON_FD);
    if (status != ARES_SUCCESS) return std::unexpected(Error::FromAres(static_cast<int>(std::to_underlying(status))));
    return {};
  }

  void ProcessTimeouts() noexcept { ProcessFd(ARES_SOCKET_BAD, ARES_SOCKET_BAD); }

  [[nodiscard]] TimerDeadline NextTimeout(std::uint32_t max_wait_ms = 0) const noexcept {
    if (channel_ == nullptr) return {};
    timeval cap{};
    timeval out{};
    timeval* cap_ptr = nullptr;
    if (max_wait_ms != 0) {
      constexpr auto kMilli = uarch::divisor_u32<1000>();
      cap.tv_sec = static_cast<decltype(cap.tv_sec)>(kMilli.div(max_wait_ms));
      cap.tv_usec = static_cast<decltype(cap.tv_usec)>(kMilli.rem(max_wait_ms)) * 1000;
      cap_ptr = &cap;
    }
    // c-ares returns maxtv itself when the caller cap is sooner than the query.
    const timeval* chosen = ares_timeout(channel_, cap_ptr, &out);
    if (chosen == nullptr || ares_queue_active_queries(channel_) == 0) return {};
    return ComputeTimerDeadline(true, chosen->tv_sec, chosen->tv_usec);
  }

  void CancelAll() noexcept {
    if (channel_ != nullptr) ares_cancel(channel_);
  }

  void Destroy() noexcept {
    if (stable_ != nullptr) stable_->callbacks.ReclaimAllAborted();
    if (channel_ != nullptr) {
      ares_channel_t* channel = std::exchange(channel_, nullptr);
      ares_destroy(channel);
    }
    stable_.reset();
    guard_ = LibraryGuard{};
  }

  [[nodiscard]] Result<void> Reinit() noexcept {
    if (channel_ == nullptr) return std::unexpected(Error::FromAres(ARES_ENOTINITIALIZED));
    const auto status = ares_reinit(channel_);
    if (status != ARES_SUCCESS) return std::unexpected(Error::FromAres(static_cast<int>(std::to_underlying(status))));
    return {};
  }

  [[nodiscard]] std::size_t ActiveQueryCount() const noexcept {
    if (stable_ == nullptr) return 0;
    return stable_->callbacks.ActiveCount();
  }

  [[nodiscard]] ares_channel_t* Raw() noexcept { return channel_; }
  [[nodiscard]] const ares_channel_t* Raw() const noexcept { return channel_; }

 private:
  /**
   * @brief Immovable objects whose addresses c-ares keeps.
   * CallbackTable and SocketBridge both delete their move operations.
   */
  struct StableState {
    CallbackTable<MaxInflight> callbacks{};
    SocketBridge bridge{};
  };

  [[nodiscard]] static Result<ChannelCore> Open(const ChannelOptions* options, SocketStateObserver observer,
                                                bool system_channel) noexcept {
    auto guard = LibraryGuard::Acquire();
    if (!guard.has_value()) return std::unexpected(guard.error());
    auto gate = LibraryGuard::EnsureThreadingDisabled();
    if (!gate.has_value()) return std::unexpected(gate.error());

    auto stable = std::make_unique<StableState>();
    stable->bridge.SetObserver(std::move(observer));

    detail::PreparedOptions prepared{};
    if (!system_channel) {
      auto built = detail::PrepareOptions(*options);
      if (!built.has_value()) return std::unexpected(built.error());
      prepared = *built;
    }

    ares_options opts{};
    std::array<char*, 6> domain_ptrs{};
    stable->bridge.Bind(&opts);
    // System init must not apply ARES_FLAG_NO_DFLT_SVR; that flag is only for an explicit server list.
    int mask = ARES_OPT_SOCK_STATE_CB;
    if (system_channel) {
      opts.flags = ARES_FLAG_EDNS | ARES_FLAG_STAYOPEN;
      mask |= ARES_OPT_FLAGS;
    }
    if (!system_channel) {
      mask = prepared.mask;
      opts.flags = prepared.flags;
      if (prepared.use_timeout) opts.timeout = prepared.timeout_ms;
      if (prepared.use_tries) opts.tries = prepared.tries;
      if (prepared.use_ndots) opts.ndots = prepared.ndots;
      if (prepared.use_udp) opts.udp_max_queries = prepared.udp_max_queries;
      if (prepared.use_edns) opts.ednspsz = prepared.edns_psz;
      for (int i = 0; i < prepared.domain_count; ++i) {
        domain_ptrs[static_cast<std::size_t>(i)] = prepared.domains[static_cast<std::size_t>(i)].data();
      }
      if (prepared.domain_count > 0) {
        opts.domains = domain_ptrs.data();
        opts.ndomains = prepared.domain_count;
        mask |= ARES_OPT_DOMAINS;
      }
      if (prepared.resolvconf_len > 0) {
        opts.resolvconf_path = prepared.resolvconf.data();
        mask |= ARES_OPT_RESOLVCONF;
      }
      if (prepared.hosts_len > 0) {
        opts.hosts_path = prepared.hosts.data();
        mask |= ARES_OPT_HOSTS_FILE;
      }
    }

    ares_channel_t* channel = nullptr;
    const int status = ares_init_options(&channel, &opts, mask);
    if (status != ARES_SUCCESS || channel == nullptr) {
      if (channel != nullptr) ares_destroy(channel);
      if (status == ARES_ENOSERVER) return std::unexpected(Error::InvalidArgument());
      return std::unexpected(Error::FromAres(status));
    }

    ChannelCore core;
    core.guard_ = std::move(*guard);
    core.stable_ = std::move(stable);
    core.channel_ = channel;
    if (!system_channel && prepared.csv.len > 0) {
      const int servers = ares_set_servers_csv(channel, prepared.csv.text.data());
      if (servers != ARES_SUCCESS) {
        core.Destroy();
        return std::unexpected(Error::FromAres(servers));
      }
    }
    char* listed = ares_get_servers_csv(channel);
    const bool empty = listed == nullptr || listed[0] == '\0';
    if (listed != nullptr) ares_free_string(listed);
    if (empty) {
      core.Destroy();
      return std::unexpected(Error::InvalidArgument());
    }
    return core;
  }

  [[nodiscard]] Result<QueryHandle> ArmDns(DnsRecCallback callback) noexcept {
    if (stable_ == nullptr || channel_ == nullptr) return std::unexpected(Error::FromAres(ARES_ENOTINITIALIZED));
    return stable_->callbacks.AllocateDnsRec(callback);
  }
  [[nodiscard]] Result<QueryHandle> ArmHost(HostCallback callback) noexcept {
    if (stable_ == nullptr || channel_ == nullptr) return std::unexpected(Error::FromAres(ARES_ENOTINITIALIZED));
    return stable_->callbacks.AllocateHost(callback);
  }
  [[nodiscard]] Result<QueryHandle> ArmAddr(AddrInfoCallback callback) noexcept {
    if (stable_ == nullptr || channel_ == nullptr) return std::unexpected(Error::FromAres(ARES_ENOTINITIALIZED));
    return stable_->callbacks.AllocateAddrInfo(callback);
  }
  [[nodiscard]] Result<QueryHandle> ArmName(NameInfoCallback callback) noexcept {
    if (stable_ == nullptr || channel_ == nullptr) return std::unexpected(Error::FromAres(ARES_ENOTINITIALIZED));
    return stable_->callbacks.AllocateNameInfo(callback);
  }

  [[nodiscard]] void* SlotArg(QueryHandle handle) noexcept { return stable_->callbacks.SlotContextPtr(handle); }

  /**
   * @brief Surface a submit failure without a second user callback.
   * A slot that is already gone was completed inside the submit call.
   */
  [[nodiscard]] Result<QueryHandle> FinishStatus(QueryHandle handle, ares_status_t status, unsigned short qid) noexcept {
    if (status != ARES_SUCCESS) {
      if (!stable_->callbacks.IsValid(handle)) return handle;
      static_cast<void>(stable_->callbacks.CancelSlot(handle));
      return std::unexpected(Error::FromAres(static_cast<int>(std::to_underlying(status))));
    }
    stable_->callbacks.BindQid(handle, qid);
    return handle;
  }

  std::unique_ptr<StableState> stable_{};
  ares_channel_t* channel_{nullptr};
  LibraryGuard guard_{};
};

}  // namespace cares
