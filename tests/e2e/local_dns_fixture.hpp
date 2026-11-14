/**
 * @file local_dns_fixture.hpp
 * @brief Authoritative UDP and TCP DNS on 127.0.0.1. Children block in recvfrom and accept.
 */
#pragma once

#include <ares.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <bit>
#include <cares/resolver/resolver.hpp>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string_view>

namespace cares::test {

enum class DnsMode : std::uint8_t {
  Answer,
  NxDomain,
  Drop,
  Truncate,
  Retry,
  DuplicateMinTtl,
  V4ServFail,
  V4NoData,
  V4NxDomain,
  RefusedThenNoData,
  NoDataThenRefused
};

struct DnsTelemetry {
  std::atomic<std::uint32_t> udp_queries{0};
  std::atomic<std::uint32_t> tcp_queries{0};
  std::atomic<bool> drop_replies{false};
  std::atomic<bool> release_family_reply{false};
  std::atomic<unsigned> first_family_reply{0};
};

struct QuestionSpan {
  bool ok{false};
  unsigned qtype{0};
  unsigned qend{0};
  bool zero_ttl{false};
};

[[nodiscard]] inline bool ReadFull(int fd, unsigned char* data, unsigned len) noexcept {
  unsigned got = 0;
  while (got < len) {
    const ssize_t n = ::read(fd, data + got, static_cast<std::size_t>(len - got));
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    got += static_cast<unsigned>(n);
  }
  return true;
}

[[nodiscard]] inline bool WriteFull(int fd, const unsigned char* data, unsigned len) noexcept {
  unsigned sent = 0;
  while (sent < len) {
    const ssize_t n = ::write(fd, data + sent, static_cast<std::size_t>(len - sent));
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    sent += static_cast<unsigned>(n);
  }
  return true;
}

[[nodiscard]] inline QuestionSpan ParseQuestion(const unsigned char* query, unsigned qlen) noexcept {
  if (qlen < 12) return {};
  unsigned off = 12;
  bool zero_ttl = false;
  if (off + 7 < qlen && query[off] == 7 && std::memcmp(query + off + 1, "zerottl", 7) == 0) {
    zero_ttl = true;
  }
  while (off < qlen) {
    const unsigned label = query[off];
    if (label == 0) {
      ++off;
      break;
    }
    if ((label & 0xC0u) == 0xC0u) {
      if (off + 2 > qlen) return {};
      off += 2;
      break;
    }
    if (off + 1 + label > qlen) return {};
    off += 1u + label;
  }
  if (off + 4 > qlen) return {};
  return QuestionSpan{
      .ok = true,
      .qtype = (static_cast<unsigned>(query[off]) << 8u) | query[off + 1],
      .qend = off + 4,
      .zero_ttl = zero_ttl,
  };
}

inline void WriteARecord(unsigned char* rr, std::uint32_t ttl, unsigned char last_octet) noexcept {
  rr[0] = 0xC0;
  rr[1] = 0x0C;
  rr[2] = 0;
  rr[3] = static_cast<unsigned char>(ARES_REC_TYPE_A);
  rr[4] = 0;
  rr[5] = 1;
  rr[6] = static_cast<unsigned char>((ttl >> 24u) & 0xffu);
  rr[7] = static_cast<unsigned char>((ttl >> 16u) & 0xffu);
  rr[8] = static_cast<unsigned char>((ttl >> 8u) & 0xffu);
  rr[9] = static_cast<unsigned char>(ttl & 0xffu);
  rr[10] = 0;
  rr[11] = 4;
  rr[12] = 192;
  rr[13] = 0;
  rr[14] = 2;
  rr[15] = last_octet;
}

[[nodiscard]] inline unsigned BuildReply(const unsigned char* query, unsigned qlen, unsigned char* out, unsigned cap,
                                         DnsMode mode, bool tcp) noexcept {
  const auto q = ParseQuestion(query, qlen);
  if (!q.ok || q.qend > cap) return 0;
  if (mode == DnsMode::DuplicateMinTtl && q.qtype == static_cast<unsigned>(ARES_REC_TYPE_A)) {
    const unsigned ancount = q.zero_ttl ? 2u : 3u;
    const unsigned need = q.qend + ancount * 16u;
    if (need > cap) return 0;
    std::memcpy(out, query, q.qend);
    out[2] = static_cast<unsigned char>(0x84u | (query[2] & 0x01u));
    out[3] = 0;
    out[4] = 0;
    out[5] = 1;
    out[6] = 0;
    out[7] = static_cast<unsigned char>(ancount);
    out[8] = out[9] = out[10] = out[11] = 0;
    if (q.zero_ttl) {
      WriteARecord(out + q.qend, 300u, 10);
      WriteARecord(out + q.qend + 16u, 0u, 11);
    } else {
      WriteARecord(out + q.qend, 120u, 10);
      WriteARecord(out + q.qend + 16u, 1u, 10);
      WriteARecord(out + q.qend + 32u, 90u, 11);
    }
    return need;
  }
  const bool v4 = q.qtype == static_cast<unsigned>(ARES_REC_TYPE_A);
  const bool servfail = mode == DnsMode::V4ServFail && v4;
  const bool ordered = mode == DnsMode::RefusedThenNoData || mode == DnsMode::NoDataThenRefused;
  const bool refused = ordered && v4;
  const bool nodata = (mode == DnsMode::V4NoData && v4) || (ordered && !v4);
  const bool nx = mode == DnsMode::NxDomain || (mode == DnsMode::V4NxDomain && v4);
  const bool tc = mode == DnsMode::Truncate && !tcp;
  const bool typed = q.qtype == static_cast<unsigned>(ARES_REC_TYPE_A) || q.qtype == static_cast<unsigned>(ARES_REC_TYPE_AAAA);
  const bool answer = !nx && !tc && !servfail && !refused && !nodata && typed;
  const unsigned rdlen = q.qtype == static_cast<unsigned>(ARES_REC_TYPE_AAAA) ? 16u : 4u;
  const unsigned need = q.qend + (answer ? 12u + rdlen : 0u);
  if (need > cap) return 0;
  std::memcpy(out, query, q.qend);
  auto flags = static_cast<unsigned char>(0x84u | (query[2] & 0x01u));
  if (tc) flags = static_cast<unsigned char>(flags | 0x02u);
  out[2] = flags;
  out[3] = nx ? 3u : (servfail ? 2u : (refused ? 5u : 0u));
  out[4] = 0;
  out[5] = 1;
  out[6] = 0;
  out[7] = answer ? static_cast<unsigned char>(1) : static_cast<unsigned char>(0);
  out[8] = out[9] = out[10] = out[11] = 0;
  if (!answer) return q.qend;
  unsigned char* rr = out + q.qend;
  rr[0] = 0xC0;
  rr[1] = 0x0C;
  rr[2] = static_cast<unsigned char>(q.qtype >> 8u);
  rr[3] = static_cast<unsigned char>(q.qtype & 0xffu);
  rr[4] = 0;
  rr[5] = 1;
  rr[6] = 0;
  rr[7] = 0;
  rr[8] = 0;
  rr[9] = 60;
  rr[10] = 0;
  rr[11] = static_cast<unsigned char>(rdlen);
  if (q.qtype == static_cast<unsigned>(ARES_REC_TYPE_A)) {
    rr[12] = 192;
    rr[13] = 0;
    rr[14] = 2;
    rr[15] = 10;
  } else {
    const std::array<unsigned char, 16> v6{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}};
    std::memcpy(rr + 12, v6.data(), 16);
  }
  return need;
}

inline void ServeUdp(int fd, DnsMode mode, DnsTelemetry* telemetry) noexcept {
  unsigned skips = 0;
  struct Reply {
    std::array<unsigned char, 512> bytes{};
    sockaddr_in peer{};
    socklen_t peer_len{sizeof(sockaddr_in)};
    unsigned len{0};
    unsigned type{0};
  };
  std::optional<Reply> pending;
  const auto send = [fd](const Reply& reply) noexcept {
    static_cast<void>(
        ::sendto(fd, reply.bytes.data(), reply.len, 0, std::bit_cast<const sockaddr*>(&reply.peer), reply.peer_len));
  };
  for (;;) {
    std::array<unsigned char, 512> query{{}};
    sockaddr_in from{};
    socklen_t fromlen = sizeof(from);
    const ssize_t n = ::recvfrom(fd, query.data(), sizeof(query), 0, reinterpret_cast<sockaddr*>(&from), &fromlen);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (n <= 0) continue;
    if (telemetry != nullptr) telemetry->udp_queries.fetch_add(1u, std::memory_order_release);
    if (mode == DnsMode::Drop || (telemetry != nullptr && telemetry->drop_replies.load(std::memory_order_acquire))) {
      continue;
    }
    if (mode == DnsMode::Retry && skips == 0) {
      ++skips;
      continue;
    }
    std::array<unsigned char, 512> reply{{}};
    const unsigned len = BuildReply(query.data(), static_cast<unsigned>(n), reply.data(), sizeof(reply), mode, false);
    if (len == 0) continue;
    if ((mode == DnsMode::RefusedThenNoData || mode == DnsMode::NoDataThenRefused) && telemetry != nullptr &&
        !telemetry->release_family_reply.load(std::memory_order_acquire)) {
      const Reply incoming{reply, from, fromlen, len, ParseQuestion(query.data(), static_cast<unsigned>(n)).qtype};
      if (!pending) {
        pending = incoming;
        continue;
      }
      const bool first_v4 = mode == DnsMode::RefusedThenNoData;
      const bool pending_v4 = pending->type == ARES_REC_TYPE_A;
      const auto& first = first_v4 == pending_v4 ? *pending : incoming;
      const auto& second = first_v4 == pending_v4 ? incoming : *pending;
      telemetry->first_family_reply.store(first.type, std::memory_order_release);
      send(first);
      while (!telemetry->release_family_reply.load(std::memory_order_acquire)) static_cast<void>(::sched_yield());
      send(second);
      pending.reset();
      continue;
    }
    static_cast<void>(::sendto(fd, reply.data(), len, 0, reinterpret_cast<sockaddr*>(&from), fromlen));
  }
}

inline void ServeTcp(int fd, DnsMode mode, DnsTelemetry* telemetry) noexcept {
  for (;;) {
    const int client = ::accept(fd, nullptr, nullptr);
    if (client < 0) {
      if (errno == EINTR) continue;
      break;
    }
    std::array<unsigned char, 2> prefix{{}};
    std::array<unsigned char, 512> query{{}};
    std::array<unsigned char, 512> reply{{}};
    std::array<unsigned char, 514> frame{{}};
    const bool prefix_ok = ReadFull(client, prefix.data(), 2);
    const unsigned qlen = prefix_ok ? (static_cast<unsigned>(prefix[0]) << 8u) | prefix[1] : 0u;
    if (prefix_ok && qlen > 0 && qlen <= sizeof(query) && ReadFull(client, query.data(), qlen)) {
      if (telemetry != nullptr) telemetry->tcp_queries.fetch_add(1u, std::memory_order_release);
      const unsigned len = BuildReply(query.data(), qlen, reply.data(), sizeof(reply), mode, true);
      if (len > 0 && len + 2 <= sizeof(frame)) {
        frame[0] = static_cast<unsigned char>(len >> 8u);
        frame[1] = static_cast<unsigned char>(len & 0xffu);
        std::memcpy(frame.data() + 2, reply.data(), len);
        static_cast<void>(WriteFull(client, frame.data(), len + 2));
      }
    }
    static_cast<void>(::close(client));
  }
}

class LocalDns {
 public:
  explicit LocalDns(DnsMode mode) noexcept {
    void* mem = ::mmap(nullptr, sizeof(DnsTelemetry), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    telemetry_ = (mem != MAP_FAILED) ? std::construct_at(static_cast<DnsTelemetry*>(mem)) : nullptr;
    int udp = -1;
    int tcp = -1;
    sockaddr_in addr{};
    for (int attempt = 0; attempt < 8 && port_ == 0; ++attempt) {
      udp = ::socket(AF_INET, SOCK_DGRAM, 0);
      if (udp < 0) return;
      addr = {};
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = (std::endian::native == std::endian::little ? std::byteswap(0x7f000001u) : 0x7f000001u);
      addr.sin_port = 0;
      if (::bind(udp, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        static_cast<void>(::close(udp));
        udp = -1;
        continue;
      }
      socklen_t alen = sizeof(addr);
      if (::getsockname(udp, reinterpret_cast<sockaddr*>(&addr), &alen) != 0) {
        static_cast<void>(::close(udp));
        udp = -1;
        continue;
      }
      tcp = ::socket(AF_INET, SOCK_STREAM, 0);
      if (tcp < 0) {
        static_cast<void>(::close(udp));
        udp = -1;
        return;
      }
      const int yes = 1;
      static_cast<void>(::setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &yes, static_cast<socklen_t>(sizeof(yes))));
      if (::bind(tcp, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(tcp, 8) != 0) {
        static_cast<void>(::close(udp));
        static_cast<void>(::close(tcp));
        udp = -1;
        tcp = -1;
        continue;
      }
      port_ = (std::endian::native == std::endian::little ? std::byteswap(addr.sin_port) : addr.sin_port);
    }
    if (port_ == 0 || udp < 0 || tcp < 0) return;
    const pid_t udp_pid = ::fork();
    if (udp_pid < 0) {
      static_cast<void>(::close(udp));
      static_cast<void>(::close(tcp));
      port_ = 0;
      return;
    }
    if (udp_pid == 0) {
      static_cast<void>(::close(tcp));
      static_cast<void>(::signal(SIGPIPE, SIG_IGN));
      ServeUdp(udp, mode, telemetry_);
      _exit(0);
    }
    const pid_t tcp_pid = ::fork();
    if (tcp_pid < 0) {
      static_cast<void>(::kill(udp_pid, SIGTERM));
      int status = 0;
      static_cast<void>(::waitpid(udp_pid, &status, 0));
      static_cast<void>(::close(udp));
      static_cast<void>(::close(tcp));
      port_ = 0;
      return;
    }
    if (tcp_pid == 0) {
      static_cast<void>(::close(udp));
      static_cast<void>(::signal(SIGPIPE, SIG_IGN));
      ServeTcp(tcp, mode, telemetry_);
      _exit(0);
    }
    udp_pid_ = udp_pid;
    tcp_pid_ = tcp_pid;
    static_cast<void>(::close(udp));
    static_cast<void>(::close(tcp));
  }

  void ReleaseFamilyReply() noexcept {
    if (telemetry_ != nullptr) telemetry_->release_family_reply.store(true, std::memory_order_release);
  }

  [[nodiscard]] unsigned FirstFamilyReply() const noexcept {
    return telemetry_ == nullptr ? 0u : telemetry_->first_family_reply.load(std::memory_order_acquire);
  }

  LocalDns(const LocalDns&) = delete ("single-owner resource");
  LocalDns& operator=(const LocalDns&) = delete ("single-owner resource");

  ~LocalDns() {
    Stop();
    if (telemetry_ != nullptr) {
      std::destroy_at(telemetry_);
      static_cast<void>(::munmap(telemetry_, sizeof(DnsTelemetry)));
      telemetry_ = nullptr;
    }
  }

  void Stop() noexcept {
    Reap(udp_pid_);
    udp_pid_ = -1;
    Reap(tcp_pid_);
    tcp_pid_ = -1;
  }

  [[nodiscard]] std::uint16_t Port() const noexcept { return port_; }
  [[nodiscard]] std::uint32_t UdpQueries() const noexcept {
    return telemetry_ != nullptr ? telemetry_->udp_queries.load(std::memory_order_acquire) : 0u;
  }
  [[nodiscard]] std::uint32_t TcpQueries() const noexcept {
    return telemetry_ != nullptr ? telemetry_->tcp_queries.load(std::memory_order_acquire) : 0u;
  }
  void SetDropReplies(bool drop) noexcept {
    if (telemetry_ != nullptr) telemetry_->drop_replies.store(drop, std::memory_order_release);
  }

 private:
  static void Reap(pid_t pid) noexcept {
    if (pid <= 0) return;
    static_cast<void>(::kill(pid, SIGTERM));
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
  }

  DnsTelemetry* telemetry_{nullptr};
  std::uint16_t port_{0};
  pid_t udp_pid_{-1};
  pid_t tcp_pid_{-1};
};

[[nodiscard]] inline ChannelOptions MockOptions(std::uint16_t port, std::uint32_t timeout_ms, std::uint32_t tries) noexcept {
  ChannelOptions options;
  static_cast<void>(options.WithTimeoutMs(timeout_ms).WithTries(tries).WithNdots(1));
  options.flags = ARES_FLAG_NOSEARCH | ARES_FLAG_EDNS | ARES_FLAG_STAYOPEN;
  const ServerEndpoint server{IpAddress::FromV4(Ipv4Bytes{127, 0, 0, 1}), port, false};
  static_cast<void>(options.AddServer(server));
  return options;
}

[[nodiscard]] inline ResolverConfig Ipv4Config() noexcept {
  ResolverConfig cfg;
  cfg.family = IpFamily::Ipv4;
  cfg.enable_hosts = false;
  return cfg;
}

[[nodiscard]] inline ResolverConfig DualConfig() noexcept {
  ResolverConfig cfg;
  cfg.family = IpFamily::DualStack;
  cfg.enable_hosts = false;
  return cfg;
}

}  // namespace cares::test
