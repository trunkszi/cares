#include <ares.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cares/channel/channel_core.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
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

struct DnsCapture {
  int calls{0};
  cares::Error error{};
  bool ok{false};
  void OnDns(cares::Result<cares::DnsRecordRef> result) noexcept {
    ++calls;
    ok = result.has_value();
    if (!ok) error = result.error();
  }
};

struct SockCapture {
  int calls{0};
  void OnSocket(int, cares::SocketInterest) noexcept { ++calls; }
};

cares::DnsRecCallback DnsCb(DnsCapture& capture) noexcept { return uarch::bind<&DnsCapture::OnDns>(capture); }

cares::SocketStateObserver SockCb(SockCapture& capture) noexcept { return uarch::bind<&SockCapture::OnSocket>(capture); }

cares::ChannelOptions Blackhole() noexcept {
  cares::ChannelOptions options{};
  if (auto added = options.AddServer(
          cares::ServerEndpoint{.ip = cares::IpAddress::FromV4({192, 0, 2, 1}), .port = 53, .use_tcp = false});
      !added.has_value()) {
    return options;
  }
  options = options.WithTimeoutMs(2000);
  options = options.WithTries(1);
  return options;
}

bool CsvContains(ares_channel_t* channel, const char* needle) {
  char* csv = ares_get_servers_csv(channel);
  const bool found = csv != nullptr && std::strstr(csv, needle) != nullptr;
  if (csv != nullptr) ares_free_string(csv);
  return found;
}

int FromSystemOneLiveChannel() {
  auto channel = cares::ChannelCore<>::FromSystem();
  if (!channel || channel->Raw() == nullptr) return __LINE__;
  if (!CsvContains(channel->Raw(), "127.0.0.53") && !CsvContains(channel->Raw(), ".")) return __LINE__;
  if (channel->ActiveQueryCount() != 0) return __LINE__;
  channel->Destroy();
  if (channel->Raw() != nullptr) return __LINE__;
  DnsCapture capture;
  const auto rejected = channel->SubmitQuery("example", cares::DnsClass::IN, cares::DnsType::A, DnsCb(capture));
  if (rejected.has_value()) return __LINE__;
  return 0;
}

int CreateSetsListedServers() {
  auto channel = cares::ChannelCore<>::Create(Blackhole());
  if (!channel || channel->Raw() == nullptr) return __LINE__;
  if (!CsvContains(channel->Raw(), "192.0.2.1")) return __LINE__;
  if (CsvContains(channel->Raw(), "127.0.0.53")) return __LINE__;
  return 0;
}

int SubmitQueryCancelCompletes() {
  auto channel = cares::ChannelCore<>::Create(Blackhole());
  if (!channel) return __LINE__;
  DnsCapture capture;
  const auto handle = channel->SubmitQuery("cancel.invalid", cares::DnsClass::IN, cares::DnsType::A, DnsCb(capture));
  if (!handle) return __LINE__;
  channel->CancelAll();
  if (capture.calls != 1 || !capture.error.IsCancelled()) return __LINE__;
  if (channel->ActiveQueryCount() != 0) return __LINE__;
  return 0;
}

int CancelOneSiblingCompletes() {
  cares::ChannelOptions options{};
  if (auto added = options.AddServer(
          cares::ServerEndpoint{.ip = cares::IpAddress::FromV4({192, 0, 2, 1}), .port = 53, .use_tcp = false});
      !added.has_value()) {
    return __LINE__;
  }
  options = options.WithTimeoutMs(50);
  options = options.WithTries(1);
  auto channel = cares::ChannelCore<>::Create(options);
  if (!channel) return __LINE__;
  DnsCapture dropped;
  DnsCapture sibling;
  const auto first = channel->SubmitQuery("drop.invalid", cares::DnsClass::IN, cares::DnsType::A, DnsCb(dropped));
  const auto second = channel->SubmitQuery("keep.invalid", cares::DnsClass::IN, cares::DnsType::A, DnsCb(sibling));
  if (!first || !second) return __LINE__;
  if (!channel->CancelQuery(*first) || dropped.calls != 0) return __LINE__;
  if (channel->ActiveQueryCount() != 2) return __LINE__;
  for (int i = 0; i < 40 && (sibling.calls == 0 || channel->ActiveQueryCount() != 0); ++i) {
    channel->ProcessTimeouts();
    const timespec pause{.tv_sec = 0, .tv_nsec = 20'000'000};
    nanosleep(&pause, nullptr);
  }
  if (dropped.calls != 0 || sibling.calls != 1) return __LINE__;
  if (channel->ActiveQueryCount() != 0) return __LINE__;
  return 0;
}

int BatchSkipsNonFd() {
  auto channel = cares::ChannelCore<>::Create(Blackhole());
  if (!channel) return __LINE__;
  const auto empty = channel->ProcessBatch({});
  if (!empty) return __LINE__;
  ares_fd_events_t ignored{.fd = 1, .events = 0};
  const auto skipped = channel->ProcessBatch(std::span<const ares_fd_events_t>{&ignored, 1});
  if (!skipped) return __LINE__;
  channel->ProcessTimeouts();
  return 0;
}

int TimeoutRespectsCap() {
  auto channel = cares::ChannelCore<>::Create(Blackhole());
  if (!channel) return __LINE__;
  DnsCapture capture;
  if (!channel->SubmitQuery("timeout.invalid", cares::DnsClass::IN, cares::DnsType::A, DnsCb(capture))) return __LINE__;
  const auto deadline = channel->NextTimeout(50);
  if (!deadline.armed || deadline.relative_ns > 50'000'000ULL) return __LINE__;
  channel->CancelAll();
  return 0;
}

int ReinitKeepsChannel() {
  auto channel = cares::ChannelCore<>::Create(Blackhole());
  if (!channel) return __LINE__;
  ares_channel_t* before = channel->Raw();
  if (!channel->Reinit()) return __LINE__;
  if (channel->Raw() != before) return __LINE__;
  if (!CsvContains(channel->Raw(), "192.0.2.1")) return __LINE__;
  return 0;
}

int DestroyRejectsSubmit() {
  auto channel = cares::ChannelCore<>::Create(Blackhole());
  if (!channel) return __LINE__;
  channel->Destroy();
  DnsCapture capture;
  const auto rejected = channel->SubmitQuery("gone.invalid", cares::DnsClass::IN, cares::DnsType::A, DnsCb(capture));
  if (rejected.has_value() || capture.calls != 0) return __LINE__;
  if (channel->Reinit().has_value()) return __LINE__;
  return 0;
}

int EmptyResolvRejects() {
  TempFile file;
  if (OpenTemp(file, "resolv") < 0) return __LINE__;
  if (::close(file.fd) != 0) return __LINE__;
  file.fd = -1;
  cares::ChannelOptions options{};
  const auto stored = options.SetResolvconfPath(file.path.data());
  if (!stored.has_value()) return __LINE__;
  auto channel = cares::ChannelCore<>::Create(options);
  if (channel.has_value() || channel.error() != cares::Error::InvalidArgument()) return __LINE__;
  return 0;
}

int MoveKeepsSocketBridge() {
  SockCapture sockets;
  auto channel = cares::ChannelCore<>::Create(Blackhole(), SockCb(sockets));
  if (!channel) return __LINE__;
  DnsCapture capture;
  if (!channel->SubmitQuery("move.invalid", cares::DnsClass::IN, cares::DnsType::A, DnsCb(capture))) return __LINE__;
  if (sockets.calls == 0) return __LINE__;
  const int before = sockets.calls;
  cares::ChannelCore<> moved = std::move(*channel);
  moved.Destroy();
  if (sockets.calls < before) return __LINE__;
  if (moved.Raw() != nullptr) return __LINE__;
  return 0;
}

}  // namespace

int main() {
  const std::array<int, 10> tests{{FromSystemOneLiveChannel(), CreateSetsListedServers(), SubmitQueryCancelCompletes(),
                                   CancelOneSiblingCompletes(), BatchSkipsNonFd(), TimeoutRespectsCap(), ReinitKeepsChannel(),
                                   DestroyRejectsSubmit(), EmptyResolvRejects(), MoveKeepsSocketBridge()}};
  for (int line : tests) {
    if (line != 0) {
      std::fprintf(stderr, "channel_core_test failed at line %d\n", line);
      return line;
    }
  }
  return 0;
}
