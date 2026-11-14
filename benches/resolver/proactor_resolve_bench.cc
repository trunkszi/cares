#include "../../tests/e2e/local_dns_fixture.hpp"
#if defined(CARES_HAS_PROBES)
#include <cares/probes/probes.hpp>
#endif

#include <array>
#include <cares/record/dns_record.hpp>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string_view>
#include <uring/uring.hpp>
#include <utility>

namespace {

int RunProbeLoop([[maybe_unused]] std::string_view probe, [[maybe_unused]] std::uint64_t iterations) noexcept {
#if !defined(CARES_HAS_PROBES)
  return 2;
#else
  if (probe == "cares_probe_resolver_step") {
    for (std::uint64_t i = 0; i < iterations; ++i) {
      cares_probe_resolver_step();
      asm volatile("" ::: "memory");
    }
    return 0;
  }
  if (probe == "cares_probe_poll_flush") {
    for (std::uint64_t i = 0; i < iterations; ++i) {
      cares_probe_poll_flush();
      asm volatile("" ::: "memory");
    }
    return 0;
  }
  if (probe == "cares_probe_timer_reconcile") {
    for (std::uint64_t i = 0; i < iterations; ++i) {
      cares_probe_timer_reconcile();
      asm volatile("" ::: "memory");
    }
    return 0;
  }
  if (probe == "cares_probe_record_view") {
    ares_library_init(ARES_LIB_INIT_ALL);
    auto owned = cares::DnsRecord::CreateQuery("probe.example", cares::DnsType::A, cares::DnsClass::IN, 0x0B11);
    if (!owned) return 2;
    std::array<std::byte, 512> storage{};
    const auto wire = owned->WriteWire(storage);
    if (!wire) return 2;
    for (std::uint64_t i = 0; i < iterations; ++i) {
      cares_probe_record_view(std::span<const std::byte>{storage}.first(*wire));
      asm volatile("" ::: "memory");
    }
    return 0;
  }
  return 2;
#endif
}

template <typename Fn>
[[nodiscard]] std::uint64_t Median(Fn&& fn) noexcept {
  std::array<std::uint64_t, 32> samples{};
  for (std::uint64_t& sample : samples) {
    const auto start = std::chrono::steady_clock::now();
    if (!fn()) return 0;
    sample = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count());
  }
  for (std::size_t i = 1; i < samples.size(); ++i) {
    const std::uint64_t key = samples[i];
    std::size_t slot = i;
    while (slot > 0 && samples[slot - 1] > key) {
      samples[slot] = samples[slot - 1];
      --slot;
    }
    samples[slot] = key;
  }
  return samples[samples.size() / 2];
}

[[nodiscard]] std::optional<std::uint64_t> ParseIterations(const char* text) noexcept {
  if (text == nullptr || *text == '\0') return std::nullopt;
  errno = 0;
  char* end = nullptr;
  const unsigned long long value = std::strtoull(text, &end, 10);
  if (end == text || *end != '\0' || errno == ERANGE || value == 0) return std::nullopt;
  return static_cast<std::uint64_t>(value);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc >= 5 && std::string_view{argv[1]} == "--probe" && std::string_view{argv[3]} == "--iterations") {
    const auto iterations = ParseIterations(argv[4]);
    if (!iterations.has_value()) return 2;
    return RunProbeLoop(argv[2], *iterations);
  }
  cares::test::LocalDns dns(cares::test::DnsMode::Answer);
  if (dns.Port() == 0) return 1;
  auto ring = uring::Proactor::Create(64, uring::RingMode::kStandard64_16, cares::Resolver<>::RequiredCaps());
  if (!ring) return 1;
  auto made = cares::Resolver<>::Create(*ring, cares::test::MockOptions(dns.Port(), 200, 2), cares::test::Ipv4Config());
  if (!made) return 1;
  if (!made->InsertStaticHost("app.internal", cares::IpAddress::FromV4(cares::Ipv4Bytes{10, 1, 2, 3}))) return 1;
  auto primed = made->ResolveEndpoints("app.example", 53, 2000);
  if (!primed) return 1;
  dns.Stop();
  const std::uint64_t literal = Median([&]() noexcept {
    auto resolved = made->ResolveEndpoints("127.0.0.1:4001", 80, 50);
    return resolved && resolved->size() == 1;
  });
  const std::uint64_t hosts = Median([&]() noexcept {
    auto resolved = made->ResolveEndpoints("app.internal", 53, 50);
    return resolved && resolved->size() == 1;
  });
  const std::uint64_t cached = Median([&]() noexcept {
    auto resolved = made->ResolveEndpoints("app.example", 53, 50);
    return resolved && resolved->size() == 1;
  });
  if (literal == 0 || hosts == 0 || cached == 0) return 1;
  std::printf("p50_ns literal %llu hosts %llu cache %llu\n", static_cast<unsigned long long>(literal),
              static_cast<unsigned long long>(hosts), static_cast<unsigned long long>(cached));
  return 0;
}
