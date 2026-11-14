#include <benchmark/benchmark.h>

#include <algorithm>
#include <array>
#include <cares/query_table/query_table.hpp>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

struct[[= cares::notes::QueryRoute("example.com", cares::DnsType::A)]] BenchA {};
struct[[= cares::notes::QueryRoute("example.com", cares::DnsType::MX)]] BenchMx {};
struct[[= cares::notes::QueryRoute("www.example.com", cares::DnsType::AAAA)]] BenchAaaa {};

struct Hit {
  std::uint64_t count{0};
  template <typename Route>
  void operator()(const cares::FirstQuestionWire &question) noexcept {
    count += static_cast<std::uint64_t>(question.qtype) + 1;
  }
};

constexpr std::array<std::byte, 29> ExamplePacket() {
  std::array<std::byte, 29> packet{};
  packet[5] = std::byte{1};
  const std::array<unsigned char, 13> name{{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}};
  for (std::size_t index = 0; index < sizeof(name); ++index) {
    packet[12 + index] = std::byte{name[index]};
  }
  packet[26] = std::byte{1};
  packet[28] = std::byte{1};
  return packet;
}

[[gnu::noinline]] cares::Result<cares::FirstQuestionWire> ParseProbe(std::span<const std::byte> packet) noexcept {
  return cares::ParseFirstQuestionWire(packet);
}

[[gnu::noinline]] cares::Result<std::uint16_t> DispatchProbe(std::span<const std::byte> packet, Hit &hit) noexcept {
  return cares::QueryTable<BenchA, BenchMx, BenchAaaa>::DispatchWireQuestion(packet, hit);
}

double Percentile(const std::vector<double> &samples, double fraction) {
  if (samples.empty()) return 0;
  std::vector<double> ordered = samples;
  std::sort(ordered.begin(), ordered.end());
  const auto rank = static_cast<std::size_t>(std::ceil(fraction * static_cast<double>(ordered.size())));
  const auto index = rank == 0 ? std::size_t{0} : std::min(ordered.size() - 1, rank - 1);
  return ordered[index];
}

static void ParseFirstQuestion(benchmark::State &state) {
  constexpr auto kPacket = ExamplePacket();
  for (auto _ : state) {
    auto parsed = ParseProbe(std::span<const std::byte>{kPacket});
    benchmark::DoNotOptimize(parsed);
  }
}

static void DispatchWireQuestion(benchmark::State &state) {
  constexpr auto kPacket = ExamplePacket();
  Hit hit;
  for (auto _ : state) {
    auto index = DispatchProbe(std::span<const std::byte>{kPacket}, hit);
    benchmark::DoNotOptimize(index);
  }
  benchmark::DoNotOptimize(hit.count);
}

BENCHMARK(ParseFirstQuestion)
    ->ComputeStatistics("p50", [](const std::vector<double> &samples) { return Percentile(samples, 0.50); })
    ->ComputeStatistics("p90", [](const std::vector<double> &samples) { return Percentile(samples, 0.90); })
    ->ComputeStatistics("p99", [](const std::vector<double> &samples) { return Percentile(samples, 0.99); })
    ->ComputeStatistics("p99.9", [](const std::vector<double> &samples) { return Percentile(samples, 0.999); });

BENCHMARK(DispatchWireQuestion);

BENCHMARK_MAIN();
