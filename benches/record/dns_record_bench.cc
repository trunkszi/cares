#include <ares.h>
#include <benchmark/benchmark.h>

#include <algorithm>
#include <array>
#include <cares/record/dns_record.hpp>
#include <cares/record/record_rr.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

namespace cares {
namespace {

[[nodiscard]] DnsRecord BuildSamplePacket() noexcept {
  auto pkt =
      DnsRecord::Create(0x4242, DnsFlags::Qr | DnsFlags::Aa | DnsFlags::Rd | DnsFlags::Ra, DnsOpcode::Query, DnsRcode::NoError);
  if (!pkt) return {};
  static_cast<void>(pkt->QuestionPush("api.edge.example.com", DnsType::A, DnsClass::IN));
  static_cast<void>(pkt->AddRr(RecordSection::Answer, "api.edge.example.com",
                               ARecord{.addr = IpAddress::FromV4({10, 24, 8, 99}), .ttl = 60}));
  static_cast<void>(pkt->AddRr(
      RecordSection::Answer, "api.edge.example.com",
      AaaaRecord{.addr = IpAddress::FromV6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), .ttl = 60}));
  static_cast<void>(pkt->AddRr(RecordSection::Additional, "", OptRecord{.udp_size = 1232, .version = 0, .flags = 0, .ttl = 0}));
  return std::move(*pkt);
}

void BmDnsRecordRefExtractA(benchmark::State& state) {
  const DnsRecord pkt = BuildSamplePacket();
  const DnsRecordRef view = pkt.AsRef();
  for (auto _ : state) {
    auto a_res = view.ExtractRrAt<ARecord>(RecordSection::Answer, 0);
    auto q_res = view.QuestionAt(0);
    benchmark::DoNotOptimize(a_res);
    benchmark::DoNotOptimize(q_res);
  }
}

void BmDnsRecordParseAndExtract(benchmark::State& state) {
  const DnsRecord pkt = BuildSamplePacket();
  std::array<std::byte, 512> wire{};
  const auto wire_len = pkt.WriteWire(wire).value_or(0);
  const std::span<const std::byte> wire_span(wire.data(), wire_len);
  for (auto _ : state) {
    auto parsed = DnsRecord::ParseWire(wire_span);
    if (!parsed.has_value()) return;
    auto a_res = parsed->ExtractRrAt<ARecord>(RecordSection::Answer, 0);
    benchmark::DoNotOptimize(parsed);
    benchmark::DoNotOptimize(a_res);
  }
}

void BmDnsRecordCreateAndWriteWire(benchmark::State& state) {
  std::array<std::byte, 512> wire{};
  for (auto _ : state) {
    auto pkt = DnsRecord::CreateQuery("api.edge.example.com", DnsType::A, DnsClass::IN, 0x1001);
    if (!pkt.has_value()) return;
    static_cast<void>(
        pkt->AddRr(RecordSection::Additional, "", OptRecord{.udp_size = 1232, .version = 0, .flags = 0, .ttl = 0}));
    auto written = pkt->WriteWire(wire);
    benchmark::DoNotOptimize(written);
    benchmark::DoNotOptimize(wire);
  }
}

[[nodiscard]] bool ReportQuantiles() noexcept {
  using Clock = std::chrono::steady_clock;
  const DnsRecord pkt = BuildSamplePacket();
  const DnsRecordRef view = pkt.AsRef();
  std::array<double, 4096> samples{};
  std::uint64_t checksum = 0;
  for (double& s : samples) {
    const auto t0 = Clock::now();
    const auto a_res = view.ExtractRrAt<ARecord>(RecordSection::Answer, 0);
    const auto aaaa_res = view.ExtractRrAt<AaaaRecord>(RecordSection::Answer, 1);
    if (!a_res || !aaaa_res) return false;
    checksum += a_res->ttl + aaaa_res->ttl;
    s = std::chrono::duration<double, std::nano>(Clock::now() - t0).count();
  }
  std::sort(samples.begin(), samples.end());
  std::printf("dns_record_ref extract ns p50=%.1f p90=%.1f p99=%.1f p99.9=%.1f checksum=%llu\n", samples[2048], samples[3686],
              samples[4055], samples[4091], static_cast<unsigned long long>(checksum));
  return checksum == 4096ULL * 120ULL;
}

}  // namespace
}  // namespace cares

int main(int argc, char** argv) {
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) return 1;
  if (!cares::ReportQuantiles()) {
    ares_library_cleanup();
    return 2;
  }
  static_cast<void>(benchmark::RegisterBenchmark("BmDnsRecordRefExtractA", cares::BmDnsRecordRefExtractA));
  static_cast<void>(benchmark::RegisterBenchmark("BmDnsRecordParseAndExtract", cares::BmDnsRecordParseAndExtract));
  static_cast<void>(benchmark::RegisterBenchmark("BmDnsRecordCreateAndWriteWire", cares::BmDnsRecordCreateAndWriteWire));
  benchmark::Initialize(&argc, argv);
  if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
    ares_library_cleanup();
    return 1;
  }
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  ares_library_cleanup();
  return 0;
}
