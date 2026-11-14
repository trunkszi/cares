cmake_minimum_required(VERSION 4.0)
find_package(benchmark CONFIG REQUIRED)

add_executable(dns_record_bench dns_record_bench.cc)
cares_configure_internal(dns_record_bench)
target_link_libraries(dns_record_bench PRIVATE benchmark::benchmark)
