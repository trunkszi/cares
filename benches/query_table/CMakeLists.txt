cmake_minimum_required(VERSION 4.0)
find_package(benchmark CONFIG REQUIRED)

add_executable(query_table_bench query_table_bench.cc)
target_link_libraries(query_table_bench PRIVATE benchmark::benchmark)
cares_configure_internal(query_table_bench)
