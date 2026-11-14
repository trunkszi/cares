cmake_minimum_required(VERSION 4.0)
foreach(source IN ITEMS
  smoke_test.cc
  ares_error_test.cc
  dns_types_test.cc
  host_types_test.cc
  endpoint_test.cc
  query_handle_test.cc
  dns_record_test.cc
  record_rr_test.cc
  query_table_test.cc
  record_extract_test.cc
  library_guard_test.cc
  options_test.cc
  socket_bridge_test.cc
  timer_state_test.cc
  callback_table_test.cc
  completion_words_test.cc
  channel_core_test.cc
  poll_table_test.cc
  dns_cache_test.cc
)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
    get_filename_component(target "${source}" NAME_WE)
    cares_add_test(${target} "${source}")
  endif()
endforeach()
if(CARES_BUILD_TOOLS)
  cares_add_codegen_probes(cares_t1_probes smoke_test.cc)
  target_compile_definitions(cares_t1_probes PRIVATE CARES_CODEGEN_PROBE=1)
endif()
