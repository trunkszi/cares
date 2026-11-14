cmake_minimum_required(VERSION 4.0)
foreach(source IN ITEMS
  error_types_consteval_test.cc
  record_rr_consteval_test.cc
  query_table_consteval_test.cc
  record_extract_consteval_test.cc
  channel_primitives_consteval_test.cc
  poll_table_cache_consteval_test.cc
)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
    get_filename_component(target "${source}" NAME_WE)
    cares_add_test(${target} "${source}")
  endif()
endforeach()
