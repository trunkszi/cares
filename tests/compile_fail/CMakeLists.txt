cmake_minimum_required(VERSION 4.0)
foreach(source IN ITEMS
  smoke_compile_fail.cc
  error_DiscardResult_compile_fail.cc
  endpoint_InvalidPort_compile_fail.cc
  record_InvalidKey_compile_fail.cc
  query_table_DuplicateRoute_compile_fail.cc
  record_extract_UnannotatedField_compile_fail.cc
  record_extract_WrongRrKey_compile_fail.cc
  callback_table_ZeroCapacity_compile_fail.cc
  poll_table_Copy_compile_fail.cc
)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
    get_filename_component(target "${source}" NAME_WE)
    cares_add_compile_fail(${target} "${source}")
  endif()
endforeach()
