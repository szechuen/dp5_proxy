cmake_minimum_required (VERSION 2.8)

project (DP5)

set (DP5_VERSION_MAJOR 0)
set (DP5_VERSION_MINOR 01)

set (CMAKE_CXX_FLAGS "-g -O0 -Wall -Werror -Wno-deprecated-declarations -fPIC")

set (PERCYDIR ${CMAKE_CURRENT_SOURCE_DIR}/../percy)


find_file(NTL_INCLUDE_DIR "NTL/")

include_directories(${PERCYDIR})
include_directories(${NTL_INCLUDE_DIR})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_library (dp5 curve25519-donna.c dp5lookupclient.cpp dp5lookupserver.cpp dp5params.cpp dp5regclient.cpp dp5regserver.cpp)

add_executable(test_dh dp5params.cpp curve25519-donna.c)
set_target_properties(test_dh PROPERTIES COMPILE_DEFINITIONS TEST_DH)
target_link_libraries(test_dh ${OPENSSL_LIBRARIES})

enable_testing()
add_test(test_dh test_dh)

set_tests_properties (test_dh PROPERTIES PASS_REGULAR_EXPRESSION "MATCH")
set_tests_properties (test_dh PROPERTIES FAIL_REGULAR_EXPRESSION "NO MATCH")