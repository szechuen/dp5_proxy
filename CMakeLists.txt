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

add_library(curve25519-donna curve25519-donna.c)

macro(testdef TARGET SOURCES) 
	string(TOUPPER ${TARGET} TARGET_UPPER)
	add_executable(${TARGET} ${SOURCES})
	set_target_properties(${TARGET} PROPERTIES COMPILE_DEFINITIONS ${TARGET_UPPER})
	target_link_libraries(${TARGET} ${OPENSSL_LIBRARIES} curve25519-donna ${ARGN})
	add_test(${TARGET} ${TARGET})
endmacro(testdef)

enable_testing()

testdef(test_dh dp5params.cpp)
set_tests_properties (test_dh PROPERTIES PASS_REGULAR_EXPRESSION "MATCH")
set_tests_properties (test_dh PROPERTIES FAIL_REGULAR_EXPRESSION "NO MATCH")

testdef(test_hashes dp5params.cpp)

testdef(test_prf dp5params.cpp)

testdef(test_enc dp5params.cpp)

testdef(test_epoch dp5params.cpp)
set_tests_properties (test_epoch PROPERTIES PASS_REGULAR_EXPRESSION "successful")
set_tests_properties (test_epoch PROPERTIES FAIL_REGULAR_EXPRESSION "NO MATCH;failed")

testdef(test_rsconst "dp5regserver.cpp;dp5params.cpp")

testdef(test_rsreg "dp5regserver.cpp;dp5params.cpp" pthread)

testdef(test_client "dp5regclient.cpp;dp5params.cpp" pthread)
set_tests_properties (test_client PROPERTIES FAIL_REGULAR_EXPRESSION "False")