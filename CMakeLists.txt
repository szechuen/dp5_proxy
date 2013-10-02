cmake_minimum_required (VERSION 2.8)

project (DP5)

set (DP5_VERSION_MAJOR 0)
set (DP5_VERSION_MINOR 01)

set (CMAKE_CXX_FLAGS "-g -O0 -Wall -Werror -Wno-deprecated-declarations -fPIC")

set (PERCYDIR ${CMAKE_CURRENT_SOURCE_DIR}/../percy)

find_library(NTL ntl)
find_file(NTL_INCLUDE_DIR "NTL/")

set (PERCYDIR ${CMAKE_CURRENT_SOURCE_DIR}/../percy)
find_library(PERCYSERVER NAMES percyserver PATHS ${PERCYDIR})
find_library(PERCYCLIENT NAMES percyclient PATHS ${PERCYDIR})
find_file(PERCYH NAMES percyclient.h PATHS ${PERCYDIR})
string(REGEX REPLACE "[^/]+$" "" PERCYINCLUDE ${PERCYH})

include_directories(${PERCYINCLUDE})
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

testdef(test_lscd "dp5lookupserver.cpp;dp5params.cpp" ${NTL} ${PERCYSERVER})
testdef(test_reqcd "dp5lookupclient.cpp;dp5params.cpp" ${NTL} ${PERCYCLIENT})
testdef(test_pirglue "dp5lookupserver.cpp;dp5lookupclient.cpp;dp5params.cpp" ${NTL} ${PERCYSERVER} ${PERCYCLIENT})
testdef(test_pirgluemt "dp5lookupserver.cpp;dp5lookupclient.cpp;dp5params.cpp" ${NTL} ${PERCYSERVER} ${PERCYCLIENT} pthread)

add_executable(test_integrate dp5integrationtest.cpp)
target_link_libraries(test_integrate dp5 curve25519-donna ${OPENSSL_LIBRARIES} ${PERCYCLIENT} ${PERCYSERVER} ${NTL})
add_test(IntegrationTest test_integrate)
