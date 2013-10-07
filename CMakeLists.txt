cmake_minimum_required (VERSION 2.8)

project (DP5)

set (DP5_VERSION_MAJOR 0)
set (DP5_VERSION_MINOR 01)

set (CMAKE_CXX_FLAGS "-g -O0 -Wall -Werror -Wno-deprecated-declarations -Wno-non-template-friend -fPIC")
set (CMAKE_C_FLAGS "-g -O0 -Wall -Werror -Wno-deprecated-declarations -fPIC")

include(ExternalProject)
ExternalProject_Add(
    Relic
    LIST_SEPARATOR @@
    URL http://relic-toolkit.googlecode.com/files/relic-0.3.5.tar.gz
    CMAKE_ARGS -DWITH=ALL -DCHECK=off -DARITH=gmp -DFP_PRIME=254 -DFP_QNRES=on
    -DFP_METHD=BASIC@@COMBA@@COMBA@@MONTY@@LOWER@@SLIDE DFP_QNRES=on
    -DPC_METHD=PRIME -DPP_METHD=INTEG@@INTEG@@LAZYR@@OATEP
    "-DCOMP=-O2 -funroll-loops -fomit-frame-pointer -fPIC"
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>)
ExternalProject_Get_Property(Relic INSTALL_DIR)
include_directories(${INSTALL_DIR}/include)
set (RELIC_LIBRARIES ${INSTALL_DIR}/lib/librelic_s.a)

set (PERCYDIR ${CMAKE_CURRENT_SOURCE_DIR}/../percy)

find_library(NTL ntl)
find_file(NTL_INCLUDE_DIR "NTL/")

set (PERCYDIR ${CMAKE_CURRENT_SOURCE_DIR}/../percy)
find_library(PERCYSERVER NAMES percyserver PATHS ${PERCYDIR})
find_library(PERCYCLIENT NAMES percyclient PATHS ${PERCYDIR})
find_file(PERCYH NAMES percyclient.h PATHS ${PERCYDIR})
string(REGEX REPLACE "[^/]+$" "" PERCYINCLUDE ${PERCYH})

# NTL might be compiled with GMP, so link with it just in case
find_library(GMP gmp)
set(PERCY_LIBRARIES ${PERCYSERVER} ${PERCYCLIENT} ${NTL})
if(GMP)
    set(PERCY_LIBRARIES ${PERCY_LIBRARIES} ${GMP})
    set(RELIC_LIBRARIES ${RELIC_LIBRARIES} ${GMP})
endif(GMP)

include_directories(${PERCYINCLUDE})
include_directories(${NTL_INCLUDE_DIR})
get_filename_component(NTL_PARENT_DIR ${NTL_INCLUDE_DIR} PATH)
include_directories(${NTL_PARENT_DIR})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(relicwrapper)

include_directories(${DP5_SOURCE_DIR}/relicwrapper)

add_library (dp5 curve25519-donna.c dp5lookupclient.cpp dp5lookupserver.cpp
    dp5params.cpp dp5metadata.cpp dp5combregclient.cpp dp5regclient.cpp dp5regserver.cpp)

# Separate this library for building tests to avoid
# rebuilding it every time
add_library(curve25519-donna curve25519-donna.c)

get_directory_property(INCLUDES INCLUDE_DIRECTORIES)
get_directory_property(LIBRARIES LIBRARY_DIRECTORIES)

find_program(PYTHON python)
if(PYTHON)
    configure_file(${PROJECT_SOURCE_DIR}/setup.py.in ${PROJECT_BINARY_DIR}/setup.py)

    set(PYTHONCMD ${PYTHON} setup.py install --install-platlib=${PROJECT_BINARY_DIR})
    if(CMAKE_HOST_APPLE)
        set(PYTHONCMD env "ARCHFLAGS=-arch x86_64" ${PYTHONCMD})
    endif(CMAKE_HOST_APPLE)
    add_custom_command(OUTPUT dp5.so
                           COMMAND ${PYTHONCMD}
                           DEPENDS dp5 ${PROJECT_BINARY_DIR}/setup.py relicwrapper)
    add_custom_target(python ALL DEPENDS dp5.so)
endif(PYTHON)

# Ian-style test: compile sources with -DTEST_FOO
# Extra libraries to link can follow as additional unnamed arguments
macro(testdef TARGET SOURCES)
	string(TOUPPER ${TARGET} TARGET_UPPER)
	add_executable(${TARGET} ${SOURCES})
	set_target_properties(${TARGET} PROPERTIES
        COMPILE_DEFINITIONS ${TARGET_UPPER})
	target_link_libraries(${TARGET} ${OPENSSL_LIBRARIES}
        curve25519-donna relicwrapper ${RELIC_LIBRARIES} ${ARGN})
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

testdef(test_rsconst "dp5regserver.cpp;dp5params.cpp;dp5metadata.cpp")

testdef(test_rsreg "dp5regserver.cpp;dp5params.cpp;dp5metadata.cpp" pthread)

testdef(test_client "dp5regclient.cpp;dp5params.cpp" pthread)
set_tests_properties (test_client PROPERTIES FAIL_REGULAR_EXPRESSION "False")

testdef(test_lscd "dp5lookupserver.cpp;dp5params.cpp;dp5metadata.cpp" ${PERCY_LIBRARIES})
testdef(test_reqcd "dp5lookupclient.cpp;dp5params.cpp;dp5metadata.cpp" ${PERCY_LIBRARIES})
testdef(test_pirglue "dp5lookupserver.cpp;dp5lookupclient.cpp;dp5params.cpp;dp5metadata.cpp" ${PERCY_LIBRARIES})
testdef(test_pirgluemt "dp5lookupserver.cpp;dp5lookupclient.cpp;dp5params.cpp;dp5metadata.cpp" ${PERCY_LIBRARIES} pthread)

add_executable(test_integrate dp5integrationtest.cpp)
target_link_libraries(test_integrate dp5 curve25519-donna ${OPENSSL_LIBRARIES} ${PERCY_LIBRARIES}
    relicwrapper ${RELIC_LIBRARIES})
# Don't add it as a test because it takes a long time
#add_test(IntegrationTest test_integrate)
