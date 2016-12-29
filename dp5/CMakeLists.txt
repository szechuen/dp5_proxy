cmake_minimum_required (VERSION 2.8)

project (DP5)

set (DP5_VERSION_MAJOR 0)
set (DP5_VERSION_MINOR 01)

set (CMAKE_CXX_FLAGS "-g -O0 -Wall  -Werror -Wno-deprecated-declarations -Wno-non-template-friend -Wno-unknown-warning-option -fPIC")
set (CMAKE_C_FLAGS "-g -O0 -Wall -Werror -Wno-deprecated-declarations -fPIC")

find_library(GMP gmp)
if(GMP)
    set(RELIC_ARITH "-DARITH=gmp")
else(GMP)
    set(RELIC_ARITH "-DARITH=easy")
endif(GMP)

find_library(PTHREAD pthread)

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES i.86)
  if(${CMAKE_SIZEOF_VOID_P} EQUAL 4)
    set(RELIC_ARCH -DARCH=X86 -DWORD=32)
  endif(${CMAKE_SIZEOF_VOID_P} EQUAL 4)
endif(${CMAKE_SYSTEM_PROCESSOR} MATCHES i.86)

include(ExternalProject)
ExternalProject_Add(
    Relic
    LIST_SEPARATOR @@
    URL https://github.com/relic-toolkit/relic/archive/relic-toolkit-0.3.5.tar.gz
    URL_MD5 25e19bf4323e52d5485e88c14ef2c443
    CMAKE_ARGS -DWITH=ALL -DCHECK=off ${RELIC_ARITH} ${RELIC_ARCH} -DFP_PRIME=254 -DFP_QNRES=on
    -DFP_METHD=BASIC@@COMBA@@COMBA@@MONTY@@LOWER@@SLIDE DFP_QNRES=on
    -DPC_METHD=PRIME -DPP_METHD=INTEG@@INTEG@@LAZYR@@OATEP
    -DSEED=UDEV "-DCOMP=-O2 -funroll-loops -fomit-frame-pointer -fPIC"
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>)
ExternalProject_Get_Property(Relic INSTALL_DIR)
set(RELIC_INCLUDE ${INSTALL_DIR}/include)
include_directories(${RELIC_INCLUDE})
set (RELIC_LIBRARIES ${INSTALL_DIR}/lib/librelic_s.a)

ExternalProject_Add(
    googletest
    URL https://github.com/google/googletest/archive/release-1.7.0.zip
    URL_MD5 ef5e700c8a0f3ee123e2e0209b8b4961
    INSTALL_COMMAND "")
ExternalProject_Get_Property(googletest source_dir)
set(GTEST_INCLUDE_DIRS ${source_dir}/include)
ExternalProject_Get_Property(googletest binary_dir)
set(GTEST_LIBS_DIR ${binary_dir})
set(GTEST_LIBRARIES ${GTEST_LIBS_DIR}/libgtest.a ${GTEST_LIBS_DIR}/libgtest_main.a)

ExternalProject_Add(
    Percy++
    URL http://downloads.sourceforge.net/percy/percy++-1.0.0.tar.gz
    URL_MD5 1cb88ba5b0288dfa601fb0f6bc899c2b
    CMAKE_ARGS "-DCMAKE_CXX_FLAGS=-g -O2 -fPIC"
    PATCH_COMMAND patch -t -N < ${CMAKE_CURRENT_SOURCE_DIR}/percy.patch || true
    INSTALL_COMMAND "")
ExternalProject_Get_Property(Percy++ source_dir)
include_directories(${source_dir})
ExternalProject_Get_Property(Percy++ binary_dir)
set(PERCYSERVER ${binary_dir}/libpercyserver.a)
set(PERCYCLIENT ${binary_dir}/libpercyclient.a)

find_library(NTL ntl)
find_file(NTL_INCLUDE_DIR "NTL/" "/usr/local/include/")

set(PERCY_LIBRARIES ${PERCYSERVER} ${PERCYCLIENT} ${NTL} ${PTHREAD})
if(GMP)
# NTL might be compiled with GMP, so link with it just in case
    set(PERCY_LIBRARIES ${PERCY_LIBRARIES} ${GMP})
    set(RELIC_LIBRARIES ${RELIC_LIBRARIES} ${GMP})
endif(GMP)

include_directories(${NTL_INCLUDE_DIR})
get_filename_component(NTL_PARENT_DIR ${NTL_INCLUDE_DIR} PATH)
include_directories(${NTL_PARENT_DIR})

find_package(OpenSSL REQUIRED)
if(${OPENSSL_VERSION} VERSION_LESS "1.0.1")
    message("Need OpenSSL 1.0.1 or later to use GCM mode encryption (found ${OPENSSL_VERSION})")
endif(${OPENSSL_VERSION} VERSION_LESS "1.0.1")
include_directories(${OPENSSL_INCLUDE_DIR})

ExternalProject_Add(
    RelicWrapper
    DEPENDS Relic
    URL https://crysp.uwaterloo.ca/software/relicwrapper-0.9.tar.gz
    URL_MD5 19146857d7302734c3662ef9c2ca1838
    CMAKE_ARGS "-DCMAKE_CXX_FLAGS=-g -O2 -fPIC" "-DRELIC_INCLUDE:STRING=${RELIC_INCLUDE}"
    PATCH_COMMAND patch -t -N <
    ${CMAKE_CURRENT_SOURCE_DIR}/relicwrapper.patch
    INSTALL_COMMAND "")
ExternalProject_Get_Property(RelicWrapper source_dir)
include_directories(${source_dir})
ExternalProject_Get_Property(RelicWrapper binary_dir)
set(RELICWRAPPER_LIBRARY ${binary_dir}/librelicwrapper.a)

add_library (dp5 curve25519-donna.c dp5lookupclient.cpp dp5lookupserver.cpp
    dp5params.cpp dp5metadata.cpp dp5combregclient.cpp dp5regclient.cpp dp5regserver.cpp)

add_dependencies(dp5 RelicWrapper)

# Build a pure C shared-library to call with Python CFFI wrapper
add_library(dp5clib SHARED dp5clib.cpp curve25519-donna.c dp5lookupclient.cpp dp5lookupserver.cpp
    dp5params.cpp dp5metadata.cpp dp5combregclient.cpp dp5regclient.cpp dp5regserver.cpp)
add_dependencies(dp5clib RelicWrapper)
target_link_libraries(dp5clib ${OPENSSL_LIBRARIES} ${PERCY_LIBRARIES}
        ${RELICWRAPPER_LIBRARY} ${RELIC_LIBRARIES})
set_source_files_properties(dp5clib.cpp PROPERTIES COMPILE_FLAGS "-Wno-error")

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
      set(PYTHONCMD env "ARCHFLAGS=-arch x86_64 -Wno-unused-command-line-argument-hard-error-in-future" ${PYTHONCMD})
    endif(CMAKE_HOST_APPLE)
    add_custom_command(OUTPUT dp5.so
                           COMMAND ${PYTHONCMD}
                           DEPENDS Percy++ dp5py.cpp dp5 ${PROJECT_BINARY_DIR}/setup.py ${RELICWRAPPER_LIBRARY})
    add_custom_target(python ALL DEPENDS dp5.so)
endif(PYTHON)

# Ian-style test: compile sources with -DTEST_FOO
# Extra libraries to link can follow as additional unnamed arguments
macro(testdef TARGET SOURCES)
	string(TOUPPER ${TARGET} TARGET_UPPER)
	add_executable(${TARGET} ${SOURCES})
	add_dependencies(${TARGET} RelicWrapper)
	set_target_properties(${TARGET} PROPERTIES
        COMPILE_DEFINITIONS ${TARGET_UPPER})
	target_link_libraries(${TARGET} ${OPENSSL_LIBRARIES}
        curve25519-donna ${RELICWRAPPER_LIBRARY} ${RELIC_LIBRARIES} ${ARGN})
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

testdef(test_rsreg "dp5regserver.cpp;dp5params.cpp;dp5metadata.cpp" ${PTHREAD})

testdef(test_client "dp5regclient.cpp;dp5params.cpp" ${PTHREAD})
set_tests_properties (test_client PROPERTIES FAIL_REGULAR_EXPRESSION "False")

testdef(test_lscd "dp5lookupserver.cpp;dp5params.cpp;dp5metadata.cpp" ${PERCY_LIBRARIES})
testdef(test_reqcd "dp5lookupclient.cpp;dp5params.cpp;dp5metadata.cpp" ${PERCY_LIBRARIES})
testdef(test_pirglue "dp5lookupserver.cpp;dp5lookupclient.cpp;dp5params.cpp;dp5metadata.cpp" ${PERCY_LIBRARIES})
testdef(test_pirmultic "dp5lookupserver.cpp;dp5lookupclient.cpp;dp5params.cpp;dp5metadata.cpp" ${PERCY_LIBRARIES})
testdef(test_pirgluemt "dp5lookupserver.cpp;dp5lookupclient.cpp;dp5params.cpp;dp5metadata.cpp" ${PERCY_LIBRARIES} ${PTHREAD} )

add_executable(test_integrate dp5integrationtest.cpp)
target_link_libraries(test_integrate dp5 curve25519-donna ${OPENSSL_LIBRARIES} ${PERCY_LIBRARIES}
    ${RELICWRAPPER_LIBRARY} ${RELIC_LIBRARIES})
# Note that this doesn't exercise PIR, but at least it runs quickly
add_test(IntegrationTest test_integrate 25)
set_tests_properties(IntegrationTest PROPERTIES FAIL_REGULAR_EXPRESSION "False")

include_directories(${GTEST_INCLUDE_DIRS})

macro(gtest TARGET SOURCES)
    add_executable(${TARGET} ${SOURCES})
    add_dependencies(${TARGET} googletest RelicWrapper Percy++)
    target_link_libraries(${TARGET} ${OPENSSL_LIBRARIES}
     ${PERCY_LIBRARIES} ${RELICWRAPPER_LIBRARY} ${RELIC_LIBRARIES} curve25519-donna ${GTEST_LIBRARIES} ${ARGN} pthread)
    add_test(${TARGET} ${TARGET})
endmacro(gtest)

gtest(bytearray_unittest bytearray_unittest.cpp)
gtest(dp5metadata_unittest "dp5metadata_unittest.cpp;dp5metadata.cpp;dp5params.cpp")
gtest(dp5combregclient_unittest "dp5combregclient_unittest.cpp;dp5combregclient.cpp;dp5params.cpp")
gtest(dp5lookupclient_unittest "dp5lookupclient_unittest.cpp;dp5lookupclient.cpp;dp5params.cpp;dp5metadata.cpp")
gtest(pairing_unittest "pairing_unittest.cpp;dp5params.cpp")
gtest(enc_test "enc_test.cpp;dp5params.cpp")
gtest(dp5lookupserver_unittest "dp5lookupserver_unittest.cpp;dp5lookupserver.cpp;dp5params.cpp;dp5metadata.cpp")
