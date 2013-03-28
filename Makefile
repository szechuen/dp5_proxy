CC = gcc
CXX = g++
CXXFLAGS = -O0 -g -Wall -Werror
CFLAGS = -O0 -g -Wall -Werror
LDLIBS = -lcrypto

BINS =
TESTS = test_dh test_hashes

all: $(BINS) $(TESTS)

test_dh: test_dh.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_hashes: test_hashes.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_dh.o: dp5params.cpp
	g++ $(CXXFLAGS) -DTEST_DH -c $^ -o $@

test_hashes.o: dp5params.cpp
	g++ $(CXXFLAGS) -DTEST_HASHES -c $^ -o $@
