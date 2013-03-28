CC = gcc
CXX = g++
CXXFLAGS = -O0 -g -Wall -Werror
CFLAGS = -O0 -g -Wall -Werror
LDLIBS = -lcrypto

BINS =
TESTS = test_dh

all: $(BINS) $(TESTS)

test_dh: test_dh.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_dh.o: dp5params.cpp
	g++ $(CXXFLAGS) -DTEST_DH -c $^ -o $@
