CC = gcc
CXX = g++
CXXFLAGS = -O0 -g -Wall -Werror
CFLAGS = -O0 -g -Wall -Werror
LDLIBS = -lcrypto

BINS =
TESTS = test_dh test_hashes test_prf test_enc

all: $(BINS) $(TESTS)

test_dh: test_dh.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_hashes: test_hashes.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_prf: test_prf.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_enc: test_enc.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_dh.o: dp5params.cpp
	g++ $(CXXFLAGS) -DTEST_DH -c $^ -o $@

test_hashes.o: dp5params.cpp
	g++ $(CXXFLAGS) -DTEST_HASHES -c $^ -o $@

test_prf.o: dp5params.cpp
	g++ $(CXXFLAGS) -DTEST_PRF -c $^ -o $@

test_enc.o: dp5params.cpp
	g++ $(CXXFLAGS) -DTEST_ENC -c $^ -o $@
