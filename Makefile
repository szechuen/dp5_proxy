PERCYINC = ../percy
NTLINC = /usr/local/include/NTL
CC = gcc
CXX = g++
CXXFLAGS = -O0 -g -Wall -Werror -Wno-deprecated-declarations
CFLAGS = -O0 -g -Wall -Werror -Wno-deprecated-declarations
LDLIBS = -lcrypto

BINS =
TESTS = test_dh test_hashes test_prf test_enc test_epoch \
	test_rsconst test_rsreg test_client

all: $(BINS) $(TESTS)

test_dh: test_dh.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_hashes: test_hashes.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_prf: test_prf.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_enc: test_enc.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_epoch: test_epoch.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_rsconst: test_rsconst.o dp5params.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_rsreg: test_rsreg.o dp5params.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS) -lpthread

test_client: test_client.o dp5params.o curve25519-donna.o
	g++ $^ -o $@ $(LDFLAGS) $(LDLIBS) -lpthread

test_dh.o: dp5params.cpp dp5params.h
	g++ $(CXXFLAGS) -DTEST_DH -c $< -o $@

test_hashes.o: dp5params.cpp dp5params.h
	g++ $(CXXFLAGS) -DTEST_HASHES -c $< -o $@

test_prf.o: dp5params.cpp dp5params.h
	g++ $(CXXFLAGS) -DTEST_PRF -c $< -o $@

test_enc.o: dp5params.cpp dp5params.h
	g++ $(CXXFLAGS) -DTEST_ENC -c $< -o $@

test_epoch.o: dp5params.cpp dp5params.h
	g++ $(CXXFLAGS) -DTEST_EPOCH -c $< -o $@

test_rsconst.o: dp5regserver.cpp dp5regserver.h dp5params.h
	g++ $(CXXFLAGS) -DTEST_RSCONST -c $< -o $@

test_rsreg.o: dp5regserver.cpp dp5regserver.h dp5params.h
	g++ $(CXXFLAGS) -DTEST_RSREG -c $< -o $@

test_client.o: dp5regclient.cpp dp5regclient.h dp5params.h
	g++ $(CXXFLAGS) -DTEST_CLIENT -c $< -o $@

dp5lookupclient.o: dp5lookupclient.cpp dp5lookupclient.h dp5params.h
	g++ $(CXXFLAGS) -I$(PERCYINC) -I$(NTLINC) -c $< -o $@

clean:
	-rm -f *.o
