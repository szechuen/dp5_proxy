PERCYINC = ../percy
PERCYLIB = ../percy
NTLINC = /usr/local/include/NTL
NTLLIB = /usr/local/lib
CC = gcc
CXX = g++
CXXFLAGS = -O0 -g -Wall -Werror -Wno-deprecated-declarations
CFLAGS = -O0 -g -Wall -Werror -Wno-deprecated-declarations
LDLIBS = -lcrypto

BINS =
TESTS = test_dh test_hashes test_prf test_enc test_epoch \
	test_rsconst test_rsreg test_client test_reqcd \
	test_lscd test_pirglue test_pirgluemt test_integrate

all: $(BINS) $(TESTS)

test_dh: test_dh.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_hashes: test_hashes.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_prf: test_prf.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_enc: test_enc.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_epoch: test_epoch.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_rsconst: test_rsconst.o dp5params.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS)

test_rsreg: test_rsreg.o dp5params.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS) -lpthread

test_client: test_client.o dp5params.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS) -lpthread

test_reqcd: test_reqcd.o dp5params.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS) -L$(PERCYLIB) -lpercyclient -L$(NTLLIB) -lntl -lgmp

test_lscd: test_lscd.o dp5params.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS) -L$(PERCYLIB) -lpercyserver -L$(NTLLIB) -lntl -lgmp

test_pirglue: test_pirglue.o dp5lookupclient.o dp5params.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS) -L$(PERCYLIB) -lpercyclient -lpercyserver -L$(NTLLIB) -lntl -lgmp

test_pirgluemt: test_pirgluemt.o dp5lookupclient.o dp5params.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS) -L$(PERCYLIB) -lpercyclient -lpercyserver -L$(NTLLIB) -lntl -lgmp -lpthread

test_integrate: test_integrate.o dp5regserver.o dp5regclient.o dp5params.o curve25519-donna.o
	g++ -g $^ -o $@ $(LDFLAGS) $(LDLIBS) -L$(PERCYLIB) -lpercyclient -lpercyserver -L$(NTLLIB) -lntl -lgmp

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

test_reqcd.o: dp5lookupclient.cpp dp5lookupclient.h dp5params.h
	g++ $(CXXFLAGS) -DTEST_REQCD -I$(PERCYINC) -I$(NTLINC) -c $< -o $@

test_lscd.o: dp5lookupserver.cpp dp5lookupserver.h dp5params.h
	g++ $(CXXFLAGS) -DTEST_LSCD -I$(PERCYINC) -I$(NTLINC) -c $< -o $@

test_pirglue.o: dp5lookupserver.cpp dp5lookupserver.h dp5params.h
	g++ $(CXXFLAGS) -DTEST_PIRGLUE -I$(PERCYINC) -I$(NTLINC) -c $< -o $@

test_pirgluemt.o: dp5lookupserver.cpp dp5lookupserver.h dp5params.h
	g++ $(CXXFLAGS) -DTEST_PIRGLUEMT -I$(PERCYINC) -I$(NTLINC) -c $< -o $@

dp5regserver.o: dp5regserver.cpp dp5regserver.h dp5params.h
	g++ $(CXXFLAGS) -c $< -o $@

dp5regclient.o: dp5regclient.cpp dp5regclient.h dp5params.h
	g++ $(CXXFLAGS) -c $< -o $@

dp5lookupclient.o: dp5lookupclient.cpp dp5lookupclient.h dp5params.h
	g++ $(CXXFLAGS) -I$(PERCYINC) -I$(NTLINC) -c $< -o $@

dp5lookupserver.o: dp5lookupserver.cpp dp5lookupserver.h dp5params.h
	g++ $(CXXFLAGS) -I$(PERCYINC) -I$(NTLINC) -c $< -o $@

test_integrate.o: dp5integrationtest.cpp dp5regserver.h dp5regclient.h dp5params.h
	g++ $(CXXFLAGS) -I$(PERCYINC) -I$(NTLINC) -c $< -o $@

clean:
	-rm -f *.o
