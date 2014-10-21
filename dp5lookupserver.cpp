#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <stdexcept>
#include <sstream>
#include <fstream>

#include "dp5lookupserver.h"

using namespace std;

namespace dp5 {

using namespace dp5::internal;

// The constructor consumes the current epoch number, and the
// filenames of the current metadata and data files.
DP5LookupServer::DP5LookupServer(const char *metadatafilename, const char *datafilename)
{
    init(metadatafilename, datafilename);
}

// Initialize the private members from the epoch and the filenames
void DP5LookupServer::init(const char *metadatafilename,
    const char *datafilename)
{
    _metadatafilename = strdup(metadatafilename);
    _datafilename = strdup(datafilename);

    ifstream metadatafile(metadatafilename);
    if (!metadatafile) {
        throw runtime_error("Cannot open metadata file");
    }
    if (_metadata.fromStream(metadatafile) != 0) {
        throw runtime_error("Cannot parse metadata file");
    }

    if (_metadata.num_buckets > 0 && _metadata.bucket_size > 0) {
	_pirparams = new GF2EParams(
            _metadata.num_buckets,
    	    _metadata.bucket_size * (HASHKEY_BYTES + _metadata.dataenc_bytes),
	    8, false);
        _pirserverparams = new PercyServerParams(_pirparams, 0,
		// The first number on the next line is the number of
		// threads to use.  It should probably be a parameter.
		32, DIST_SPLIT_QUERIES);

        _datastore = new FileDataStore(_datafilename, _pirserverparams);

        _pirserver = PercyServer::make_server(_datastore, _pirserverparams);
    } else {
	_pirparams = NULL;
	_pirserverparams = NULL;
        _pirserver = NULL;
        _datastore = NULL;
    }
}

// Copy constructor
DP5LookupServer::DP5LookupServer(const DP5LookupServer &other)
{
    init(other._metadatafilename, other._datafilename);
}

// Assignment operator
DP5LookupServer& DP5LookupServer::operator=(DP5LookupServer other)
{
    // Swap the fields of the temporary "other" with ours so things get
    // properly freed
    char *tmp = other._metadatafilename;
    other._metadatafilename = _metadatafilename;
    _metadatafilename = tmp;

    tmp = other._datafilename;
    other._datafilename = _datafilename;
    _datafilename = tmp;

    GF2EParams *tmpp = other._pirparams;
    other._pirparams = _pirparams;
    _pirparams = tmpp;

    PercyServerParams *tmppsp = other._pirserverparams;
    other._pirserverparams = _pirserverparams;
    _pirserverparams = tmppsp;

    FileDataStore *tmpfds = other._datastore;
    other._datastore = _datastore;
    _datastore = tmpfds;

    PercyServer *tmpps = other._pirserver;
    other._pirserver = _pirserver;
    _pirserver = tmpps;

    // copy metadata
    _metadata = other._metadata;

    return *this;
}

// Destructor
DP5LookupServer::~DP5LookupServer()
{
    if (_pirserver) {
        delete _pirserver;
        delete _datastore;
        delete _pirserverparams;
        delete _pirparams;
    }

    free(_datafilename);
    free(_metadatafilename);
}

// The glue API to the PIR layer (single-client version).  Pass a
// request string as produced by pir_query.  reponse is filled in with
// the reponse; pass it to pir_response.  Return 0 on success, non-0 on
// failure.
int DP5LookupServer::pir_process(string &response, const string &request)
{
    if (!_pirserver || !_pirparams || !_pirserverparams) {
	return -1;
    }

    stringstream ins(request);
    stringstream outs;

    bool ret = _pirserver->handle_request(ins, outs);

    if (!ret) {
	return -1;
    }

    response = outs.str();

    return 0;
}

// The glue API to the PIR layer (multi-client version).  Pass a vector
// of request strings, each as produced by pir_query.  reponse is filled
// in with the vector of reponses; pass each to pir_response.  Return 0
// on success, non-0 on failure.
int DP5LookupServer::pir_process(vector<string> &responses,
	const vector<string>&requests)
{
    if (!_pirserver || !_pirparams || !_pirserverparams) {
	return -1;
    }

    size_t num_clients = requests.size();
    vector<istream *> insv;
    vector<ostream *> outsv;

    for (size_t c=0; c<num_clients; ++c) {
	insv.push_back(new stringstream(requests[c]));
	outsv.push_back(new stringstream);
    }

    bool ret = _pirserver->handle_request(insv, outsv);

    if (!ret) {
	goto clean;
    }

    for (size_t c=0; c<num_clients; ++c) {
	stringstream *ss = (stringstream *)(outsv[c]);
	responses.push_back(ss->str());
    }

clean:
    for (size_t c=0; c<num_clients; ++c) {
	delete insv[c];
	delete outsv[c];
    }
    return ret ? 0 : -1;
}

// Process a received request from a lookup client.  This may be either
// a metadata or a data request.  Set reply to the reply to return to
// the client.
void DP5LookupServer::process_request(string &reply, const string &request)
{
    size_t reqlen = request.length();
    const unsigned char *reqdata = (const unsigned char *)request.data();

    // Check for a well-formed command
    if (reqlen < 5 ||
	    (reqdata[0] != 0xff && reqdata[0] != 0xfe && reqdata[0] != 0xfd)
	    || epoch_bytes_to_num(reqdata+1) != _metadata.epoch) {
	unsigned char errmsg[5];
	if (reqlen > 0 && reqdata[0] == 0xfe) {
	    errmsg[0] = 0x80;
	} else if (reqlen > 0 && reqdata[1] == 0xfd) {
	    errmsg[0] = 0x80;
	} else {
	    errmsg[0] = 0x00;
	}
	epoch_num_to_bytes(errmsg+1, _metadata.epoch);
	reply.assign((char *) errmsg, 5);
	return;
    }

    // At this point, we have a well-formed 5-byte command header with
    // the correct epoch in it.
    if (reqdata[0] == 0xff) {
        reply = _metadata.toString();
    	return;
    }

    if (reqdata[0] == 0xfe) {
	// PIR query
	string pirquery((const char *)reqdata+5, reqlen-5);
	string pirresp;
	int ret = pir_process(pirresp, pirquery);
	if (ret) {
	    // Error occurred
	    unsigned char errmsg[5];
	    errmsg[0] = 0x80;
	    epoch_num_to_bytes(errmsg+1, _metadata.epoch);
	    reply.assign((char *) errmsg, 5);
	    return;
	}
	unsigned char repmsg[5];
	repmsg[0] = 0x81;
	epoch_num_to_bytes(repmsg+1, _metadata.epoch);
	reply.assign((char *) repmsg, 5);
	reply.append(pirresp);
	return;
    }

    if (reqdata[0] == 0xfd) {
	// Request for the whole data file
	unsigned char repmsg[5];
	repmsg[0] = 0x82;
	epoch_num_to_bytes(repmsg+1, _metadata.epoch);
	reply.assign((char *) repmsg, 5);
    if (_datastore) {
    	reply.append((const char *)(_datastore->get_data()),
    	    _metadata.num_buckets * _metadata.bucket_size *
    	    (HASHKEY_BYTES + _metadata.dataenc_bytes));
    }
	return;
    }

    // It should not be possible to get here
    throw runtime_error("Unhandled request");
}

} // namespace dp5
#ifdef TEST_LSCD

// Test the constructor, copy constructor, assignment operator,
// destructor
using namespace dp5;
void test_lscd()
{
    DP5LookupServer a("metadata.out", "data.out");
    DP5LookupServer b;
    b = a;
    DP5LookupServer c(b);
    DP5LookupServer d = c;
    DP5LookupServer e;
    e = d;
}

int main()
{
    ZZ_p::init(to_ZZ(256));

    test_lscd();

    // Ensure we've closed all of the file descriptors
    char cmd[100];
    sprintf(cmd, "ls -l /proc/%d/fd", getpid());
    system(cmd);

    return 0;
}

#endif // TEST_LSCD

#ifdef TEST_PIRGLUE

#include "dp5lookupclient.h"

// Test the PIR API glue

// Run as: ./test_pirglue | hexdump -e '10/1 "%02x" " " 1/16 "%s" "\n"'

namespace dp5 {
    using namespace dp5::internal;
void test_pirglue(int num_blocks_to_fetch)
{
    unsigned int num_servers = 5;

    // Create the right number of lookup servers
    DP5LookupServer *servers = new DP5LookupServer[num_servers];

    // Initialize them.  NOTE: You must have run test_rsreg prior to
    // this to create the metadata.out and data.out files.
    for(unsigned int s=0; s<num_servers; ++s) {
    	servers[s].init("metadata.out", "data.out");
    }

    PIRRequest req;
    req.init(num_servers, 2, servers[0].getMetadata(),
        servers[0].getConfig().dataenc_bytes + HASHKEY_BYTES);

    unsigned int numbuckets = servers[0].getMetadata().num_buckets;

    vector<unsigned int> bucketnums;
    cerr << "Fetching bucket numbers";
    for (int i=0; i<num_blocks_to_fetch; ++i) {
	unsigned int b = lrand48()%numbuckets;
	cerr << " " << b;
	bucketnums.push_back(b);
    }
    cerr << "\n";

    vector<string> requests;

    int res = req.pir_query(requests, bucketnums);
    if (res) {
    	throw runtime_error("Calling pir_query");
    }

    vector<string> responses;
    for(unsigned int s=0; s<num_servers; ++s) {
	string resp;
	cerr << "Query " << s+1 << " has length " <<
		requests[s].length() << "\n";
	res = servers[s].pir_process(resp, requests[s]);
	if (res) {
	    throw runtime_error("Calling pir_process");
	}
	cerr << "Reply " << s+1 << " has length " <<
		resp.length() << "\n";
	responses.push_back(resp);
    }

    vector<string> buckets;

    res = req.pir_response(buckets, responses);
    if (res) {
	throw runtime_error("Calling pir_response");
    }

    size_t num_blocks = buckets.size();
    cerr << num_blocks << " blocks retrieved\n";
    for (size_t b=0; b<num_blocks; ++b) {
	cout << buckets[b];
    }

    delete[] servers;
}
}

int main(int argc, char **argv)
{
    int num_blocks_to_fetch = argc > 1 ? atoi(argv[1]) : 3;

    ZZ_p::init(to_ZZ(256));
    dp5::test_pirglue(num_blocks_to_fetch);

    return 0;
}

#endif // TEST_PIRGLUE

#ifdef TEST_PIRGLUEMT
// Test the multi-threadedness of the PIR API glue

#include "dp5lookupclient.h"

namespace dp5 {
DP5LookupServer *server = NULL;
void* test_pirgluemt_single(void *d)
{
    pair<string,string> *p = (pair<string,string> *)d;
    string r;
    server->pir_process(r, p->first);
    if (r != p->second) {
	cerr << "Answers differ!\n";
    }
    return NULL;
}

void test_pirgluemt()
{
    unsigned int numthreads = 100;
    unsigned int qperthread = 3;
    bool multithread = true;

    // Use a single server.  NOTE: You must have run test_rsreg prior to
    // this to create the metadata.out and data.out files.
    server = new DP5LookupServer("metadata.out", "data.out");

    PRF prf((const unsigned char*) server->_metadata.prfkey,
        server->_metadata.num_buckets);

    // A vector of question/answer pairs
    vector< pair<string,string> > qas;

    unsigned char hashkey[HASHKEY_BYTES];
    memset(hashkey, '\0', HASHKEY_BYTES);
    unsigned int iter = 0;

    PIRRequest req;
    req.init(5, 2, server->_metadata, HASHKEY_BYTES +
        server->_metadata.dataenc_bytes);

    for (unsigned int i=0; i<numthreads; ++i) {
	// Generate a random question
	vector<unsigned int> buckets;
	cerr << "Requesting";
	for (unsigned int j=0; j<qperthread; ++j) {
	    ++iter;
	    memmove(hashkey, &iter, sizeof(iter));
	    unsigned int b = prf.M(hashkey);
	    buckets.push_back(b);
	    cerr << " " << b;
	    vector<string> requests;
	    string reply;
	    req.pir_query(requests, buckets);
	    server->pir_process(reply, requests[0]);
	    qas.push_back(pair<string,string>(requests[0], reply));
	}
	cerr << "\n";
    }

    // Now see if we get the same answers in a multithreaded setting
    vector<pthread_t> children;

    for (unsigned int i=0; i<numthreads; ++i) {
	if (multithread) {
	    pthread_t thr;
	    pthread_create(&thr, NULL, test_pirgluemt_single, &(qas[i]));
	    children.push_back(thr);
	} else {
	    test_pirgluemt_single(&(qas[i]));
	}
    }

    size_t numchildren = children.size();
    for (unsigned int i=0; i<numchildren; ++i) {
	pthread_join(children[i], NULL);
    }

    delete server;
}
}
int main()
{
    ZZ_p::init(to_ZZ(256));
    dp5::test_pirgluemt();

    return 0;
}

#endif // TEST_PIRGLUEMT
