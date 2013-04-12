#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include <stdexcept>
#include <sstream>

#include "dp5lookupserver.h"

// The constructor consumes the current epoch number, and the
// filenames of the current metadata and data files.
DP5LookupServer::DP5LookupServer(unsigned int epoch,
    const char *metadatafilename, const char *datafilename)
{
    init(epoch, metadatafilename, datafilename);
}

// Initialize the private members from the epoch and the filenames
void DP5LookupServer::init(unsigned int epoch, const char *metadatafilename,
    const char *datafilename)
{
    _epoch = epoch;
    _metadatafilename = strdup(metadatafilename);
    _datafilename = strdup(datafilename);

    // Open the metadata file
    _metadatafd = open(_metadatafilename, O_RDONLY);
    if (_metadatafd < 0) {
	perror("open metadata file");
	throw runtime_error("Cannot open metadata file");
    }

    // mmap it
    _metadatafilecontents = (unsigned char *)mmap(NULL,
	    PRFKEY_BYTES + UINT_BYTES + UINT_BYTES, PROT_READ, MAP_PRIVATE,
	    _metadatafd, 0);
    if (!_metadatafilecontents) {
	perror("mmap metadata file");
	throw runtime_error("Cannot mmap metadata file");
    }

    unsigned int num_buckets_be = 0;
    unsigned int bucket_size_be = 0;
    memmove(((char *)&num_buckets_be)+sizeof(unsigned int)-UINT_BYTES,
	_metadatafilecontents+PRFKEY_BYTES, UINT_BYTES);
    memmove(((char *)&bucket_size_be)+sizeof(unsigned int)-UINT_BYTES,
	_metadatafilecontents+PRFKEY_BYTES+UINT_BYTES, UINT_BYTES);
    _num_buckets = ntohl(num_buckets_be);
    _bucket_size = ntohl(bucket_size_be);

    _pirserverparams = new PercyServerParams(
	_bucket_size * (HASHKEY_BYTES + DATAENC_BYTES), _num_buckets,
	0, to_ZZ(256), MODE_GF28, false, NULL, false, 0, 0);

    _datastore = new FileDataStore(_datafilename, *_pirserverparams);

    _pirserver = new PercyServer(_datastore);
}

// Copy constructor
DP5LookupServer::DP5LookupServer(const DP5LookupServer &other)
{
    init(other._epoch, other._metadatafilename, other._datafilename);
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

    int tmpfd = other._metadatafd;
    other._metadatafd = _metadatafd;
    _metadatafd = tmpfd;

    unsigned char *tmpuc = other._metadatafilecontents;
    other._metadatafilecontents = _metadatafilecontents;
    _metadatafilecontents = tmpuc;

    PercyServerParams *tmppsp = other._pirserverparams;
    other._pirserverparams = _pirserverparams;
    _pirserverparams = tmppsp;

    FileDataStore *tmpfds = other._datastore;
    other._datastore = _datastore;
    _datastore = tmpfds;

    PercyServer *tmpps = other._pirserver;
    other._pirserver = _pirserver;
    _pirserver = tmpps;

    // These can just be copied
    _epoch = other._epoch;
    _num_buckets = other._num_buckets;
    _bucket_size = other._bucket_size;

    return *this;
}

// Destructor
DP5LookupServer::~DP5LookupServer()
{
    delete _pirserver;
    delete _datastore;
    delete _pirserverparams;

    munmap(_metadatafilecontents, PRFKEY_BYTES + UINT_BYTES + UINT_BYTES);
    if (_metadatafd >= 0) {
	close(_metadatafd);
    }
    free(_datafilename);
    free(_metadatafilename);
}

// The glue API to the PIR layer.  Pass a request string as produced
// by pir_query.  reponse is filled in with the reponse; pass it to
// pir_response.  Return 0 on success, non-0 on failure.
int DP5LookupServer::pir_process(string &response, const string &request)
{
    if (!_pirserver || !_pirserverparams) {
	return -1;
    }

    stringstream ins(request);
    stringstream outs;

    bool ret = _pirserver->handle_request(*_pirserverparams, ins, outs);

    if (!ret) {
	return -1;
    }

    response = outs.str();

    return 0;
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
	    || epoch_bytes_to_num(reqdata+1) != _epoch) {
	unsigned char errmsg[5];
	if (reqlen > 0 && reqdata[0] == 0xfe) {
	    errmsg[0] = 0x80;
	} else if (reqlen > 0 && reqdata[1] == 0xfd) {
	    errmsg[0] = 0x80;
	} else {
	    errmsg[0] = 0x00;
	}
	epoch_num_to_bytes(errmsg+1, _epoch);
	reply.assign((const char *)errmsg, 5);
	return;
    }

    // At this point, we have a well-formed 5-byte command header with
    // the correct epoch in it.
    if (reqdata[0] == 0xff) {
	// Request for the metadata file
	unsigned char repmsg[5];
	repmsg[0] = METADATA_VERSION;
	epoch_num_to_bytes(repmsg+1, _epoch);
	reply.assign((const char *)repmsg, 5);
	reply.append((const char *)_metadatafilecontents,
	    PRFKEY_BYTES + UINT_BYTES + UINT_BYTES);
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
	    epoch_num_to_bytes(errmsg+1, _epoch);
	    reply.assign((const char *)errmsg, 5);
	    return;
	}
	unsigned char repmsg[5];
	repmsg[0] = 0x81;
	epoch_num_to_bytes(repmsg+1, _epoch);
	reply.assign((const char *)repmsg, 5);
	reply.append(pirresp);
	return;
    }

    if (reqdata[0] == 0xfd) {
	// Request for the whole data file
	unsigned char repmsg[5];
	repmsg[0] = 0x82;
	epoch_num_to_bytes(repmsg+1, _epoch);
	reply.assign((const char *)repmsg, 5);
	reply.append((const char *)(_datastore->get_data()),
	    _num_buckets * _bucket_size *
	    (HASHKEY_BYTES + DATAENC_BYTES));
	return;
    }

    // It should not be possible to get here
    throw runtime_error("Unhandled request");
}

#ifdef TEST_LSCD

// Test the constructor, copy constructor, assignment operator,
// destructor
void test_lscd()
{
    DP5Params p;

    DP5LookupServer a(p.current_epoch(), "metadata.out", "data.out");
    DP5LookupServer b;
    b = a;
    DP5LookupServer c(b);
    DP5LookupServer d = c;
    DP5LookupServer e;
    e = d;
}

int main(int argc, char **argv)
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

void test_pirglue()
{
    DP5Params params;

    // The current epoch
    unsigned int epoch = params.current_epoch();

    unsigned int num_servers = params.NUM_PIRSERVERS;

    // Create the right number of lookup servers
    DP5LookupServer *servers = new DP5LookupServer[num_servers];

    // Initialize them.  NOTE: You must have run test_rsreg prior to
    // this to create the metadata.out and data.out files.
    for(unsigned int s=0; s<num_servers; ++s) {
	servers[s].init(epoch, "metadata.out", "data.out");
    }

    DP5LookupClient::Metadata meta;
    meta.version = 1;
    meta.epoch = epoch;
    memmove(meta.prfkey, servers[0]._metadatafilecontents,
	    servers[0].PRFKEY_BYTES);
    meta.num_buckets = servers[0]._num_buckets;
    meta.bucket_size = servers[0]._bucket_size;

    cerr << meta.num_buckets << " buckets\n";
    cerr << meta.bucket_size << " records per bucket\n";
    cerr << meta.bucket_size * (params.HASHKEY_BYTES +
	    params.DATAENC_BYTES) << " bytes per bucket\n\n";

    DP5LookupClient::Request req;
    req.init(num_servers, DP5LookupClient::PRIVACY_LEVEL, meta);

    vector<unsigned int> bucketnums;
    bucketnums.push_back(3);
    bucketnums.push_back(1);
    bucketnums.push_back(6);

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

int main(int argc, char **argv)
{
    ZZ_p::init(to_ZZ(256));
    test_pirglue();

    return 0;
}

#endif // TEST_PIRGLUE

#ifdef TEST_PIRGLUEMT
// Test the multi-threadedness of the PIR API glue

#include "dp5lookupclient.h"

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
    DP5Params params;

    unsigned int numthreads = 100;
    unsigned int qperthread = 3;
    bool multithread = true;

    // The current epoch
    unsigned int epoch = params.current_epoch();

    // Use a single server.  NOTE: You must have run test_rsreg prior to
    // this to create the metadata.out and data.out files.
    server = new DP5LookupServer(epoch, "metadata.out", "data.out");

    DP5LookupClient::Metadata meta;
    meta.version = 1;
    meta.epoch = epoch;
    memmove(meta.prfkey, server->_metadatafilecontents, server->PRFKEY_BYTES);
    meta.num_buckets = server->_num_buckets;
    meta.bucket_size = server->_bucket_size;

    DP5Params::PRF prf(meta.prfkey, meta.num_buckets);

    // A vector of question/answer pairs
    vector< pair<string,string> > qas;

    unsigned char hashkey[server->HASHKEY_BYTES];
    memset(hashkey, '\0', server->HASHKEY_BYTES);
    unsigned int iter = 0;

    DP5LookupClient::Request req;
    req.init(params.NUM_PIRSERVERS, DP5LookupClient::PRIVACY_LEVEL, meta);

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

int main(int argc, char **argv)
{
    ZZ_p::init(to_ZZ(256));
    test_pirgluemt();

    return 0;
}

#endif // TEST_PIRGLUEMT
