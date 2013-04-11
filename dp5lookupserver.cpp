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
}

int main(int argc, char **argv)
{
    ZZ_p::init(to_ZZ(256));
    test_pirglue();

    return 0;
}

#endif // TEST_PIRGLUE
