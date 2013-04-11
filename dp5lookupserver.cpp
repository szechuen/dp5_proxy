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

    unsigned int num_buckets = 0;
    unsigned int bucket_size = 0;
    memmove(((char *)&num_buckets)+sizeof(unsigned int)-UINT_BYTES,
	_metadatafilecontents+PRFKEY_BYTES, UINT_BYTES);
    memmove(((char *)&bucket_size)+sizeof(unsigned int)-UINT_BYTES,
	_metadatafilecontents+PRFKEY_BYTES+UINT_BYTES, UINT_BYTES);
    num_buckets = ntohl(num_buckets);
    bucket_size = ntohl(bucket_size);

    _pirserverparams = new PercyServerParams(
	bucket_size * (HASHKEY_BYTES + DATAENC_BYTES), num_buckets,
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

    // This can just be copied
    _epoch = other._epoch;

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
