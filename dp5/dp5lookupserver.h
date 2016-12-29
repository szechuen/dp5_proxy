#ifndef __DP5LOOKUPSERVER_H__
#define __DP5LOOKUPSERVER_H__

#include <string>
#include "dp5params.h"
#include "dp5metadata.h"
#include "percyserver.h"

namespace dp5 {

class DP5LookupServer {
public:
    static const nservers_t DEFAULT_NUM_THREADS = 16;
    static const DistSplit DEFAULT_SPLIT_TYPE = DIST_SPLIT_RECORDS;

    // The constructor consumes the current epoch number, and the
    // filenames of the current metadata and data files.
    DP5LookupServer(const char *metadatafilename,
	const char *datafilename,
	nservers_t numthreads = DEFAULT_NUM_THREADS,
	DistSplit splittype = DEFAULT_SPLIT_TYPE);

    // Default constructor
    DP5LookupServer() : _metadatafilename(NULL),
	    _datafilename(NULL), _pirparams(NULL), _pirserverparams(NULL),
	    _datastore(NULL), _pirserver(NULL), _metadata(),
	    _numthreads(DEFAULT_NUM_THREADS),
	    _splittype(DEFAULT_SPLIT_TYPE) {}

    // Copy constructor
    DP5LookupServer(const DP5LookupServer &other);

    // Assignment operator
    DP5LookupServer& operator=(DP5LookupServer other);

    // Destructor
    ~DP5LookupServer();

    // Initialize the private members from the epoch and the filenames
    void init(const char *metadatafilename,
	const char *datafilename,
	nservers_t numthreads = DEFAULT_NUM_THREADS,
	DistSplit splittype = DEFAULT_SPLIT_TYPE);

    // Process a received request from a lookup client.  This may be
    // either a metadata or a data request.  Set reply to the reply to
    // return to the client.
    void process_request(std::string &reply, const std::string &request);

    const internal::Metadata & getMetadata() { return _metadata; }

    const DP5Config & getConfig() { return _metadata; }

private:
    // The glue API to the PIR layer (single-client version).  Pass a
    // request string as produced by pir_query.  reponse is filled in
    // with the reponse; pass it to pir_response.  Return 0 on success,
    // non-0 on failure.
    int pir_process(std::string &response, const std::string &request);

    // The glue API to the PIR layer (multi-client version).  Pass a
    // vector of request strings, each as produced by pir_query.
    // reponse is filled in with the vector of reponses; pass each to
    // pir_response.  Return 0 on success, non-0 on failure.
    int pir_process(vector<string> &responses, const vector<string>&requests);

    // The metadata filename
    char *_metadatafilename;

    // The data filename
    char *_datafilename;

    // The PercyServerParams, filled in from the metadata file
    GF2EParams *_pirparams;
    PercyServerParams *_pirserverparams;

    // The DataStore, filled in from the data file
    FileDataStore *_datastore;

    // The PercyServer used to serve requests
    PercyServer *_pirserver;

    internal::Metadata _metadata;

    // The number of threads to use
    nservers_t _numthreads;

    // Split by query (DIST_SPLIT_QUERIES) or by record
    // (DIST_SPLIT_RECORDS)?
    DistSplit _splittype;

#ifdef TEST_PIRGLUE
    friend void test_pirglue(int num_blocks_to_fetch);
#endif
#ifdef TEST_PIRGLUEMT
    friend void test_pirgluemt();
    friend void *test_pirgluemt_single(void *);
#endif
#ifdef TEST_PIRMULTIC
    friend void test_pirmultic(int num_clients, int num_blocks_to_fetch);
#endif
};

}
#endif
