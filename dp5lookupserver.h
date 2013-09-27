#ifndef __DP5LOOKUPSERVER_H__
#define __DP5LOOKUPSERVER_H__

#include <string>
#include "dp5params.h"
#include "dp5metadata.h"
#include "percyserver.h"

namespace dp5 {

class DP5LookupServer {
public:
    // The constructor consumes the current epoch number, and the
    // filenames of the current metadata and data files.
    DP5LookupServer(const char *metadatafilename,
	const char *datafilename);

    // Default constructor
    DP5LookupServer() : _metadatafilename(NULL),
	    _datafilename(NULL), _pirserverparams(NULL),
	    _datastore(NULL), _pirserver(NULL), _metadata() {}

    // Copy constructor
    DP5LookupServer(const DP5LookupServer &other);

    // Assignment operator
    DP5LookupServer& operator=(DP5LookupServer other);

    // Destructor
    ~DP5LookupServer();

    // Initialize the private members from the epoch and the filenames
    void init(const char *metadatafilename,
	const char *datafilename);

    // Process a received request from a lookup client.  This may be
    // either a metadata or a data request.  Set reply to the reply to
    // return to the client.
    void process_request(std::string &reply, const std::string &request);

    const internal::Metadata & getMetadata() { return _metadata; }

    const DP5Config & getConfig() { return _metadata; }

private:
    // The glue API to the PIR layer.  Pass a request string as produced
    // by pir_query.  reponse is filled in with the reponse; pass it to
    // pir_response.  Return 0 on success, non-0 on failure.
    int pir_process(std::string &response, const std::string &request);


    // The metadata filename
    char *_metadatafilename;

    // The data filename
    char *_datafilename;

    // The PercyServerParams, filled in from the metadata file
    PercyServerParams *_pirserverparams;

    // The DataStore, filled in from the data file
    FileDataStore *_datastore;

    // The PercyServer used to serve requests
    PercyServer *_pirserver;

    internal::Metadata _metadata;

#ifdef TEST_PIRGLUE
    friend void test_pirglue();
#endif

};

}
#endif
