#ifndef __DP5LOOKUPSERVER_H__
#define __DP5LOOKUPSERVER_H__

#include <string>
#include "dp5params.h"
#include "percyserver.h"

class DP5LookupServer : public DP5Params {
public:
    // The constructor consumes the current epoch number, and the
    // filenames of the current metadata and data files.
    DP5LookupServer(unsigned int epoch, const char *metadatafilename,
	const char *datafilename);

    // Copy constructor
    DP5LookupServer(const DP5LookupServer &other);

    // Assignment operator
    DP5LookupServer& operator=(DP5LookupServer other);

    // Destructor
    ~DP5LookupServer();

    // Process a received request from a lookup client.  This may be
    // either a metadata or a data request.  Set reply to the reply to
    // return to the client.
    void process_request(string &reply, const string &request);

private:
    // Initialize the private members from the epoch and the filenames
    void init(unsigned int epoch, const char *metadatafilename,
	const char *datafilename);

    // The glue API to the PIR layer.  Pass a request string as produced
    // by pir_query.  reponse is filled in with the reponse; pass it to
    // pir_response.  Return 0 on success, non-0 on failure.
    int pir_process(string &response, const string &request);

    // The epoch
    unsigned int _epoch;

    // The metadata filename
    char *_metadatafilename;

    // The data filename
    char *_datafilename;

    // The metadata file descriptor
    int _metadatafd;

    // The metadata file contents
    unsigned char *_metadatafilecontents;

    // The PercyServerParams, filled in from the metadata file
    PercyServerParams *_pirserverparams;

    // The DataStore, filled in from the data file
    FileDataStore *_datastore;

    // The PercyServer used to serve requests
    PercyServer *_pirserver;
};

#endif
