#ifndef __DP5LOOKUPSERVER_H__
#define __DP5LOOKUPSERVER_H__

#include <string>
#include "dp5params.h"

class DP5LookupServer : public DP5Params {
public:
    // The constructor consumes the current epoch number, and the
    // filenames of the current metadata and data files.
    DP5LookupServer(unsigned int epoch, const char *metadatafilename,
	const char *datafilename);

    // Process a received request from a lookup client.  This may be
    // either a metadata or a data request.  Set reply to the reply to
    // return to the client.
    void process_request(string &reply, const string &request);
};

#endif
