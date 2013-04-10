#include "dp5lookupclient.h"
#include "percyclient.h"

// The array of valid numbers of buddies a client can send at lookup time
unsigned int DP5LookupClient::QUERY_SIZES[] =
    { 1, DP5LookupClient::MAX_BUDDIES };


// The glue API to the PIR layer.  Pass a vector of the bucket
// numbers to look up.  This should already be padded to one of
// the valid sizes listed in QUERY_SIZES.  Place the querys to
// send to the servers into requeststrs.  Return 0 on success,
// non-0 on failure.
int DP5LookupClient::Request::pir_query(vector<string> &requeststrs,
		const vector<unsigned int> &bucketnums)
{
    int err = -1;

    // Convert the bucketnums to the right type
    vector<dbsize_t> pir_bucketnums;
    size_t numqs = bucketnums.size();
    for (size_t i=0; i<numqs; ++i) {
	pir_bucketnums.push_back((dbsize_t)bucketnums[i]);
    }

    // Create the iostreams to hold the output
    vector<iostream*> iosvec;
    for (unsigned int j=0; j<_num_servers; ++j) {
	iosvec.push_back(new stringstream());
    }

    int ret = _pirclient->send_request(pir_bucketnums, iosvec);
    if (ret) {
	return err;
    }

    requeststrs.clear();
    for (unsigned int j=0; j<_num_servers; ++j) {
	requeststrs.push_back(((stringstream*)(iosvec[j]))->str());
	delete iosvec[j];
	iosvec[j] = NULL;
    }

    return 0;
}

// The glue API to the PIR layer.  Pass the responses from the
// servers into responsestrs.  buckets will be filled with the
// contents of the buckets indexed by bucketnums.  Return 0 on
// success, non-0 on failure.
int DP5LookupClient::Request::pir_response(vector<string> &buckets,
		const vector<string> &responses)
{
    int err = -1;

    return err;
}
