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

    return err;
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
