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
    if (!ret) {
	err = 0;
    }

    requeststrs.clear();
    for (unsigned int j=0; j<_num_servers; ++j) {
	if (!ret) {
	    requeststrs.push_back(((stringstream*)(iosvec[j]))->str());
	}
	delete iosvec[j];
	iosvec[j] = NULL;
    }

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

    if (responses.size() != _num_servers) {
	return err;
    }

    // Receive the replies
    vector<iostream *> iosvec;
    for (unsigned int i=0; i<_num_servers;++i) {
	iosvec.push_back(new stringstream(responses[i]));
    }

    unsigned int num_replies = _pirclient->receive_replies(iosvec);

    for (unsigned int i=0; i<_num_servers;++i) {
	delete iosvec[i];
	iosvec[i] = NULL;
    }
    iosvec.clear();

    // The minimum number of servers that must be honest for us to
    // recover the data.  Let's just do the simplest thing for now.
    unsigned int min_honest = (num_replies + _privacy_level) / 2 + 1;

    // Process the replies.  The empty blocknumers and iosvec will cause
    // bad things to happen if the "fetch more blocks to try to correct
    // more errors" code is invoked.  For now, we won't worry about
    // having lots of Byzantine lookup servers, and indeed since
    // min_honest is set to the above value, this should never happen.
    vector<dbsize_t> block_numbers;
    vector< vector<PercyResult> > pirres = _pirclient->process_replies(
	min_honest, block_numbers, iosvec);

    err = 0;
    buckets.clear();
    size_t num_res = pirres.size();
    for (size_t r=0; r<num_res; ++r) {
	if (pirres[r].size() == 1) {
	    buckets.push_back(pirres[r][0].sigma);
	} else {
	    buckets.push_back(string());
	    err = -1;
	}
    }

    return err;
}

void DP5LookupClient::metadata_request(string &msgtosend, unsigned int epoch){
    unsigned char metadata_request_message[1+EPOCH_BYTES];
    metadata_request_message[0] = 0xff;
    epoch_num_to_bytes(metadata_request_message+1, epoch);

    // Keep track of the current metadata request epoch
    _metadata_request_epoch = epoch; 

    // Output this message
    msgtosend.assign((char *) metadata_request_message, 1+EPOCH_BYTES);
}

// Consume the reply to a metadata request.  Return 0 on success,
// non-0 on failure.
int DP5LookupClient::metadata_reply(const string &metadata){
    const unsigned char* msgdata = (const unsigned char*) metadata.data();
    
    // Check input: The server returned an error.
    if (msgdata[0] == 0x00) return 0x01;
        
    // Check input: We do not know about this version of the protocol.
    if (msgdata[0] != 0x01) return 0x02;

    // Check input: wrong input length
    if(metadata.size() != (1 + EPOCH_BYTES + PRFKEY_BYTES + 2 * UINT_BYTES)) 
        return 0x03;

    unsigned int epoch = epoch_bytes_to_num(msgdata + 1);

    // Check epoch: we did not expect a metadata reply
    if (_metadata_request_epoch == 0) return 0x04;

    // Check epoch: not the epoch we expected strangely
    // TODO: should we somehow tell the client that they need to sync?
    if (epoch != _metadata_request_epoch) return 0x05;
    
    // Now copy all fields to the metadata record
    _metadata_current.version = msgdata[0];
    _metadata_current.epoch = epoch;
    memcpy(_metadata_current.prfkey, msgdata+(1+EPOCH_BYTES), 
        PRFKEY_BYTES);
    _metadata_current.num_buckets = 
        uint_bytes_to_num(msgdata+(1+EPOCH_BYTES+PRFKEY_BYTES));
    _metadata_current.bucket_size = 
        uint_bytes_to_num(msgdata+(1+EPOCH_BYTES+PRFKEY_BYTES+UINT_BYTES));

    // Reset the state
    _metadata_request_epoch = 0; 

    return 0x00;
}

#ifdef TEST_REQCD

// Test the constructor, copy constructor, assignment operator,
// destructor
void test_reqcd(DP5LookupClient::Request &a)
{
    DP5Params p;

    DP5LookupClient::Metadata meta;
    meta.version = 1;
    meta.epoch = p.current_epoch();
    p.random_bytes(meta.prfkey, p.PRFKEY_BYTES);
    meta.num_buckets = 1000;
    meta.bucket_size = 50;

    DP5LookupClient::Request b;
    a.init(5, 2, meta);
    b = a;
    DP5LookupClient::Request c(b);
    DP5LookupClient::Request d = c;
    DP5LookupClient::Request e;
    e = d;
}

int main(int argc, char **argv)
{
    DP5LookupClient::Request a;
    ZZ_p::init(to_ZZ(256));

    test_reqcd(a);

    return 0;
}

#endif // TEST_REQCD
