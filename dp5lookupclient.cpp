#include <sstream>
#include <stdio.h>

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

    // Create the ostreams to hold the output
    vector<ostream*> osvec;
    for (unsigned int j=0; j<_num_servers; ++j) {
	osvec.push_back(new stringstream());
    }

    int ret = _pirclient->send_request(pir_bucketnums, osvec);
    if (!ret) {
	err = 0;
    }

    requeststrs.clear();
    for (unsigned int j=0; j<_num_servers; ++j) {
	if (!ret) {
	    requeststrs.push_back(((stringstream*)(osvec[j]))->str());
	}
	delete osvec[j];
	osvec[j] = NULL;
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
    vector<istream *> isvec;
    for (unsigned int i=0; i<_num_servers;++i) {
	isvec.push_back(new stringstream(responses[i]));
    }

    unsigned int num_replies = _pirclient->receive_replies(isvec);

    for (unsigned int i=0; i<_num_servers;++i) {
	delete isvec[i];
	isvec[i] = NULL;
    }
    isvec.clear();

    // The minimum number of servers that must be honest for us to
    // recover the data.  Let's just do the simplest thing for now.
    unsigned int min_honest = (num_replies + _privacy_level) / 2 + 1;

    // Process the replies.
    vector<PercyBlockResults> pirres;
    _pirclient->process_replies(min_honest, pirres);

    err = 0;
    buckets.clear();
    size_t num_res = pirres.size();
    for (size_t r=0; r<num_res; ++r) {
	if (pirres[r].results.size() == 1) {
	    buckets.push_back(pirres[r].results[0].sigma);
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

// The constructor consumes the client's private key
DP5LookupClient::DP5LookupClient(const unsigned char privkey[PRIVKEY_BYTES]){
    memmove(_privkey,privkey, PRIVKEY_BYTES);
}

// Look up some number of buddies.  Pass in the vector of buddies'
// public keys, the number of lookup servers there are, and the
// privacy level to use (the privacy level is the maximum number of
// lookup servers that can collude without learning what you are
// looking up).  It must be the case that privacy_level <
// num_servers.  req will be filled in with a new Request object.
// Use the get_msgs method on that object to obtain the messages to
// send to the servers, and the lookup_reply method on that object
// to obtain the BuddyPresence information.  Return 0 on success,
// non-0 on failure.
int DP5LookupClient::lookup_request(Request &req, const vector<BuddyKey> buddies,
	unsigned int num_servers, unsigned int privacy_level){

    // Check inputs
    if (buddies.size() > MAX_BUDDIES)
        return 0x01; // Number of buddies exceeds maximum.

    if (_metadata_current.version == 0 || _metadata_current.epoch == 0)
        return 0x02; // No up to date metadata!.

    // Determine the target epoch for the registration
    // as the next epoch, and convert to bytes.
    unsigned int epoch = _metadata_current.epoch;
    unsigned char epoch_bytes[EPOCH_BYTES];
    epoch_num_to_bytes(epoch_bytes, epoch);

    // Placeholder for the output message
    vector<string> labels;

    PRF bucket_mapping(_metadata_current.prfkey, _metadata_current.num_buckets);
    std::set<unsigned int> BIs;
    
    vector<Request::Friend_state> friends;

    // For each real buddy
    for(unsigned int i = 0; i < buddies.size(); i++)
    {
        Request::Friend_state friend_rec;

        const BuddyKey& current_buddy = buddies[i];
        memmove(friend_rec.pubkey, current_buddy.pubkey, PUBKEY_BYTES);

        // Get the long terms shared DH key
        unsigned char shared_dh_secret[PUBKEY_BYTES];
        diffie_hellman(shared_dh_secret, _privkey, friend_rec.pubkey);

        // Derive the epoch keys
        H1H2(friend_rec.shared_key, friend_rec.data_key, epoch_bytes, 
                buddies[i].pubkey, shared_dh_secret);
      
        // Produce HKi
        H3(friend_rec.HKi, epoch_bytes, friend_rec.shared_key);

        // Produce Bi
        friend_rec.bucket = bucket_mapping.M(friend_rec.HKi);
        BIs.insert(friend_rec.bucket);

        friends.push_back(friend_rec);
    }

    unsigned int buckets_to_query = MAX_BUDDIES; 
    if (BIs.size() <= 1) buckets_to_query = 1;

    unsigned int pir_bytes = NUM_PIRSERVERS * ( (_metadata_current.num_buckets / PIR_WORDS_PER_BYTE) + (_metadata_current.bucket_size * (HASHKEY_BYTES + DATAENC_BYTES)) ) * buckets_to_query;
    unsigned int download_bytes = _metadata_current.num_buckets * _metadata_current.bucket_size * (HASHKEY_BYTES + DATAENC_BYTES);

    // Decide if PIR is worth it
    bool do_PIR = pir_bytes < download_bytes;
    // printf("Size: pir %i bytes vs. %i bytes", pir_bytes, download_bytes);

    // Seed the request with all necessary keys and information to determine
    // the messages to be sent.
    req.init(num_servers, privacy_level, _metadata_current, friends, do_PIR);
    return 0x00;
}

vector<string> DP5LookupClient::Request::get_msgs(){
    // Make a sequence of unique buckets
    map<unsigned int,unsigned int> bucket_map;
    vector<unsigned int> buckets;
    for(unsigned int i = 0; i < _friends.size(); i++){
        if (bucket_map.find(_friends[i].bucket) == bucket_map.end()){
            bucket_map[_friends[i].bucket] = buckets.size();            
            buckets.push_back(_friends[i].bucket);
        }
        _friends[i].position = bucket_map[_friends[i].bucket];
    }

    // Determine the number of buckets
    unsigned int buckets_to_query = MAX_BUDDIES; 
    if (bucket_map.size() <= 1) buckets_to_query = 1;

    // Pad to the right number of buckets
    for(unsigned int j = buckets.size(); j < buckets_to_query; j++)
        buckets.push_back(0);

    unsigned char request_header[1+EPOCH_BYTES];
    if (_do_PIR) { request_header[0] = 0xfe; }
           else { request_header[0] = 0xfd; }
    epoch_num_to_bytes(request_header+1, _metadata_current.epoch);
    string header;
    header.assign((const char *)request_header, 1+EPOCH_BYTES);

    // Build the request depending on whether we do PIR or not
    vector<string> requests;
    if(_do_PIR){
        
        // Get the PIR requests and stick a header on them
        int err = pir_query(requests,buckets);
        if (err != 0x00) return requests;

        for (unsigned int j = 0; j < requests.size(); j++){
            requests[j] = header + requests[j];
        }
    } 
    else {

        // Asign the trivial download to a PIR server at random
        DP5Params local_prng;
        unsigned int rand;
        local_prng.random_bytes((unsigned char *) &rand, 4);

        for (unsigned int j = 0; j < _num_servers; j++){
            if (rand % _num_servers == j){
                requests.push_back(header);
            }
            else {
                requests.push_back("");
            }
        }
    }


    return requests;
}


// Process the replies to yield the BuddyPresence information.
// This may only be called once for a given Request object.
// The order of the reply messages must correspond to that of
// the messages produced by get_msgs().  That is, the ith entry
// of the result of get_msgs() should be sent to lookup server
// i, and its response should be the ith entry of replies.  If a
// server does not reply, put the empty string as that entry.
// Return 0 on success, non-0 on error.
int DP5LookupClient::Request::lookup_reply(
        vector<BuddyPresence> &presence,
	    const vector<string> &replies){

    // We expect the same number of replies as servers.
    // (Or empty strings at least)
    if (replies.size() != _num_servers) return 0x01;


    unsigned int number_of_valid_msg = 0;
    vector<string> buckets;
    buckets.assign(MAX_BUDDIES, ""); // Hack: max number of buckets

    if (_do_PIR){
        vector<string> pir_replies;
        for (unsigned int s = 0; s < _num_servers; s++){
            // Process a non reply
            if (replies[s] == ""){
                pir_replies.push_back("");
                continue;
            }

            // Message should be long-ish
            if ( replies[s].length() < 1 + EPOCH_BYTES) return 0x02;

            unsigned int status = ((unsigned char *) replies[s].data())[0];
            // Expected a PIR request but got a download.
            if (status != 0x81) return 0x03;
            
            unsigned int server_epoch = 
                epoch_bytes_to_num((const unsigned char *) replies[s].data() + 1);
            // Expect to get a reply for the current epoch            
            if (server_epoch != _metadata_current.epoch) return 0x04;
            
            string q;
            q.assign(replies[s].data() + (1 + EPOCH_BYTES), 
                replies[s].length() - (1 + EPOCH_BYTES));

            pir_replies.push_back(q);
            number_of_valid_msg ++;
        }
        
        // Do we have the right number of replies?
        if (number_of_valid_msg < _privacy_level +1) return 0x05;

        // Process the responses using the PIR library
        int err = pir_response(buckets, pir_replies);
        if (err != 0) return err;

    }
    else {
        for (unsigned int s = 0; s < _num_servers; s++){
            // Process a non reply
            if (replies[s] != ""){

                // Message should be long-ish
                if ( replies[s].length() < 1 + EPOCH_BYTES) return 0x12;

                unsigned int status = ((unsigned char *) replies[s].data())[0];
                // Expected a download request but got a PIR?
                // printf("Status %X\n", status);
                if (status != 0x82) return 0x13;
            
                unsigned int server_epoch = 
                    epoch_bytes_to_num((const unsigned char *) replies[s].data() + 1);
                // Expect to get a reply for the current epoch            
                if (server_epoch != _metadata_current.epoch) return 0x14;

                const char * database = 
                    ((char *) replies[s].data()) + (1 + EPOCH_BYTES); 
                unsigned int database_size = replies[s].length() - (1 + EPOCH_BYTES);

                // Check it is a multiple of HASHKEY_BYTES + DATAENC_BYTES
                if (database_size % (HASHKEY_BYTES + DATAENC_BYTES) != 0)
                    return 0x15;

                // Extract the buckets
                for (unsigned int f = 0; f < _friends.size(); f++){
                    string friend_record;
                    if (buckets[_friends[f].position] == ""){
                        size_t idx = 
                            _friends[f].bucket * _metadata_current.bucket_size 
                            * (HASHKEY_BYTES + DATAENC_BYTES);

                        // Is this still within bounds?
                        if (idx + HASHKEY_BYTES + DATAENC_BYTES > database_size)
                            return 0x17;

                        friend_record.assign(database + idx, 
                            _metadata_current.bucket_size  * (HASHKEY_BYTES + DATAENC_BYTES));
                        buckets[_friends[f].position] = friend_record;
                    }
                }

                number_of_valid_msg ++;
                break;
            }
            
            // Did not find a single valid download reply
            if (number_of_valid_msg < 0) return 0x16;
        }
    }


    // Since we have made it so far, it means we have a bunch
    // of buckets, and should use them to extract the (HK,D) for 
    // each friend. 
    // TODO: We could use a binary search algorithm, but I am 
    // just going to use linear search for the moment. Its not like
    // we are going to be doing this very often, and it is not on 
    // the critical path to enable other ops. Optimize later.

    presence.clear();

    for (unsigned int f = 0; f < _friends.size(); f++){
        // We asked for this bucket, but it is empty!
        if (buckets[_friends[f].position] == "") return 0x08;

        const char * friend_bucket = buckets[_friends[f].position].data();
        BuddyPresence output_record;
        memmove(output_record.pubkey, _friends[f].pubkey, PUBKEY_BYTES);
        output_record.is_online = false;

        // Linear search through the bucket to find the hash
        for(unsigned int i = 0; i < _metadata_current.bucket_size; i++){
            const char * p = friend_bucket + i*(HASHKEY_BYTES + DATAENC_BYTES);
            if (memcmp(p, _friends[f].HKi, HASHKEY_BYTES) == 0)
            {
                // Found it!
                output_record.is_online = true;
                Dec(output_record.data, _friends[f].data_key, (unsigned char *) p + HASHKEY_BYTES);
            }
        }

        presence.push_back(output_record);
    }
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
    vector<DP5LookupClient::Request::Friend_state> fs;
    a.init(5, 2, meta, fs, true);
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
