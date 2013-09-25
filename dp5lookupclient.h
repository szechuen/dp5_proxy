#ifndef __DP5LOOKUPCLIENT_H__
#define __DP5LOOKUPCLIENT_H__

#include <vector>
#include <string>
#include <set>
#include <map>
#include <stdexcept>
#include <sstream>
#include "dp5params.h"
#include "percyparams.h"
#include "percyclient.h"

struct BuddyKey {
    // A buddy's public key
    std::string pubkey;
};

struct BuddyPresence {
    // A buddy's public key
    std::string pubkey;

    // Is the buddy reporting to us that he/she is online?
    bool is_online;

    // If is_online is true, the plaintext associated data goes here
    std::string data;
};

typedef PercyClient_GF2E<GF28_Element> PercyClientGF28;

class DP5LookupClient: protected DP5Metadata {
private:
    // The epoch number for which we have an outstanding metadata request,
    // or 0 if there is no outstanding metadata request
    unsigned int _metadata_request_epoch;

    // Save a copy of the private key
    std::string _privkey;

public:
    // A class representing an in-progress lookup request
    class Request {
    public:
	// Constructor
	Request(): _pirparams(NULL), _pirclient(NULL) {}

	// Destructor
	~Request() {
	    delete _pirparams;
	    delete _pirclient;
	}

	// Copy constructor
	Request(const Request &other) {
	    _num_servers = other._num_servers;
	    _privacy_level = other._privacy_level;
	    _metadata_current = other._metadata_current;
        _friends = other._friends;
        _do_PIR = other._do_PIR;

	    _pirparams = NULL;
	    if (other._pirparams) {
		_pirparams = new PercyClientParams(*other._pirparams);
	    }
	    _pirclient = NULL;
	    if (other._pirclient) {
		_pirclient = new PercyClientGF28(*other._pirclient);
	    }
	}

	// Assignment operator
	Request& operator=(Request other) {
	    // Swap the fields of the temporary "other" with ours
	    // so things get properly freed

	    PercyClientParams *tmpc = other._pirparams;
	    other._pirparams = _pirparams;
	    _pirparams = tmpc;

	    PercyClientGF28 *tmpcl = other._pirclient;
	    other._pirclient = _pirclient;
	    _pirclient = tmpcl;

	    // The non-dynamic members can be just copied
	    _num_servers = other._num_servers;
	    _privacy_level = other._privacy_level;
	    _metadata_current = other._metadata_current;
        _friends = other._friends;
        _do_PIR = other._do_PIR;
	    return *this;
	}

    struct Friend_state {
    	std::string pubkey;
        unsigned char shared_key[SHAREDKEY_BYTES];
        unsigned char data_key[DATAKEY_BYTES];
        unsigned char HKi[HASHKEY_BYTES];
        unsigned int bucket;
        unsigned int position;
    };

	// Initialize the Request object
	void init(unsigned int num_servers, unsigned int privacy_level,
		    const DP5Metadata &metadata, const vector<Friend_state> &friends, bool do_PIR) {        
        _do_PIR = do_PIR; 
        _friends = friends;
	    _num_servers = num_servers;
	    _privacy_level = privacy_level;
	    _metadata_current = metadata;
	    _pirparams = new PercyClientParams(
		_metadata_current.bucket_size *
		    (HASHKEY_BYTES + _metadata_current.dataenc_bytes),
		_metadata_current.num_buckets, 0, to_ZZ(256), MODE_GF28,
		    NULL, false);

	    _pirclient = (PercyClientGF28*)PercyClient::make_client(
			    *_pirparams, _num_servers, _privacy_level);
	}

	// Get the messages to send to the lookup servers.  Send the ith
	// entry of the resulting vector to lookup server i, unless the
	// ith entry is the empty string (in which case don't send
	// anything to server i, and set the corresponding reply to the
	// empty string in lookup_reply).
	vector<string> get_msgs();

	// Process the replies to yield the BuddyPresence information.
	// This may only be called once for a given Request object.
	// The order of the reply messages must correspond to that of
	// the messages produced by get_msgs().  That is, the ith entry
	// of the result of get_msgs() should be sent to lookup server
	// i, and its response should be the ith entry of replies.  If a
	// server does not reply, put the empty string as that entry.
	// Return 0 on success, non-0 on error.
	int lookup_reply(vector<BuddyPresence> &presence,
	    const vector<string> &replies);



    private:

    // The internal state of the fiends, inc. keys and bukets
    vector<Friend_state> _friends;

    // Flag indicating we do PIR, and not download.
    bool _do_PIR;

	// The number of lookup servers
	unsigned int _num_servers;

	// The privacy level to use
	unsigned int _privacy_level;

	// The PercyClientParams, constructed from the above pieces
	PercyClientParams *_pirparams;

	// The PercyClient in use
	PercyClientGF28 *_pirclient;

	DP5Metadata _metadata_current;

	// The glue API to the PIR layer.  Pass a vector of the bucket
	// numbers to look up.  This should already be padded to one of
	// the valid sizes listed in QUERY_SIZES.  Place the querys to
	// send to the servers into requeststrs.  Return 0 on success,
	// non-0 on failure.
	int pir_query(vector<string> &requeststrs,
			const vector<unsigned int> &bucketnums);

	// The glue API to the PIR layer.  Pass the responses from the
	// servers into responsestrs.  buckets will be filled with the
	// contents of the buckets indexed by bucketnums.  Return 0 on
	// success, non-0 on failure.
	int pir_response(vector<string> &buckets,
			const vector<string> &responses);

#ifdef TEST_PIRGLUE
	friend void test_pirglue();
#endif // TEST_PIRGLUE
#ifdef TEST_PIRGLUEMT
	friend void test_pirgluemt();
#endif // TEST_PIRGLUEMT
    };

    // The number of valid numbers of buddies a client can send at
    // lookup time
    static const unsigned int NUM_QUERY_SIZES = 2;

    // The array of valid numbers of buddies a client can send at lookup
    // time (The actual values are set in the cpp file.)
    static unsigned int QUERY_SIZES[NUM_QUERY_SIZES];

    // The constructor consumes the client's private key
    DP5LookupClient(const string & privkey) 
        throw (std::invalid_argument) :
        _privkey(privkey)
    {
        if (privkey.length() != PRIVKEY_BYTES) {
            stringstream error;
            error << "Private key must be " << PRIVKEY_BYTES << " long  (got " 
                << privkey.length() << ")";
            throw std::invalid_argument(error.str());
        }
    }

        // FIXME: make sure string is long enough

    // Create a request for the metadata file.  This (and the next
    // method) must complete in each epoch before invoking the lookup
    // functions.
    void metadata_request(string &msgtosend, unsigned int epoch);

    // Consume the reply to a metadata request.  Return 0 on success,
    // non-0 on failure.
    int metadata_reply(const string &metadata);

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
    int lookup_request(Request &req, const vector<BuddyKey> buddies,
	unsigned int num_servers, unsigned int privacy_level);

#ifdef TEST_REQCD
    friend void test_reqcd(Request &a);
#endif // TEST_REQCD
#ifdef TEST_PIRGLUE
    friend void test_pirglue();
#endif // TEST_PIRGLUE
#ifdef TEST_PIRGLUEMT
    friend void test_pirgluemt();
#endif // TEST_PIRGLUEMT

};

#endif
