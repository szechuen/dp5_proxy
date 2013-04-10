#ifndef __DP5LOOKUPCLIENT_H__
#define __DP5LOOKUPCLIENT_H__

#include <vector>
#include <string>
#include "dp5params.h"
#include "percyparams.h"
#include "percyclient.h"

struct BuddyKey {
    // A buddy's public key
    unsigned char pubkey[DP5Params::PUBKEY_BYTES];
};

struct BuddyPresence {
    // A buddy's public key
    unsigned char pubkey[DP5Params::PUBKEY_BYTES];

    // Is the buddy reporting to us that he/she is online?
    bool is_online;

    // If is_online is true, the plaintext associated data goes here
    unsigned char data[DP5Params::DATAPLAIN_BYTES];
};

class DP5LookupClient: public DP5Params {
private:
    // The epoch number for which we have an outstanding metadata request,
    // or 0 if there is no outstanding metadata request
    unsigned int _metadata_request_epoch;

    // The last successful metadata response.  version and epoch will be
    // 0 if no response has yet been successfully received.
    struct Metadata {
	unsigned char version;
	unsigned int epoch;
	unsigned char prfkey[PRFKEY_BYTES];
	unsigned int num_buckets;
	unsigned int bucket_size;
    } _metadata_current;

public:
    // A class representing an in-progress lookup request
    class Request {
    public:
	// Constructor
	Request(): _pirparams(NULL), _pirclient(NULL),
		    _pir_server_indices(NULL) {}

	// Destructor
	~Request() {
	    delete[] _pir_server_indices;
	    delete _pirparams;
	    delete _pirclient;
	}

	// Copy constructor
	Request(const Request &other) {
	    _num_servers = other._num_servers;
	    _privacy_level = other._privacy_level;
	    _metadata_current = other._metadata_current;
	    _pirparams = NULL;
	    if (other._pirparams) {
		_pirparams = new PercyClientParams(*other._pirparams);
	    }
	    _pirclient = NULL;
	    if (other._pirclient) {
		_pirclient = new PercyClient(*other._pirclient);
	    }
	    _pir_server_indices = NULL;
	    if (other._pir_server_indices) {
		_pir_server_indices = new sid_t[_num_servers];
		memmove(_pir_server_indices, other._pir_server_indices,
			_num_servers * sizeof(sid_t));
	    }
	}

	// Assignment operator
	Request& operator=(Request other) {
	    // Swap the fields of the temporary "other" with ours
	    // so things get properly freed
	    sid_t *tmp = other._pir_server_indices;
	    other._pir_server_indices = _pir_server_indices;
	    _pir_server_indices = tmp;

	    PercyClientParams *tmpc = other._pirparams;
	    other._pirparams = _pirparams;
	    _pirparams = tmpc;

	    PercyClient *tmpcl = other._pirclient;
	    other._pirclient = _pirclient;
	    _pirclient = tmpcl;

	    // The non-dynamic members can be just copied
	    _num_servers = other._num_servers;
	    _privacy_level = other._privacy_level;
	    _metadata_current = other._metadata_current;

	    return *this;
	}

	// Initialize the Request object
	void init(unsigned int num_servers, unsigned int privacy_level,
		    const Metadata &metadata) {
	    _num_servers = num_servers;
	    _privacy_level = privacy_level;
	    _metadata_current = metadata;
	    _pirparams = new PercyClientParams(
		_metadata_current.bucket_size *
		    (HASHKEY_BYTES + DATAENC_BYTES),
		_metadata_current.num_buckets, 0, to_ZZ("256"), MODE_GF28,
		    NULL, false);
	    _pir_server_indices = new sid_t[_num_servers];

	    _pirclient = new PercyClient(*_pirparams, _num_servers,
					    _privacy_level);
	    _pirclient->choose_indices(_pir_server_indices);
	}

	// Get the messages to send to the lookup servers.  Send the ith
	// entry of the resulting vector to lookup server i, unless the
	// ith entry is the empty string (in which case don't send
	// anything to server i, and set the corresponding reply to the
	// empty string in lookup_reply).
	vector<string> get_msgs() const;

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
	// The number of lookup servers
	unsigned int _num_servers;

	// The privacy level to use
	unsigned int _privacy_level;

	// The metadata to use
	Metadata _metadata_current;

	// The PercyClientParams, constructed from the above pieces
	PercyClientParams *_pirparams;

	// The PercyClient in use
	PercyClient *_pirclient;

	// The server indices used by PIR
	sid_t *_pir_server_indices;

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
    };

    // The number of valid numbers of buddies a client can send at
    // lookup time
    static const unsigned int NUM_QUERY_SIZES = 2;

    // The array of valid numbers of buddies a client can send at lookup
    // time (The actual values are set in the cpp file.)
    static unsigned int QUERY_SIZES[NUM_QUERY_SIZES];

    // The number of PIR servers that can collude without revealing a
    // client's query
    static const unsigned int PRIVACY_LEVEL = 2;

    // The constructor consumes the client's private key
    DP5LookupClient(const unsigned char privkey[PRIVKEY_BYTES]);

    // Create a request for the metadata file.  This (and the next
    // method) must complete in each epoch before invoking the lookup
    // functions.
    void metadata_request(unsigned int epoch);

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

};

#endif
