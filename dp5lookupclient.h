#ifndef __DP5LOOKUPCLIENT_H__
#define __DP5LOOKUPCLIENT_H__

#include <vector>
#include <string>
#include "dp5params.h"

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
    };

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
