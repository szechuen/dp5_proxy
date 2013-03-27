#ifndef __DP5REGCLIENT_H__
#define __DP5REGCLIENT_H__

#include <vector>
#include <string>
#include "dp5params.h"

// The information to tell one buddy when you come online
struct BuddyInfo {
    // The buddy's public key
    unsigned char pubkey[DP5Params::PUBKEY_BYTES];

    // The associated data you want to tell him
    unsigned char data[DP5Params::DATAPLAIN_BYTES];
};

class DP5RegClient : public DP5Params {
public:
    // The constructor consumes the client's own private key
    DP5RegClient(const unsigned char privkey[PRIVKEY_BYTES]);

    // Register yourself as visible to a number of buddies (at most
    // MAX_BUDDIES).  Return 0 on success, in which case msgtosend will be
    // filled with the message to send to the registration server.
    // Return non-zero on error.
    int start_reg(string &msgtosend, const vector<BuddyInfo> &buddies);

    // Once the above message is sent to the registration server, pass
    // the reply to this function.  Return 0 on success, non-zero on
    // error.
    int complete_reg(const string &replymsg);

private:
    // Save a copy of the private key
    unsigned char _privkey[PRIVKEY_BYTES];
};

#endif
