#ifndef __DP5REGCLIENT_H__
#define __DP5REGCLIENT_H__

#include <vector>
#include <string>
#include "dp5params.h"

namespace dp5 {

// The information to tell one buddy when you come online
struct BuddyInfo {
    // The buddy's public key
    PubKey pubkey;
    std::string data;
};

class DP5RegClient {
public:
    // The constructor consumes the client's own private key
    DP5RegClient(const DP5Config & config, const PrivKey privkey);

    // Register yourself as visible to a number of buddies (at most
    // MAX_BUDDIES).  Return 0 on success, in which case msgtosend will be
    // filled with the message to send to the registration server.
    // Return non-zero on error.
    int start_reg(std::string &msgtosend,
                  Epoch next_epoch,
                  const std::vector<BuddyInfo> &buddies);

    // Once the above message is sent to the registration server, pass
    // the reply to this function.  Return 0 on success, non-zero on
    // error.
    int complete_reg(const std::string &replymsg,
                      Epoch next_epoch);

private:
    // Save a copy of the private key
    PrivKey _privkey;
    DP5Config _config;
};

}

#endif
