#ifndef __DP5REGSERVER_H__
#define __DP5REGSERVER_H__

#include <string>
#include <iostream>
#include "dp5params.h"

class DP5RegServer : public DP5Params {
    // The number of iterations over the PRF bucketization
    static const unsigned int NUM_PRF_ITERS = 10;

    // The constructor consumes the current epoch number
    DP5RegServer(unsigned int current_epoch);

    // When a registration message regmsg is received from a client,
    // pass it to this function.  msgtoreply will be filled in with the
    // message to return to the client in response.  Client
    // registrations will become visible in the *next* epoch.
    void client_reg(string &msgtoreply, const string &regmsg);

    // Call this when the epoch changes.  Pass in ostreams to which this
    // function should write the metadata and data files to serve in
    // this epoch.  The function will return the new epoch number.
    // After this function returns, send the metadata and data files to
    // the PIR servers, labelled with the new epoch number.
    unsigned int epoch_change(ostream &metadataos, ostream &dataos);
};

#endif
