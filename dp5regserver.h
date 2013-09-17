#ifndef __DP5REGSERVER_H__
#define __DP5REGSERVER_H__

#include <string>
#include <iostream>
#include "dp5params.h"  

#include <Pairing.h>

class DP5RegServer : public DP5Params {
public:
    // The number of iterations over the PRF bucketization
    static const unsigned int NUM_PRF_ITERS = 10;

    // The constructor consumes the current epoch number, the directory
    // in which to store the incoming registrations for the current
    // epoch, and the directory in which to store the metadata and data
    // files.
    DP5RegServer(unsigned int current_epoch, const char *regdir,
	const char *datadir, bool usePairings = false);

    // Copy constructor
    DP5RegServer(const DP5RegServer &other);

    // Assignment operator
    DP5RegServer& operator=(DP5RegServer other);

    // Destructor
    ~DP5RegServer();

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

protected:
    // The current epoch number
    unsigned int _epoch;

    // The directory in which to store incoming registration information
    char *_regdir;

    // The directory in which to store metadata and data files
    char *_datadir;      

	bool _usePairings;
    const Pairing _pairing;

    // Create the registration file for the given epoch.
    void create_nextreg_file(unsigned int useepoch);
};

#endif
