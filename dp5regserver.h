#ifndef __DP5REGSERVER_H__
#define __DP5REGSERVER_H__

#include <string>
#include <iostream>
#include "dp5params.h"

#include <Pairing.h>

namespace dp5 {

class DP5RegServer {
public:
    // The constructor consumes the current epoch number, the directory
    // in which to store the incoming registrations for the current
    // epoch, and the directory in which to store the metadata and data
    // files.
    DP5RegServer(const DP5Config & config, Epoch epoch, const char *regdir,
    	const char *datadir);

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
    void client_reg(std::string &msgtoreply, const std::string &regmsg);

    // Call this when the epoch changes.  Pass in ostreams to which this
    // function should write the metadata and data files to serve in
    // this epoch.  The function will return the new epoch number.
    // After this function returns, send the metadata and data files to
    // the PIR servers, labelled with the new epoch number.
    unsigned int epoch_change(std::ostream &metadataos, std::ostream &dataos);

protected:
    // The directory in which to store incoming registration information
    char *_regdir;

    // The directory in which to store metadata and data files
    char *_datadir;

    // Create the registration file for the given epoch.
    void create_nextreg_file(unsigned int useepoch);

    DP5Config _config;
    Epoch _epoch;
};

}

#endif
