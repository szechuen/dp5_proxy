#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>

#include <stdexcept>

#include "dp5regserver.h"

// Allocate a filename given the desired directory, the epoch number,
// and the filename extension.  The caller must free() the result when
// finished.
static char *construct_fname(const char *dir, unsigned int epoch,
    const char *extension)
{
    char *fname = (char *)malloc(strlen(dir) + 1 + 8 + 1 +
				    strlen(extension) + 1);
    if (fname == NULL) throw runtime_error("Cannot allocate filename");

    sprintf(fname, "%s/%08x.%s", dir, epoch, extension);
    return fname;
}

// Create the registration file for the next epoch.
void DP5RegServer::create_nextreg_file()
{
    char *fname = construct_fname(_regdir, _epoch+1, "reg");
    _nextregfd = open(fname, O_CREAT | O_RDWR | O_APPEND, 0600);
    free(fname);

    if (_nextregfd < 0) {
	throw runtime_error("Cannot create registration file");
    }
}

// The constructor consumes the current epoch number, the directory
// in which to store the incoming registrations for the current
// epoch, and the directory in which to store the metadata and data
// files.
DP5RegServer::DP5RegServer(unsigned int current_epoch, const char *regdir,
    const char *datadir) : _epoch(current_epoch)
{
    _regdir = strdup(regdir);
    _datadir = strdup(datadir);

    // Ensure the registration file for the next epoch exists
    create_nextreg_file();
}

// Copy constructor
DP5RegServer::DP5RegServer(const DP5RegServer &other)
{
    _epoch = other._epoch;
    _nextregfd = dup(other._nextregfd);
    _regdir = strdup(other._regdir);
    _datadir = strdup(other._datadir);
}

// Assignment operator
DP5RegServer& DP5RegServer::operator=(DP5RegServer other)
{
    // Swap the fields of the temporary "other" with ours
    // so things get properly freed
    char *tmp = other._regdir;
    other._regdir = _regdir;
    _regdir = tmp;
    tmp = other._datadir;
    other._datadir = _datadir;
    _datadir = tmp;
    
    int fdtmp = other._nextregfd;
    other._nextregfd = _nextregfd;
    _nextregfd = fdtmp;

    _epoch = other._epoch;

    return *this;
}

// Destructor
DP5RegServer::~DP5RegServer()
{
    close(_nextregfd);
    free(_regdir);
    free(_datadir);
}

// When a registration message regmsg is received from a client,
// pass it to this function.  msgtoreply will be filled in with the
// message to return to the client in response.  Client
// registrations will become visible in the *next* epoch.
void DP5RegServer::client_reg(string &msgtoreply, const string &regmsg)
{
    unsigned char err = 0xff;
    unsigned int next_epoch = 0;

    const unsigned char *indata = (const unsigned char *)regmsg.data();
    size_t regmsglen = regmsg.length();
    const unsigned int inrecord_size = SHAREDKEY_BYTES + DATAENC_BYTES;
    const unsigned int outrecord_size = HASHKEY_BYTES + DATAENC_BYTES;
    unsigned int numrecords;

    // Grab a shared lock on the registration file.  This ensures that
    // other threads can add client regisgtrations at the same time, but
    // an epoch change won't happen in the middle.  Once we have the
    // lock, record the epoch number, and it's guaranteed to be correct
    // at that point.
    do {
	int res = flock(_nextregfd, LOCK_SH | LOCK_NB);
	if (res == 0) {
	    // We have the lock
	    next_epoch = _epoch + 1;
	}
	// If we didn't get the lock, try again.  Note that the value of
	// _nextregfd (or which file it points to) may have changed in
	// the meantime.
    } while (next_epoch == 0);

    // From here on, we have a shared lock.  _nextregfd is guaranteed
    // not to change until we release it.

    if (regmsglen % inrecord_size != 0) {
	// The input was not an integer number of records.  Reject it.
	goto client_reg_return;
    }
    numrecords = regmsglen / inrecord_size;

    unsigned char outrecord[outrecord_size];
    unsigned char nextepochbytes[EPOCH_BYTES];
    epoch_num_to_bytes(nextepochbytes, next_epoch);

    for (unsigned int i=0; i<numrecords; ++i) {
	// Hash the key, copy the data
	H3(outrecord, nextepochbytes, indata);
	memmove(outrecord + HASHKEY_BYTES, indata + SHAREDKEY_BYTES,
		DATAENC_BYTES);

	// Append the record to the registration file
	write(_nextregfd, outrecord, outrecord_size);

	indata += inrecord_size;
    }

client_reg_return:

    // Release the lock
    flock(_nextregfd, LOCK_UN);

    // Return the response to the client
    unsigned char resp[1+EPOCH_BYTES];
    resp[0] = err;
    epoch_num_to_bytes(resp+1, next_epoch);
    msgtoreply.assign((char *)resp, 1+EPOCH_BYTES);
}

// Call this when the epoch changes.  Pass in ostreams to which this
// function should write the metadata and data files to serve in
// this epoch.  The function will return the new epoch number.
// After this function returns, send the metadata and data files to
// the PIR servers, labelled with the new epoch number.
unsigned int DP5RegServer::epoch_change(ostream &metadataos, ostream &dataos)
{
    // Grab an exclusive lock on the registration file
    while (1) {
	int res = flock(_nextregfd, LOCK_EX);
	if (res == 0) break;
    } 

    // Now we have the lock
    int workingregfd = _nextregfd;

    // Increment the epoch and create the new reg file
    ++_epoch;
    unsigned int workingepoch = _epoch;
    create_nextreg_file();

    // We can release the lock now
    flock(workingregfd, LOCK_UN);

    // Process the registration file

    // When we're done with the registration file, close it and unlink
    // it
    close(workingregfd);
    char *fname = construct_fname(_regdir, workingepoch, "reg");
    unlink(fname);
    free(fname);

    return workingepoch;
}

#ifdef TEST_RSCONST
// Test the copy constructor and assignment operator (use valgrind to
// check)
int main(int argc, char **argv)
{
    // Ensure the directories exist
    mkdir("regdir", 0700);
    mkdir("datadir", 0700);

    DP5RegServer s(DP5RegServer::current_epoch(), "regdir", "datadir");

    DP5RegServer t(s);

    DP5RegServer u = s;

    u = t;

    return 0;
}
#endif // TEST_RSCONST
