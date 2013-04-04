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

// Create the registration file for the given epoch.
void DP5RegServer::create_nextreg_file(unsigned int useepoch)
{
    char *fname = construct_fname(_regdir, useepoch, "reg");
    int fd = open(fname, O_CREAT | O_RDWR | O_APPEND, 0600);
    free(fname);

    if (fd < 0) {
	perror("open");
	throw runtime_error("Cannot create registration file");
    }

    close(fd);
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
    create_nextreg_file(_epoch+1);
}

// Copy constructor
DP5RegServer::DP5RegServer(const DP5RegServer &other)
{
    _epoch = other._epoch;
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
    
    _epoch = other._epoch;

    return *this;
}

// Destructor
DP5RegServer::~DP5RegServer()
{
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

    const unsigned char *allindata = (const unsigned char *)regmsg.data();
    const unsigned int inrecord_size = SHAREDKEY_BYTES + DATAENC_BYTES;
    const unsigned int outrecord_size = HASHKEY_BYTES + DATAENC_BYTES;

    unsigned int numrecords;
    const unsigned char *indata;
    size_t regmsglen;
    unsigned int client_next_epoch;

    // Grab a shared lock on the registration file.  This ensures that
    // other threads can add client regisgtrations at the same time, but
    // an epoch change won't happen in the middle.  Once we have the
    // lock, record the epoch number, and it's guaranteed to be correct
    // at that point.
    int lockedfd = -1;
    do {
	unsigned int my_next_epoch = _epoch + 1;
	char *fname = construct_fname(_regdir, my_next_epoch, "reg");
	if (lockedfd >= 0) {
	    close(lockedfd);
	}
	lockedfd = open(fname, O_WRONLY | O_APPEND);
	free(fname);
	if (lockedfd < 0) {
	    continue;
	}
	int res = flock(lockedfd, LOCK_SH | LOCK_NB);
	if (res == 0) {
	    // We have the lock
	    next_epoch = my_next_epoch;
	}
	// If we didn't get the lock, try again.  Note that the value of
	// _epoch may have changed in the meantime.
    } while (next_epoch == 0);
    //printf("Locked %d SH\n", lockedfd);

    // From here on, we have a shared lock.  _epoch is guaranteed not to
    // change until we release it.



    // Check the input lengths
    if (regmsg.length() < EPOCH_BYTES) {
        err = 0x01; // Message too small
        goto client_reg_return;
    }

    // Now we are sure the data is long enough to parse a client epoch.
    indata = allindata + EPOCH_BYTES;
    regmsglen = regmsg.length() - EPOCH_BYTES;
    client_next_epoch = epoch_bytes_to_num(allindata);

    if (client_next_epoch != next_epoch) {
        err = 0x02; // Epochs of client and server not in sync.
        goto client_reg_return; 
    }

    if (regmsglen % inrecord_size != 0) {
	    // The input was not an integer number of records.  Reject it.
        err = 0x03;
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
	write(lockedfd, outrecord, outrecord_size);

	indata += inrecord_size;
    }

    // We're done.  Indicate success.
    err = 0x00;

client_reg_return:

    // Release the lock
    //printf("Unlocking %d\n", lockedfd);
    flock(lockedfd, LOCK_UN);
    close(lockedfd);

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
    int lockedfd = -1;
    char *oldfname = NULL;
    while (1) {
	free(oldfname);
	oldfname = construct_fname(_regdir, _epoch + 1, "reg");
	if (lockedfd >= 0) {
	    close(lockedfd);
	}
	lockedfd = open(oldfname, O_RDONLY);
	if (lockedfd < 0) {
	    continue;
	}
	int res = flock(lockedfd, LOCK_EX);
	if (res == 0) break;
    } 
    printf("Locked %d EX\n", lockedfd);

    // Now we have the lock

    // Rename the old file
    char *newfname = construct_fname(_regdir, _epoch + 1, "sreg");
    rename(oldfname, newfname);
    free(oldfname);

    // Increment the epoch and create the new reg file
    unsigned int workingepoch = _epoch+1;
    create_nextreg_file(workingepoch+1);
    _epoch = workingepoch;

    // We can release the lock now
    printf("Unlocking %d\n", lockedfd);
    flock(lockedfd, LOCK_UN);

    // Process the registration file from lockedfd

    // When we're done with the registration file, close it and unlink
    // it
    close(lockedfd);
    //unlink(newfname);
    free(newfname);

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

#ifdef TEST_RSREG
#include <vector>

// Test client registration, especially the thread safety

static DP5RegServer *rs = NULL;

static void *client_reg_thread(void *strp)
{
    string res;
    string *data = (string *)strp;
    rs->client_reg(res, *data);
    printf("%02x %08x\n", res.data()[0], *(unsigned int*)(res.data()+1));
    return NULL;
}

static void *epoch_change_thread(void *none)
{
    rs->epoch_change(cout, cout);
    return NULL;
}

// Use hexdump -e '10/1 "%02x" " " 1/16 "%s" "\n"' to view the output
int main(int argc, char **argv)
{
    int num_clients = (argc > 1 ? atoi(argv[1]) : 10);
    int num_buddies = (argc > 2 ? atoi(argv[2]) : DP5Params::MAX_BUDDIES);
    int multithread = 1;

    // Ensure the directories exist
    mkdir("regdir", 0700);
    mkdir("datadir", 0700);

    rs = new DP5RegServer(DP5RegServer::current_epoch(), "regdir", "datadir");

    // Create the blocks of data to submit
    vector<string> submits[2];

    for (int subflag=0; subflag<2; ++subflag) {
	for (int i=0; i<num_clients; ++i) {
	    size_t datasize = num_buddies *
		(rs->SHAREDKEY_BYTES + rs->DATAENC_BYTES);
	    unsigned char data[datasize];
	    unsigned char *thisdata = data;
        
        rs->epoch_num_to_bytes(thisdata,rs->current_epoch()+1);
        thisdata += rs->EPOCH_BYTES;

	    for (int j=0; j<num_buddies; ++j) {
		// Random key
		rs->random_bytes(thisdata, rs->SHAREDKEY_BYTES);
		// Identifiable data
		thisdata[rs->SHAREDKEY_BYTES] = '[';
		thisdata[rs->SHAREDKEY_BYTES+1] = 'P'+subflag;
		thisdata[rs->SHAREDKEY_BYTES+2] = '0'+i;
		int bytesout;
		sprintf((char *)thisdata+rs->SHAREDKEY_BYTES+3, "%u%n",
		    j, &bytesout);
		memset(thisdata+rs->SHAREDKEY_BYTES+3+bytesout,
			' ', rs->DATAENC_BYTES-4-bytesout);
		thisdata[rs->SHAREDKEY_BYTES+rs->DATAENC_BYTES-1]
		    = ']';

		thisdata += rs->SHAREDKEY_BYTES + rs->DATAENC_BYTES;
	    }
	    submits[subflag].push_back(string((char *)data, datasize));
	}
    }

    vector<pthread_t> children;

    for (int subflag=0; subflag<2; ++subflag) {
	for (int i=0; i<num_clients; ++i) {
	    if (multithread) {
		pthread_t thr;
		pthread_create(&thr, NULL, client_reg_thread,
				&submits[subflag][i]);
		children.push_back(thr);
	    } else {
		client_reg_thread(&submits[subflag][i]);
	    }
	}
	if (subflag == 0) {
	    if (multithread) {
		pthread_t thr;
		pthread_create(&thr, NULL, epoch_change_thread, NULL);
		children.push_back(thr);
	    } else {
		epoch_change_thread(NULL);
	    }
	}
    }

    int numchildren = children.size();
    for (int i=0; i<numchildren; ++i) {
	pthread_join(children[i], NULL);
    }

    delete rs;

    return 0;
}
#endif // TEST_RSREG
