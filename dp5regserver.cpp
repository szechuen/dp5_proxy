#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <stdint.h>
#include <math.h>

#include <iostream>
#include <fstream>
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

// Compare two registration records for use in qsort
static int cmprecords(const void *a, const void *b)
{
    return memcmp(a, b,
		DP5RegServer::HASHKEY_BYTES + DP5RegServer::DATAENC_BYTES);
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
    unsigned int recordsize = HASHKEY_BYTES + DATAENC_BYTES;

    struct stat regst;
    int res = fstat(lockedfd, &regst);
    if (res < 0) {
	throw runtime_error("Cannot stat registration file");
    }
    size_t toread = regst.st_size;
    if (toread % recordsize != 0) {
	throw runtime_error("Corrupted registration file");
    }
    unsigned int numrecords = toread / recordsize;
    unsigned char *regdata = new unsigned char[toread];
    if (!regdata) {
	throw runtime_error("Out of memory reading registration file");
    }
    unsigned char *regptr = regdata;

    // Read the whole file
    while (toread > 0) {
	res = read(lockedfd, regptr, toread);
	if (res <= 0) {
	    delete[] regdata;
	    if (res < 0) {
		perror("reading registration file");
	    }
	    throw runtime_error("Error reading registration file");
	}
	regptr += res;
	toread -= res;
    }

    // When we're done with the registration file, close it and unlink
    // it
    close(lockedfd);
    // For debugging purposes, don't actually unlink it for now
    //unlink(newfname);
    free(newfname);

    // Sort the entries in the registration file
    qsort(regdata, numrecords, recordsize, cmprecords);

    // Extract the ones with unique hashed keys
    unsigned char *uniqrecs = new unsigned char[numrecords * recordsize];
    if (!uniqrecs) {
	delete[] regdata;
	throw runtime_error("Out of memory uniqifying registration file");
    }
    unsigned char *uniqptr = uniqrecs;
    unsigned int uniqcnt = 0;
    for (unsigned int i=0; i<numrecords; ++i) {
	if (i==0 || memcmp(regdata+(i-1)*recordsize, regdata+i*recordsize,
			    HASHKEY_BYTES)) {
	    memmove(uniqptr, regdata+i*recordsize,
		    HASHKEY_BYTES + DATAENC_BYTES);
	    uniqptr += HASHKEY_BYTES + DATAENC_BYTES;
	    uniqcnt++;
	}
    }
    delete[] regdata;

    // Now we're going to use a pseudorandom function (PRF) to partition
    // the hashed keys into buckets.

    // Compute the number of PRF buckets we want to have
    unsigned int ostensible_numkeys = 0 * MAX_CLIENTS * MAX_BUDDIES;
    if (uniqcnt > ostensible_numkeys) {
	ostensible_numkeys = uniqcnt;
    }
    uint64_t datasize = ostensible_numkeys *
			(HASHKEY_BYTES + DATAENC_BYTES) *
			PIR_WORDS_PER_BYTE;
    unsigned int num_buckets = (unsigned int)ceil(sqrt((double)datasize));

    // Try NUM_PRF_ITERS random PRF keys and see which one results in
    // the smallest largest bucket.
    unsigned char best_prfkey[PRFKEY_BYTES];
    unsigned int best_size = uniqcnt+1;
    for (unsigned int iter=0; iter<NUM_PRF_ITERS; ++iter) {
	unsigned long count[num_buckets];
	memset(count, 0, sizeof(count));
	unsigned long largest_bucket_size = 0;
	unsigned char prfkey[PRFKEY_BYTES];
	random_bytes(prfkey, PRFKEY_BYTES);
	PRF prf(prfkey, num_buckets);
	uniqptr = uniqrecs;
	for (unsigned long k=0; k<uniqcnt && largest_bucket_size < best_size;
		++k) {
	    unsigned int bucket = prf.M(uniqptr);
	    uniqptr += HASHKEY_BYTES + DATAENC_BYTES;
	    count[bucket] += 1;
	    if (count[bucket] > largest_bucket_size) {
		largest_bucket_size = count[bucket];
	    }
	}

	if (largest_bucket_size < best_size) {
	    memmove(best_prfkey, prfkey, PRFKEY_BYTES);
	    best_size = largest_bucket_size;
	}
    }

    cerr << num_buckets << " " << best_size << "*" << (HASHKEY_BYTES + DATAENC_BYTES) << "=" << (best_size*(HASHKEY_BYTES + DATAENC_BYTES)) << "\n";

    unsigned char *datafile =
	new unsigned char[num_buckets*best_size*(HASHKEY_BYTES+DATAENC_BYTES)];
    if (!datafile) {
	delete[] uniqrecs;
	throw runtime_error("Out of memory allocating data file");
    }
    memset(datafile, 0xff,
	num_buckets*best_size*(HASHKEY_BYTES+DATAENC_BYTES));
    unsigned long count[num_buckets];
    memset(count, 0, sizeof(count));
    PRF prf(best_prfkey, num_buckets);
    uniqptr = uniqrecs;
    for (unsigned long k=0; k<uniqcnt; ++k) {
	unsigned int bucket = prf.M(uniqptr);
	if (count[bucket] >= best_size) {
	    delete[] uniqrecs;
	    delete[] datafile;
	    cerr << bucket << " " << count[bucket] << " " << best_size << "\n";
	    throw runtime_error("Inconsistency creating buckets");
	}
	memmove(datafile+bucket*(best_size*(HASHKEY_BYTES+DATAENC_BYTES))
		+ count[bucket]*(HASHKEY_BYTES+DATAENC_BYTES),
		uniqptr, HASHKEY_BYTES+DATAENC_BYTES);
	count[bucket] += 1;
	uniqptr += HASHKEY_BYTES + DATAENC_BYTES;
    }
    delete[] uniqrecs;

    metadataos.write((const char *)best_prfkey, PRFKEY_BYTES);
    metadataos.write((const char *)&num_buckets, UINT_BYTES);
    metadataos.write((const char *)&best_size, UINT_BYTES);
    metadataos.flush();

    dataos.write((const char *)datafile,
	    num_buckets*best_size*(HASHKEY_BYTES+DATAENC_BYTES));
    dataos.flush();

    delete[] datafile;
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
    printf("%02x %08x %08x\n", res.data()[0],
	*(unsigned int*)(data->data()), *(unsigned int*)(res.data()+1));
    return NULL;
}

static void *epoch_change_thread(void *none)
{
    ofstream md("metadata.out");
    ofstream d("data.out");
    rs->epoch_change(md, d);
    d.close();
    md.close();
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
    unsigned int epoch = rs->current_epoch();

    // Create the blocks of data to submit
    vector<string> submits[2];

    for (int subflag=0; subflag<2; ++subflag) {
	for (int i=0; i<num_clients; ++i) {
	    size_t datasize = rs->EPOCH_BYTES + num_buddies *
		(rs->SHAREDKEY_BYTES + rs->DATAENC_BYTES);
	    unsigned char data[datasize];
	    unsigned char *thisdata = data;
        
	    rs->epoch_num_to_bytes(thisdata,epoch+1+subflag);
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
