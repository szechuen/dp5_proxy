#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

#include <stdexcept>
#include <iostream>
#include <sstream>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "dp5params.h"
#include "dp5metadata.h"

using namespace std;

namespace dp5 {

namespace internal {

Metadata::Metadata() : epoch(0), num_buckets(0), bucket_size (0) {
    memset(prfkey, 0, sizeof(prfkey));
}

Metadata::Metadata(const DP5Config & config) : DP5Config(config),
    epoch(0), num_buckets(0), bucket_size(0) {
    memset(prfkey, 0, sizeof(prfkey));
}

Metadata::Metadata(const Metadata & other) :
    DP5Config(other), epoch(other.epoch), num_buckets(other.num_buckets),
    bucket_size(other.bucket_size)
{
    memcpy(prfkey, other.prfkey, sizeof(prfkey));
}

unsigned int read_uint(istream & is) {
    unsigned char data[UINT_BYTES];
    is.read((char *) data, UINT_BYTES);
    return uint_bytes_to_num(data);
}

void write_uint(ostream & os, unsigned int n) {
    unsigned char data[UINT_BYTES];
    uint_num_to_bytes(data, n);
    os.write((char *) data, UINT_BYTES);
}

unsigned int read_epoch(istream & is) {
    unsigned char data[EPOCH_BYTES];
    is.read((char *) data, EPOCH_BYTES);
    return epoch_bytes_to_num(data);
}

void write_epoch(ostream & os, unsigned int epoch) {
    unsigned char data[EPOCH_BYTES];
    uint_num_to_bytes(data, epoch);
    os.write((char *) data, EPOCH_BYTES);
}

int Metadata::fromStream(istream & is) {
    ios::iostate exceptions = is.exceptions();
    is.exceptions(ios::eofbit | ios::failbit | ios::badbit);
    try {
        unsigned int version = is.get();
        if (version != METADATA_VERSION) {
            return 0x01;
        }
        unsigned int x = is.get();
        if (x == 0) {
            combined = false;
        } else if (x == 1) {
            combined = true;
        } else {
            // we are not being liberal in what we accept
            // since any other value is almost certainly an error
            return 0x02;
        }
        // Read in rest of parameters
        epoch = read_epoch(is);
        dataenc_bytes = read_uint(is);
        epoch_len = read_uint(is);
        num_buckets = read_uint(is);
        bucket_size = read_uint(is);
        is.read((char *) prfkey, sizeof(prfkey));
        is.exceptions(exceptions);
    } catch (ios::failure f) {
        return 0x03;
    }
    return 0;
}

int Metadata::fromString(const string & s) {
    stringstream stream(s);

    return fromStream(stream);
}

// Convert an uint number to an uint byte array in network order
void uint_num_to_bytes(unsigned char uint_bytes[UINT_BYTES], unsigned int uint_num) {
    unsigned int num_netorder = htonl(uint_num);
    memcpy((char *) uint_bytes, ((const char *)&num_netorder)
        +sizeof(unsigned int)-UINT_BYTES, UINT_BYTES);
}

// Convert an uint byte array in networkorder to an uint number
unsigned int uint_bytes_to_num(const unsigned char uint_bytes[UINT_BYTES]) {
    unsigned int res = 0;
    memcpy(((char *)&res) +sizeof(unsigned int)-UINT_BYTES,
        (const char *) uint_bytes, UINT_BYTES);
    res = ntohl(res);
    return res;
}

void Metadata::toStream(ostream & os) const {
    os.put(METADATA_VERSION);
    os.put(combined);
    write_epoch(os, epoch);
    write_uint(os, dataenc_bytes);
    write_uint(os, epoch_len);
    write_uint(os, num_buckets);
    write_uint(os, bucket_size);
    os.write((char *) prfkey, sizeof(prfkey));
}

string Metadata::toString() const {
    stringstream stream;
    toStream(stream);
    return stream.str();
}

Metadata::Metadata(istream & is) {
    if (fromStream(is) != 0)
        throw runtime_error("Error constructing Metadata from stream");
}

Metadata::Metadata(const string & s) {
    if (fromString(s) != 0)
        throw runtime_error("Error constructing Metadata from string");
}

} // namespace dp5::internal

} // namespace dp5


