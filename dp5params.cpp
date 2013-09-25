#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

#include <stdexcept>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "dp5params.h"

extern "C" {
    int curve25519_donna(unsigned char *mypublic,
	const unsigned char *secret,
	const unsigned char *basepoint);
}

using namespace std;

// default constructor
DP5Metadata::DP5Metadata() {
    memset(prfkey, 0, sizeof(prfkey));
    dataenc_bytes = 0;
    epoch = 0;
    epoch_len = 0;
    usePairings = false;
    num_buckets = 0;
    bucket_size = 0;
}

unsigned int DP5Metadata::read_uint(istream & is) {
    char data[UINT_BYTES];
    is.read(data, UINT_BYTES);
    return uint_bytes_to_num(data);
}

void DP5Metadata::write_uint(ostream & os, unsigned int n) {
    char data[UINT_BYTES];
    uint_num_to_bytes(data, n);
    os.write(data, UINT_BYTES);
}

unsigned int DP5Metadata::read_epoch(istream & is) {
    char data[EPOCH_BYTES];
    is.read(data, EPOCH_BYTES);
    return epoch_bytes_to_num(data);
}

void DP5Metadata::write_epoch(ostream & os, unsigned int epoch) {
    char data[EPOCH_BYTES];
    uint_num_to_bytes(data, epoch);
    os.write(data, EPOCH_BYTES);
}

void DP5Metadata::readFromStream(istream & is) {
    unsigned int version = is.get();
    if (!is) {
        throw runtime_error("Could not read metadata version");
    }
    if (version != METADATA_VERSION) {
        stringstream error;
        error << "Metadata version mismatch: expected " <<
            METADATA_VERSION << ", got " << version;
        throw runtime_error(error.str());
    }
    unsigned int x = is.get();
    if (x == 0) {
        usePairings = false;
    } else if (x == 1) {
        usePairings = true;
    } else {
        // we are not being liberal in what we accept
        // since any other value is almost certainly an error
        stringstream error;
        error << "Unexpected value for usePairings: " << x;
        throw runtime_error(error.str());
    }
    // Read in rest of parameters
    epoch = read_epoch(is);
    dataenc_bytes = read_uint(is);
    epoch_len = read_uint(is);
    num_buckets = read_uint(is);
    bucket_size = read_uint(is);
    is.read(prfkey, sizeof(prfkey));

    if (!is) {
        throw runtime_error("Error reading metadata");
    }
}

void DP5Metadata::fromString(const string & str) {
    stringstream stream(str);
    readFromStream(stream);
}

void DP5Metadata::writeToStream(ostream & os) const {
    os.put(METADATA_VERSION);
    os.put(usePairings);
    write_epoch(os, epoch);
    write_uint(os, dataenc_bytes);
    write_uint(os, epoch_len);
    write_uint(os, num_buckets);
    write_uint(os, bucket_size);
    os.write(prfkey, sizeof(prfkey));
}

string DP5Metadata::toString(void) const {
    stringstream stream;
    writeToStream(stream);
    return stream.str();
}

// Constructor: initialize the PRNG
DP5Params::DP5Params()
{
    unsigned char osrandbuf[32];

    // Grab 32 random bytes from the OS and use it to seed openssl's
    // PRNG.  (openssl actually seeds from /dev/urandom itself on
    // systems with one, but in case we switch to another crypto
    // library, make it explicit.)
    int urandfd = open("/dev/urandom", O_RDONLY);
    if (urandfd < 0) {
	throw runtime_error("Unable to open /dev/urandom");
    }
    int res = read(urandfd, osrandbuf, sizeof(osrandbuf));
    if (res < (int)sizeof(osrandbuf)) {
	throw runtime_error("Unable to read /dev/urandom");
    }
    close(urandfd);
    RAND_seed(osrandbuf, sizeof(osrandbuf));
}

// Do-nothing destructor
DP5Params::~DP5Params() {}

// Place num_bytes random bytes into buf.  This is not static, so that
// the PRNG can keep state if necessary
void DP5Params::random_bytes(unsigned char *buf, unsigned int num_bytes)
{
    RAND_bytes(buf, num_bytes);
}

// Generate a public/private keypair
void DP5Params::genkeypair(unsigned char pubkey[PUBKEY_BYTES],
    unsigned char privkey[PRIVKEY_BYTES])
{
    // The generator
    static const unsigned char generator[32] = {9};

    // Generate a private key
    random_bytes(privkey, PRIVKEY_BYTES);
    privkey[0] &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;

    // Generate the public key
    curve25519_donna(pubkey, privkey, generator);
}

// Generate a public/private keypair
void DP5Params::getpubkey(unsigned char pubkey[PUBKEY_BYTES],
    const unsigned char privkey[PRIVKEY_BYTES])
{
    // The generator
    static const unsigned char generator[32] = {9};

    // Generate the public key
    curve25519_donna(pubkey, privkey, generator);
}

// Compute the Diffie-Hellman output for a given (buddy's) public
// key and (your own) private key
void DP5Params::diffie_hellman(unsigned char dh_output[PUBKEY_BYTES],
    const unsigned char my_privkey[PRIVKEY_BYTES],
    const unsigned char their_pubkey[PUBKEY_BYTES])
{
    curve25519_donna(dh_output, my_privkey, their_pubkey);
}

// Hash function H_1 consumes an epoch (of size EPOCH_BYTES bytes)
// and a Diffie-Hellman output (of size PUBKEY_BYTES) and produces
// a hash value of size SHAREDKEY_BYTES bytes.  H_2 consumes the
// same input and produces a hash value of size DATAKEY_BYTES bytes.
void DP5Params::H1H2(unsigned char H1_out[SHAREDKEY_BYTES],
    unsigned char H2_out[DATAKEY_BYTES],
    Epoch epoch,
    const unsigned char pubkey[PUBKEY_BYTES],
    const unsigned char dhout[PUBKEY_BYTES])
{
    unsigned char shaout[SHA256_DIGEST_LENGTH];
    SHA256_CTX hash;
    SHA256_Init(&hash);
    SHA256_Update(&hash, "\x00", 1);
    WireEpoch wire_epoch;
    epoch_num_to_bytes(wire_epoch, epoch);
    SHA256_Update(&hash, wire_epoch, EPOCH_BYTES);
    SHA256_Update(&hash, pubkey, PUBKEY_BYTES);
    SHA256_Update(&hash, dhout, PUBKEY_BYTES);
    SHA256_Final(shaout, &hash);
    memmove(H1_out, shaout, SHAREDKEY_BYTES);
    memmove(H2_out, shaout+SHA256_DIGEST_LENGTH-DATAKEY_BYTES,
	    DATAKEY_BYTES);
}

// Hash function H_3 consumes an epoch (of size EPOCH_BYTES bytes)
// and an output of H1 (of size SHAREDKEY_BYTES bytes), and produces
// a hash value of size HASHKEY_BYTES bytes.
void DP5Params::H3(unsigned char H3_out[HASHKEY_BYTES],
    Epoch epoch,
    const unsigned char H1_out[SHAREDKEY_BYTES])
{
    unsigned char shaout[SHA256_DIGEST_LENGTH];
    SHA256_CTX hash;
    SHA256_Init(&hash);
    SHA256_Update(&hash, "\x01", 1);
    WireEpoch wire_epoch;
    epoch_num_to_bytes(wire_epoch, epoch);
    SHA256_Update(&hash, wire_epoch, EPOCH_BYTES);
    SHA256_Update(&hash, H1_out, SHAREDKEY_BYTES);
    SHA256_Final(shaout, &hash);
    memmove(H3_out, shaout, HASHKEY_BYTES);
}

// Pseudorandom functions
// The constuctor consumes a key of size PRFKEY_BYTES bytes and
// a number of buckets (the size of the codomain of the function)
DP5Params::PRF::PRF(const unsigned char prfkey[PRFKEY_BYTES],
    unsigned int num_buckets)
{
    memmove(_prfkey, prfkey, PRFKEY_BYTES);
    _num_buckets = num_buckets;
    if (_num_buckets < 1) {
	_num_buckets = 1;
    }
}

// The pseudorandom function M consumes values of size
// HASHKEY_BYTES bytes, and produces values in
// {0,1,...,num_buckets-1}
unsigned int DP5Params::PRF::M(const unsigned char x[HASHKEY_BYTES])
{
    unsigned char shaout[SHA256_DIGEST_LENGTH];
    SHA256_CTX hash;
    SHA256_Init(&hash);
    SHA256_Update(&hash, _prfkey, PRFKEY_BYTES);
    SHA256_Update(&hash, x, HASHKEY_BYTES);
    SHA256_Final(shaout, &hash);

    uint64_t outint = *(uint64_t *)shaout;
    return outint % _num_buckets;
}

// Encryption and decryption of associated data
// Each (small) piece of associated data is encrypted with a
// different key, so keeping key state is unnecessary.

// Encrypt using a key of size DATAKEY_BYTES bytes a plaintext of size
// DATAPLAIN_BYTES bytes to yield a ciphertext of size DATAENC_BYTES
// bytes.
string DP5Params::Enc(
    const unsigned char enckey[DATAKEY_BYTES],
    const string & plaintext)
{
    AES_KEY aeskey;
    AES_set_encrypt_key(enckey, 8*DATAKEY_BYTES, &aeskey);
    if (plaintext.size() != 16) {
        throw runtime_error("Only 128-bit plaintext currently supported");
    }
    unsigned char ciphertext[16];
    AES_encrypt((const unsigned char *) plaintext.data(), ciphertext, &aeskey);

    return string((char *)ciphertext, 16);
}

// Decrypt using a key of size DATAKEY_BYTES bytes a ciphertext of
// size DATAENC_BYTES bytes to yield a plaintext of size
// DATAPLAIN_BYTES.  Return 0 if the decryption was successful, -1
// otherwise.
int DP5Params::Dec(string & plaintext,
    const unsigned char enckey[DATAKEY_BYTES],
    const string & ciphertext)
{
    AES_KEY aeskey;
    if (ciphertext.size() != 16) {
        throw runtime_error("Only 128-bit ciphertext currently supported");
    }
    unsigned char plaintext_bytes[16];
    AES_set_decrypt_key(enckey, 8*DATAKEY_BYTES, &aeskey);
    AES_decrypt((const unsigned char*) ciphertext.data(), plaintext_bytes, &aeskey);
    plaintext.assign((char *) plaintext_bytes, 16);
    return 0;
}

// Retrieve the current epoch number
unsigned int DP5Metadata::current_epoch()
{
    if (epoch_len == 0) {
        throw runtime_error("Zero epoch length!");
    }
    return time(NULL)/epoch_len;
}

// Convert an epoch number to an epoch byte array
void DP5Params::epoch_num_to_bytes(WireEpoch  wire_epoch,
    unsigned int epoch_num)
{
    unsigned int big_endian_epoch_num = htonl(epoch_num);
    memmove(wire_epoch, &big_endian_epoch_num, EPOCH_BYTES);
}

// Convert an epoch byte array to an epoch number
unsigned int DP5Params::epoch_bytes_to_num(const WireEpoch wire_epoch)
{
    return ntohl(*(unsigned int*)wire_epoch);
}

// Convert an uint number to an uint byte array in network order
void DP5Metadata::uint_num_to_bytes(char uint_bytes[UINT_BYTES],
	unsigned int uint_num){
    unsigned int num_netorder = htonl(uint_num);
    memcpy((char *) uint_bytes, ((const char *)&num_netorder)
	    +sizeof(unsigned int)-UINT_BYTES, UINT_BYTES);
}

// Convert an uint byte array in networkorder to an uint number
unsigned int DP5Metadata::uint_bytes_to_num(
	const char uint_bytes[UINT_BYTES]){
    unsigned int res = 0;
    memcpy(((char *)&res) +sizeof(unsigned int)-UINT_BYTES,
        (const char *) uint_bytes, UINT_BYTES);
    res = ntohl(res);
    return res;
}


#ifdef TEST_DH
#include <stdio.h>

static void dump(const char *prefix, const unsigned char *data,
    size_t len)
{
    if (prefix) {
	printf("%s: ", prefix);
    }
    for (size_t i=0; i<len; ++i) {
	printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    DP5Params dp5;

    unsigned char alice_privkey[dp5.PRIVKEY_BYTES];
    unsigned char alice_pubkey[dp5.PUBKEY_BYTES];
    unsigned char alice_dh[dp5.PUBKEY_BYTES];
    unsigned char bob_privkey[dp5.PRIVKEY_BYTES];
    unsigned char bob_pubkey[dp5.PUBKEY_BYTES];
    unsigned char bob_dh[dp5.PUBKEY_BYTES];

    dp5.genkeypair(alice_pubkey, alice_privkey);
    dump("Alice privkey ", alice_privkey, dp5.PRIVKEY_BYTES);
    dump("Alice pubkey  ", alice_pubkey, dp5.PUBKEY_BYTES);
    dp5.genkeypair(bob_pubkey, bob_privkey);
    dump("Bob   privkey ", bob_privkey, dp5.PRIVKEY_BYTES);
    dump("Bob   pubkey  ", bob_pubkey, dp5.PUBKEY_BYTES);
    dp5.diffie_hellman(alice_dh, alice_privkey, bob_pubkey);
    dp5.diffie_hellman(bob_dh, bob_privkey, alice_pubkey);
    dump("Alice DH      ", alice_dh, dp5.PUBKEY_BYTES);
    dump("Bob   DH      ", bob_dh, dp5.PUBKEY_BYTES);

    if (memcmp(alice_dh, bob_dh, dp5.PUBKEY_BYTES)) {
	printf("\nNO MATCH\n");
	return 1;
    }

    printf("\nMATCH\n");
    return 0;
}
#endif // TEST_DH

#ifdef TEST_HASHES
#include <stdio.h>

static void dump(const char *prefix, const unsigned char *data,
    size_t len)
{
    if (prefix) {
	printf("%s: ", prefix);
    }
    for (size_t i=0; i<len; ++i) {
	printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    DP5Metadata dp5;
    dp5.epoch_len = 1800;

    unsigned char alice_privkey[dp5.PRIVKEY_BYTES];
    unsigned char alice_pubkey[dp5.PUBKEY_BYTES];
    unsigned char alice_dh[dp5.PUBKEY_BYTES];
    unsigned char bob_privkey[dp5.PRIVKEY_BYTES];
    unsigned char bob_pubkey[dp5.PUBKEY_BYTES];
    unsigned char bob_dh[dp5.PUBKEY_BYTES];
    unsigned char H1[dp5.SHAREDKEY_BYTES];
    unsigned char H2[dp5.DATAKEY_BYTES];
    unsigned char H3[dp5.HASHKEY_BYTES];

    dp5.genkeypair(alice_pubkey, alice_privkey);
    dp5.genkeypair(bob_pubkey, bob_privkey);
    dp5.diffie_hellman(alice_dh, alice_privkey, bob_pubkey);
    dp5.diffie_hellman(bob_dh, bob_privkey, alice_pubkey);
    unsigned int epoch = dp5.current_epoch();
    printf("e : %d (%08x)\n", epoch, epoch);
    dump("s ", alice_dh, dp5.PUBKEY_BYTES);
    printf("\n");
    dp5.H1H2(H1, H2,epoch, alice_pubkey, alice_dh);
    dump("H1", H1, dp5.SHAREDKEY_BYTES);
    dump("H2", H2, dp5.DATAKEY_BYTES);
    dp5.H3(H3, epoch, H1);
    dump("H3", H3, dp5.HASHKEY_BYTES);

    return 0;
}
#endif // TEST_HASHES

#ifdef TEST_PRF
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    DP5Params dp5;
    unsigned int num_buckets = (argc > 1 ? atoi(argv[1]) : 10);

    const unsigned int num_prfs = 5;
    DP5Params::PRF *prfs[num_prfs];

    for (unsigned int i=0; i<num_prfs; ++i) {
	unsigned char key[dp5.PRFKEY_BYTES];
	dp5.random_bytes(key, dp5.PRFKEY_BYTES);
	prfs[i] = new DP5Params::PRF(key, num_buckets);
    }

    const unsigned int num_inputs = 20;
    for (unsigned int inp=0; inp<num_inputs; ++inp) {
	unsigned char x[dp5.HASHKEY_BYTES];
	dp5.random_bytes(x, dp5.HASHKEY_BYTES);
	for (unsigned int p=0; p<num_prfs; ++p) {
	    printf("%u\t", prfs[p]->M(x));
	}
	printf("\n");
    }

    for (unsigned int i=0; i<num_prfs; ++i) {
	delete prfs[i];
    }

    return 0;
}
#endif // TEST_PRF

#ifdef TEST_ENC
#include <stdio.h>

static void dump(const char *prefix, const unsigned char *data,
    size_t len)
{
    if (prefix) {
	printf("%s: ", prefix);
    }
    for (size_t i=0; i<len; ++i) {
	printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    DP5Params dp5;

    const unsigned int DATAPLAIN_BYTES = 16;
    const unsigned int DATAENC_BYTES = 16;

    unsigned char key1[dp5.DATAKEY_BYTES];
    unsigned char key2[dp5.DATAKEY_BYTES];

    dp5.random_bytes(key1, dp5.DATAKEY_BYTES);
    dp5.random_bytes(key2, dp5.DATAKEY_BYTES);
    dump("Key 1  ", key1, dp5.DATAKEY_BYTES);
    dump("Key 2  ", key2, dp5.DATAKEY_BYTES);

    string plain1, plain2;
    for (unsigned int i=0; i<DATAPLAIN_BYTES; ++i) {
	plain1.push_back('A' + i);
	plain2.push_back('0' + i);
    }
    dump("\nPlain 1", (const unsigned char *) plain1.data(), DATAPLAIN_BYTES);
    dump("Plain 2", (const unsigned char *) plain2.data(), DATAPLAIN_BYTES);

    string cipher11, cipher12, cipher21, cipher22;
    cipher11 = dp5.Enc(key1, plain1);
    cipher12 = dp5.Enc(key1, plain2);
    cipher21 = dp5.Enc(key2, plain1);
    cipher22 = dp5.Enc(key2, plain2);
    dump("\nCip 1/1", (const unsigned char *) cipher11.data(), DATAENC_BYTES);
    dump("Cip 1/2", (const unsigned char *) cipher12.data(), DATAENC_BYTES);
    dump("Cip 2/1", (const unsigned char *) cipher21.data(), DATAENC_BYTES);
    dump("Cip 2/2", (const unsigned char *) cipher22.data(), DATAENC_BYTES);

    string dec11, dec12, dec21, dec22;
    int res11 = dp5.Dec(dec11, key1, cipher11);
    int res12 = dp5.Dec(dec12, key1, cipher12);
    int res21 = dp5.Dec(dec21, key2, cipher21);
    int res22 = dp5.Dec(dec22, key2, cipher22);
    printf("\n(%d) ", res11); dump("Dec 1/1", (const unsigned char *) dec11.data(), DATAPLAIN_BYTES);
    printf("(%d) ", res12); dump("Dec 1/2", (const unsigned char *) dec12.data(), DATAPLAIN_BYTES);
    printf("(%d) ", res21); dump("Dec 2/1", (const unsigned char *) dec21.data(), DATAPLAIN_BYTES);
    printf("(%d) ", res22); dump("Dec 2/2", (const unsigned char *) dec22.data(), DATAPLAIN_BYTES);

    return 0;
}
#endif // TEST_ENC

#ifdef TEST_EPOCH
#include <stdio.h>
static void dump(const char *prefix, const char *data,
    size_t len)
{
    if (prefix) {
	printf("%s: ", prefix);
    }
    for (size_t i=0; i<len; ++i) {
	printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    DP5Metadata dp5;
    dp5.epoch_len = 1800;

    unsigned int epoch = dp5.current_epoch();
    printf("Epoch = %u\n", epoch);
    char epoch_bytes[dp5.EPOCH_BYTES];
    dp5.epoch_num_to_bytes(epoch_bytes, epoch);
    dump("E", epoch_bytes, dp5.EPOCH_BYTES);
    unsigned int back;
    back = dp5.epoch_bytes_to_num(epoch_bytes);
    printf("Back  = %u\n", back);
    if (back != epoch) {
	printf("NO MATCH\n");
	return 1;
    } else {
	printf("MATCH\n");
    }

    dp5.epoch_num_to_bytes(epoch_bytes, 0x12345678);
    if (memcmp(epoch_bytes, "\x12\x34\x56\x78", 4)) {
	printf("Epoch conversion failed\n");
	return 1;
    }
    if (dp5.epoch_bytes_to_num(epoch_bytes) != 0x12345678) {
	printf("Epoch reverse conversion failed\n");
	return 1;
    }

    // Abuse this test case to also test the conversions
    // between uint and bytes.
    unsigned int test_uint = 0x5678;
    char uint_bytes[dp5.UINT_BYTES];
    dp5.uint_num_to_bytes(uint_bytes, test_uint);
    unsigned int res = dp5.uint_bytes_to_num(uint_bytes);
    if (res != 0x5678){
    printf("UINT conversion failed\n");
	return 1;
    }


    printf("\nConversions successful\n");

    return 0;
}
#endif // TEST_EPOCH
