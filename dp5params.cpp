#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include <stdexcept>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "dp5params.h"

extern "C" {
    int curve25519_donna(unsigned char *mypublic,
	const unsigned char *secret,
	const unsigned char *basepoint);
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
    const unsigned char E[EPOCH_BYTES],
    const unsigned char dhout[PUBKEY_BYTES])
{
    unsigned char shaout[SHA256_DIGEST_LENGTH];
    SHA256_CTX hash;
    SHA256_Init(&hash);
    SHA256_Update(&hash, "\x00", 1);
    SHA256_Update(&hash, E, EPOCH_BYTES);
    SHA256_Update(&hash, dhout, PUBKEY_BYTES);
    SHA256_Final(shaout, &hash);
    memmove(H1_out, shaout, SHAREDKEY_BYTES);
    memmove(H2_out, shaout+SHA256_DIGEST_LENGTH-DATAKEY_BYTES,
	    DATAKEY_BYTES);
}

// Hash function H_3 consumes the same as above, and produces a hash
// value of size HASHKEY_BYTES bytes.
void DP5Params::H3(unsigned char H3_out[HASHKEY_BYTES],
    const unsigned char E[EPOCH_BYTES],
    const unsigned char dhout[PUBKEY_BYTES])
{
    unsigned char shaout[SHA256_DIGEST_LENGTH];
    SHA256_CTX hash;
    SHA256_Init(&hash);
    SHA256_Update(&hash, "\x01", 1);
    SHA256_Update(&hash, E, EPOCH_BYTES);
    SHA256_Update(&hash, dhout, PUBKEY_BYTES);
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

    unsigned char alice_privkey[DP5Params::PRIVKEY_BYTES];
    unsigned char alice_pubkey[DP5Params::PUBKEY_BYTES];
    unsigned char alice_dh[DP5Params::PUBKEY_BYTES];
    unsigned char bob_privkey[DP5Params::PRIVKEY_BYTES];
    unsigned char bob_pubkey[DP5Params::PUBKEY_BYTES];
    unsigned char bob_dh[DP5Params::PUBKEY_BYTES];

    dp5.genkeypair(alice_pubkey, alice_privkey);
    dump("Alice privkey ", alice_privkey, DP5Params::PRIVKEY_BYTES);
    dump("Alice pubkey  ", alice_pubkey, DP5Params::PUBKEY_BYTES);
    dp5.genkeypair(bob_pubkey, bob_privkey);
    dump("Bob   privkey ", bob_privkey, DP5Params::PRIVKEY_BYTES);
    dump("Bob   pubkey  ", bob_pubkey, DP5Params::PUBKEY_BYTES);
    dp5.diffie_hellman(alice_dh, alice_privkey, bob_pubkey);
    dp5.diffie_hellman(bob_dh, bob_privkey, alice_pubkey);
    dump("Alice DH      ", alice_dh, DP5Params::PUBKEY_BYTES);
    dump("Bob   DH      ", bob_dh, DP5Params::PUBKEY_BYTES);

    if (memcmp(alice_dh, bob_dh, DP5Params::PUBKEY_BYTES)) {
	printf("\nNO MATCH\n");
	return 1;
    }

    printf("\nMATCH\n");
    return 0;
}
#endif // TEST_DH

#ifdef TEST_HASHES
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

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

    unsigned char alice_privkey[DP5Params::PRIVKEY_BYTES];
    unsigned char alice_pubkey[DP5Params::PUBKEY_BYTES];
    unsigned char alice_dh[DP5Params::PUBKEY_BYTES];
    unsigned char bob_privkey[DP5Params::PRIVKEY_BYTES];
    unsigned char bob_pubkey[DP5Params::PUBKEY_BYTES];
    unsigned char bob_dh[DP5Params::PUBKEY_BYTES];
    unsigned char H1[DP5Params::SHAREDKEY_BYTES];
    unsigned char H2[DP5Params::DATAKEY_BYTES];
    unsigned char H3[DP5Params::HASHKEY_BYTES];

    dp5.genkeypair(alice_pubkey, alice_privkey);
    dp5.genkeypair(bob_pubkey, bob_privkey);
    dp5.diffie_hellman(alice_dh, alice_privkey, bob_pubkey);
    dp5.diffie_hellman(bob_dh, bob_privkey, alice_pubkey);
    unsigned int epoch = htonl(time(NULL) / DP5Params::EPOCH_LEN);
    const unsigned char *epoch_bytes = (const unsigned char *)&epoch;
    dump("E ", epoch_bytes, DP5Params::EPOCH_BYTES);
    dump("s ", alice_dh, DP5Params::PUBKEY_BYTES);
    printf("\n");
    dp5.H1H2(H1, H2, epoch_bytes, alice_dh);
    dump("H1", H1, DP5Params::SHAREDKEY_BYTES);
    dump("H2", H2, DP5Params::DATAKEY_BYTES);
    dp5.H3(H3, epoch_bytes, alice_dh);
    dump("H3", H3, DP5Params::HASHKEY_BYTES);

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
	unsigned char key[DP5Params::PRFKEY_BYTES];
	dp5.random_bytes(key, DP5Params::PRFKEY_BYTES);
	prfs[i] = new DP5Params::PRF(key, num_buckets);
    }

    const unsigned int num_inputs = 20;
    for (unsigned int inp=0; inp<num_inputs; ++inp) {
	unsigned char x[DP5Params::HASHKEY_BYTES];
	dp5.random_bytes(x, DP5Params::HASHKEY_BYTES);
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
