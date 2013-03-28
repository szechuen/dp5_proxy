#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdexcept>

#include <openssl/rand.h>

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

#ifdef TEST_DH
#include <stdio.h>
#include <string.h>

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
