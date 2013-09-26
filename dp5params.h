#ifndef __DP5PARAMS_H__
#define __DP5PARAMS_H__

#include <iostream>
#include <string>
#include <sstream>



///
/// This class contains static (compile-time defined)
/// parameters used in DP5.
///

class DP5Params {
public:
    // The maximum number of clients
    static const unsigned int MAX_CLIENTS = 1000;

    // The mamimum number of buddies per client
    static const unsigned int MAX_BUDDIES = 100;

    // Number of bytes in a private key
    static const unsigned int PRIVKEY_BYTES = 32;

    // Number of bytes in a public key
    static const unsigned int PUBKEY_BYTES = 32;

    // Number of bytes in a shared key
    static const unsigned int SHAREDKEY_BYTES = 10;

    // Number of bytes in a hashed shared key
    static const unsigned int HASHKEY_BYTES = 10;

    // Number of bytes in the key that encrypts the associated data
    static const unsigned int DATAKEY_BYTES = 16;

    // The number of PIR words per byte.  This is 8 for Chor et al.'s
    // super-simple PIR scheme, and 1 for Goldberg's scheme over GF(2^8)
    static const unsigned int PIR_WORDS_PER_BYTE = 1;

    // Number of bytes in a key for the pseudorandom function family
    static const unsigned int PRFKEY_BYTES = 8;
    typedef char PRFKey[PRFKEY_BYTES];

    // The length of a byte-array version of an epoch number
    static const unsigned int EPOCH_BYTES = 4;  // epochs are 32 bit
    typedef unsigned int Epoch;
    typedef char WireEpoch[EPOCH_BYTES];

    // Constructor, which may do things like seed the PRNG
    DP5Params();


    // Place num_bytes random bytes into buf.  This is not static, so that
    // the PRNG can keep state if necessary
    void random_bytes(unsigned char *buf, unsigned int num_bytes);

    // Generate a public/private keypair
    void genkeypair(unsigned char pubkey[PUBKEY_BYTES],
	unsigned char privkey[PRIVKEY_BYTES]);

    // Compute a public key from a private key
    void getpubkey(unsigned char pubkey[PUBKEY_BYTES],
    const unsigned char privkey[PRIVKEY_BYTES]);

    // Compute the Diffie-Hellman output for a given (buddy's) public
    // key and (your own) private key
    void diffie_hellman(unsigned char dh_output[PUBKEY_BYTES],
	const unsigned char my_privkey[PRIVKEY_BYTES],
	const unsigned char their_pubkey[PUBKEY_BYTES]);

    // Hash function H_1 consumes an epoch (of size EPOCH_BYTES bytes)
    // and a Diffie-Hellman output (of size PUBKEY_BYTES) and produces
    // a hash value of size SHAREDKEY_BYTES bytes.  H_2 consumes the
    // same input and produces a hash value of size DATAKEY_BYTES bytes.
    static void H1H2(unsigned char H1_out[SHAREDKEY_BYTES],
	unsigned char H2_out[DATAKEY_BYTES],
	Epoch epoch,
    const unsigned char pubkey[PUBKEY_BYTES],
	const unsigned char dhout[PUBKEY_BYTES]);

    // Hash function H_3 consumes an epoch (of size EPOCH_BYTES bytes)
    // and an output of H1 (of size SHAREDKEY_BYTES bytes), and produces
    // a hash value of size HASHKEY_BYTES bytes.
    static void H3(unsigned char H3_out[HASHKEY_BYTES],
    	Epoch epoch,
    	const unsigned char H1_out[SHAREDKEY_BYTES]);

    // Pseudorandom functions
    class PRF {
    public:
	// The constuctor consumes a key of size PRFKEY_BYTES bytes and
	// a number of buckets (the size of the codomain of the function)
	PRF(const unsigned char prfkey[PRFKEY_BYTES],
	    unsigned int num_buckets);

	// The pseudorandom function M consumes values of size
	// HASHKEY_BYTES bytes, and produces values in
	// {0,1,...,num_buckets-1}
	unsigned int M(const unsigned char x[HASHKEY_BYTES]);

	// A destructor is unnecessary for our implementation
	//~PRF();

    private:
	// Store a copy of the key
	unsigned char _prfkey[PRFKEY_BYTES];

	// Store a copy of the output size
	unsigned int _num_buckets;
    };

    // Encryption and decryption of associated data
    // Each (small) piece of associated data is encrypted with a
    // different key, so keeping key state is unnecessary.

    // Encrypt using a key of size DATAKEY_BYTES bytes a plaintext of size
    // DATAPLAIN_BYTES bytes to yield a ciphertext of size DATAENC_BYTES
    // bytes.
    static string Enc(const unsigned char enckey[DATAKEY_BYTES],
	   const string & plaintext);

    // Decrypt using a key of size DATAKEY_BYTES bytes a ciphertext of
    // size DATAENC_BYTES bytes to yield a plaintext of size
    // DATAPLAIN_BYTES.  Return 0 if the decryption was successful, -1
    // otherwise.
    static int Dec(string & plaintext,
	const unsigned char enckey[DATAKEY_BYTES],
	const string & ciphertext);


    // Convert an epoch number to an epoch byte array
    static void epoch_num_to_bytes(WireEpoch result,
       unsigned int epoch_num);

    // Convert an epoch byte array to an epoch number
    static unsigned int epoch_bytes_to_num(
       const WireEpoch wire_epoch);



    // Destructor, if necessary
    ~DP5Params();
};


// Contains configurable parameters
// for a given database
struct _DP5MetadataStruct : public DP5Params {
public:
    PRFKey prfkey;
    unsigned int dataenc_bytes;
    unsigned int epoch;
    unsigned int epoch_len;
    unsigned int num_buckets;
    unsigned int bucket_size;
    bool usePairings;
};

///
/// This class contains the configurable variables
/// for a database
///
class DP5Metadata : public _DP5MetadataStruct {
public:
    // Number of bytes in an unsigned int representing a size sent
    // over the network. Note that this needs to be > 2 bytes
    // if we want to support an epoch length of 86400s
    static const unsigned int UINT_BYTES = 4;

    // The version number of the metadata file
    static const unsigned int METADATA_VERSION = 0x01;

    /// Initialize from input stream
    DP5Metadata(std::istream & is) {
        readFromStream(is);
    }

    DP5Metadata(const std::string & metadata) {
        fromString(metadata);
    }

    DP5Metadata();  // Sets default values

    // use copy constructor from the struct
    DP5Metadata(const DP5Metadata & other) :
        _DP5MetadataStruct(other) {}

    void readFromStream(std::istream & is);
    void writeToStream(std::ostream & os) const;
    std::string toString(void) const;
    void fromString(const std::string & str);

    static unsigned int read_uint(std::istream & is);
    static void write_uint(std::ostream & os, unsigned int n);
    static unsigned int read_epoch(std::istream & is);
    static void write_epoch(std::ostream & os, unsigned int epoch);

    // Convert an uint number to an uint byte array in network order
    static void uint_num_to_bytes(char uint_bytes[UINT_BYTES],
           unsigned int uint_num);

    // Convert an uint byte array in networkorder to an uint number
    static unsigned int uint_bytes_to_num(
           const char uint_bytes[UINT_BYTES]);

    // Retrieve the current epoch number
    unsigned int current_epoch();
};


#endif
