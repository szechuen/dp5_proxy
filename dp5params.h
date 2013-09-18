#ifndef __DP5PARAMS_H__
#define __DP5PARAMS_H__

using namespace std;

class DP5Params {
public:
    // The maximum number of clients
    static const unsigned int MAX_CLIENTS = 1000;

    // The mamimum number of buddies per client
    static const unsigned int MAX_BUDDIES = 100;

    // The number of PIR servers
    static const unsigned int NUM_PIRSERVERS = 5;

    // Number of bytes in a private key
    static const unsigned int PRIVKEY_BYTES = 32;  

    // Number of bytes in a BLS private key (element of Z_R)
    static const unsigned int BLS_PRIVKEY_BYTES = 32;  
    
    // Number of bytes in a shared encryption derivation key
    static const unsigned int PREKEY_BYTES = 16;

    // Number of bytes in a public key
    static const unsigned int PUBKEY_BYTES = 32;

    // The length of an epoch (in seconds)
    static const unsigned int EPOCH_LEN = 1800; // 30 minutes

    // Number of bytes in a shared key
    static const unsigned int SHAREDKEY_BYTES = 10;  
    
    // Number of bytes in an epoch signature (element of G2)
    static const unsigned int EPOCH_SIG_BYTES = 128; 
    
    // Number of bytes in a verified signature (element of GT)
    static const unsigned int SIG_VERIFY_BYTES = 384; 

    // Number of bytes in a hashed shared key
    static const unsigned int HASHKEY_BYTES = 10;

    // Number of bytes in associated data (plaintext)
    static const unsigned int DATAPLAIN_BYTES = 16;

    // Number of bytes in encrypted associated data (ciphertext)
    static const unsigned int DATAENC_BYTES = 16;
    
    // Number of bytes in the key that encrypts the associated data
    static const unsigned int DATAKEY_BYTES = 16;

    // The number of PIR words per byte.  This is 8 for Chor et al.'s
    // super-simple PIR scheme, and 1 for Goldberg's scheme over GF(2^8)
    static const unsigned int PIR_WORDS_PER_BYTE = 1;

    // Number of bytes in a key for the pseudorandom function family
    static const unsigned int PRFKEY_BYTES = 8;

    // Number of bytes in an unsigned int representing a size sent
    // over the network
    static const unsigned int UINT_BYTES = 2;

    // The version number of the metadata file
    static const unsigned int METADATA_VERSION = 0x01;

    // The length of a byte-array version of an epoch number
    static const unsigned int EPOCH_BYTES = 4;

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
	const unsigned char E[EPOCH_BYTES],
    const unsigned char pubkey[PUBKEY_BYTES],
	const unsigned char dhout[PUBKEY_BYTES]);

    // Hash function H_3 consumes an epoch (of size EPOCH_BYTES bytes)
    // and an output of H1 (of size SHAREDKEY_BYTES bytes), and produces
    // a hash value of size HASHKEY_BYTES bytes.
    static void H3(unsigned char H3_out[HASHKEY_BYTES],
	const unsigned char E[EPOCH_BYTES],
	const unsigned char H1_out[SHAREDKEY_BYTES]);  
	                                                       
    // Hash function H_4 consumes a pairing computation from the BLS 
    // protocol and produces a hash value of size HASHKEY_BYTES bytes
    static void H4(unsigned char H4_out[HASHKEY_BYTES],
        const unsigned char verifybytes[SIG_VERIFY_BYTES]);   
                                                  
    // Hash function H_4 consumed an epoch and a shared key derivation
    // key and returns a hash value of size DATAKEY_BYTES
    static void H5(unsigned char H5_out[DATAKEY_BYTES],
        const unsigned char E[EPOCH_BYTES],
        const unsigned char prekey[PREKEY_BYTES]);  
        
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
    static void Enc(unsigned char ciphertext[DATAENC_BYTES],
	const unsigned char enckey[DATAKEY_BYTES],
	const unsigned char plaintext[DATAPLAIN_BYTES]);

    // Decrypt using a key of size DATAKEY_BYTES bytes a ciphertext of
    // size DATAENC_BYTES bytes to yield a plaintext of size
    // DATAPLAIN_BYTES.  Return 0 if the decryption was successful, -1
    // otherwise.
    static int Dec(unsigned char plaintext[DATAPLAIN_BYTES],
	const unsigned char enckey[DATAKEY_BYTES],
	const unsigned char ciphertext[DATAENC_BYTES]);

    // Retrieve the current epoch number
    static unsigned int current_epoch();

    // Convert an epoch number to an epoch byte array
    static void epoch_num_to_bytes(unsigned char epoch_bytes[EPOCH_BYTES],
	unsigned int epoch_num);

    // Convert an epoch byte array to an epoch number
    static unsigned int epoch_bytes_to_num(
	const unsigned char epoch_bytes[EPOCH_BYTES]);

    // Convert an uint number to an uint byte array in network order
    static void uint_num_to_bytes(unsigned char uint_bytes[UINT_BYTES],
	    unsigned int uint_num);

    // Convert an uint byte array in networkorder to an uint number
    static unsigned int uint_bytes_to_num(
	    const unsigned char uint_bytes[UINT_BYTES]);

    // Destructor, if necessary
    ~DP5Params();
};

#endif
