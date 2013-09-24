#include <sys/types.h>

#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdexcept>


#include <algorithm>
#include "dp5combregclient.h"

// Initialize the client by storing its private key
DP5CombinedRegClient::DP5CombinedRegClient(const unsigned char bls_privkey[PRIVKEY_BYTES], const unsigned char prekey[PREKEY_BYTES]) {  
    _bls_privkey.fromBin((const char *)bls_privkey);
    memmove(this->_prekey,prekey, PREKEY_BYTES);
}

int DP5CombinedRegClient::start_reg(string &msgtosend, unsigned int next_epoch, const unsigned char data[DATAPLAIN_BYTES]) {
    // Determine the target epoch for the registration
    // as the next epoch, and convert to bytes.    
    unsigned char epoch_bytes[EPOCH_BYTES];
    epoch_num_to_bytes(epoch_bytes, next_epoch);
     
    // Add it to front of message
    msgtosend.assign((char *) epoch_bytes, EPOCH_BYTES); 

    // Generate signature on the epoch  
    G2 epoch_hash(_pairing, epoch_bytes, EPOCH_BYTES);
    
    G2 epoch_sig = epoch_hash ^ _bls_privkey; // h(e)^\sigma   
    
    char epoch_sig_bytes[EPOCH_SIG_BYTES];
    epoch_sig.toBin(epoch_sig_bytes);
    
    msgtosend.append(epoch_sig_bytes, EPOCH_SIG_BYTES);

    // Generate the encryption key
    unsigned char data_key[DATAKEY_BYTES];
    H5(data_key, epoch_bytes, _prekey);
                                  
    // Encrypt associated data
    unsigned char ciphertext[DATAENC_BYTES];
    Enc(ciphertext, data_key, data);
    
    msgtosend.append((char *) ciphertext, DATAENC_BYTES);
    
    return 0x00;
}
                       
// FIXME: this is exactly the same as DP5RegClient, refactor
int DP5CombinedRegClient::complete_reg(const string &replymsg, unsigned int next_epoch){
    // check the input length
    if (replymsg.length() != 1+EPOCH_BYTES)
        return 0xFE; // Meaning "wrong input length"
    
    // Parse the message
    unsigned char * buffer = (unsigned char *) replymsg.c_str();
    unsigned char server_err = buffer[0];
    unsigned int server_epoch = epoch_bytes_to_num(buffer + 1);
    
    if (server_err != 0x00)
        return server_err; // Give the client the error number

    
    if (server_epoch != next_epoch)
        return 0xFD; // The server epoch does not match our next epoch. 

    return 0x00; // All is well.
 
}


