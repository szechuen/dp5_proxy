#include <sys/types.h>

#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdexcept>


#include <algorithm>
#include "dp5regclient.h"

// Initialize the client by storing its private key
DP5RegClient::DP5RegClient(const unsigned char privkey[PRIVKEY_BYTES]){
    memmove(this->_privkey,privkey, PRIVKEY_BYTES);
}

int DP5RegClient::start_reg(string &msgtosend, const vector<BuddyInfo> &buddies){
    
    // Check inputs
    if (buddies.size() > DP5Params::MAX_BUDDIES)
        return 0x01; // Number of buddies exceeds maximum.

    DP5Params params;

    // Determine the target epoch for the registration
    // as the next epoch, and convert to bytes.
    unsigned int next_epoch = params.current_epoch() + 1;
    unsigned char epoch_bytes[DP5Params::EPOCH_BYTES];
    params.epoch_num_to_bytes(epoch_bytes, next_epoch);

    // Placeholder for the output message
    size_t record_length = DP5Params::SHAREDKEY_BYTES+DP5Params::DATAENC_BYTES;
    unsigned char out_data[DP5Params::MAX_BUDDIES][record_length];
    vector<string> to_sort;

    // For each real buddy
    for(unsigned int i = 0; i < buddies.size(); i++)
    {
        string s;
        const BuddyInfo& current_buddy = buddies[i];

        // Get the long terms hsared DH key
        unsigned char shared_dh_secret[DP5Params::PUBKEY_BYTES];
        params.diffie_hellman(shared_dh_secret, this->_privkey, current_buddy.pubkey);

        // Derive the epoch keys 
        unsigned char* shared_key = out_data[i];
        unsigned char data_key[DP5Params::DATAKEY_BYTES];
        DP5Params::H1H2(shared_key, data_key, epoch_bytes, shared_dh_secret);

        // Encrypt the associated data
        unsigned char* ciphertext = out_data[i] + (DP5Params::SHAREDKEY_BYTES);
        params.Enc(ciphertext, data_key, current_buddy.data);
        s.assign((char*) out_data[i], record_length);
        to_sort.push_back(s);        
    }
    
    // Now pad the end of the array with random entries
    for(unsigned int i = buddies.size(); i < DP5Params::MAX_BUDDIES; i++)
    {
        string s;
        unsigned char* shared_key = out_data[i];
        unsigned char* ciphertext = out_data[i] + DP5Params::SHAREDKEY_BYTES;
        random_bytes(shared_key, DP5Params::SHAREDKEY_BYTES);
        random_bytes(ciphertext, DP5Params::DATAENC_BYTES);
        s.assign((char*)out_data[i], record_length);
        to_sort.push_back(s);
    }    

    // Sort the records and construct the message
    msgtosend.assign("", 0);
    sort(to_sort.begin(), to_sort.end());
    for (unsigned int i = 0 ; i < DP5Params::MAX_BUDDIES; i++){
       msgtosend += to_sort[i]; 
    }

    // msgtosend.assign((char *)out_data, DP5Params::MAX_BUDDIES*(record_length));
    return 0x00;
}


#ifdef TEST_CLIENT
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
    
    // Make up a client
    unsigned char client_privkey[dp5.PRIVKEY_BYTES];
    unsigned char client_pubkey[dp5.PUBKEY_BYTES];
    dp5.genkeypair(client_pubkey, client_privkey);

    DP5RegClient client = DP5RegClient(client_privkey);

    // Make up some friends
    vector<BuddyInfo> buds;
    BuddyInfo buddies[10];
    memset(buddies, 0, sizeof(BuddyInfo)*10);
    

    for(unsigned int i = 0; i < 10; i++){
        unsigned char bud_privkey[dp5.PRIVKEY_BYTES];
        unsigned char* bud_pubkey = buddies[i].pubkey;
        dp5.genkeypair(bud_pubkey, bud_privkey);
        unsigned char* plain1 = buddies[i].data;

        for (unsigned int j=0; j<dp5.DATAPLAIN_BYTES; ++j) {
	        plain1[j] = 0x00 + j;
        }

        buds.push_back(buddies[i]);
    }

    dump("Buddies ", (unsigned char *) buddies, sizeof(BuddyInfo)*10);

    // Make the first message
    string s;
    dump("In string ", (unsigned char *) s.c_str(), s.length());

    client.start_reg(s, buds);

    dump("Out string ", (unsigned char *) s.c_str(), s.length());



}
#endif // TEST_CLIENT


