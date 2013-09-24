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

int DP5RegClient::start_reg(string &msgtosend, unsigned int next_epoch, const vector<BuddyInfo> &buddies){
    
    // Check inputs
    if (buddies.size() > MAX_BUDDIES)
        return 0x01; // Number of buddies exceeds maximum.

    unsigned char mypub[PUBKEY_BYTES];
    getpubkey(mypub, _privkey);

    // Determine the target epoch for the registration
    // as the next epoch, and convert to bytes.
    
    unsigned char epoch_bytes[EPOCH_BYTES];
    epoch_num_to_bytes(epoch_bytes, next_epoch);

    // Placeholder for the output message
    size_t record_length = SHAREDKEY_BYTES+DATAENC_BYTES;
    unsigned char out_data[MAX_BUDDIES][record_length];
    vector<string> to_sort;

    // For each real buddy
    for(unsigned int i = 0; i < buddies.size(); i++)
    {
        string s;
        const BuddyInfo& current_buddy = buddies[i];

        // Get the long terms shared DH key
        unsigned char shared_dh_secret[PUBKEY_BYTES];
        diffie_hellman(shared_dh_secret, _privkey, current_buddy.pubkey);

        // Derive the epoch keys 
        unsigned char* shared_key = out_data[i];
        unsigned char data_key[DATAKEY_BYTES];
        H1H2(shared_key, data_key, epoch_bytes, mypub, shared_dh_secret);

        // Encrypt the associated data
        unsigned char* ciphertext = out_data[i] + (SHAREDKEY_BYTES);
        Enc(ciphertext, data_key, current_buddy.data);
        s.assign((char*) out_data[i], record_length);
        to_sort.push_back(s);        
    }
    
    // Now pad the end of the array with random entries
    for(unsigned int i = buddies.size(); i < MAX_BUDDIES; i++)
    {
        string s;
        unsigned char* shared_key = out_data[i];
        unsigned char* ciphertext = out_data[i] + SHAREDKEY_BYTES;
        random_bytes(shared_key, SHAREDKEY_BYTES);
        random_bytes(ciphertext, DATAENC_BYTES);
        s.assign((char*)out_data[i], record_length);
        to_sort.push_back(s);
    }    

    // Sort the records and construct the message
    msgtosend.assign((char *)epoch_bytes, EPOCH_BYTES);
    sort(to_sort.begin(), to_sort.end());
    for (unsigned int i = 0 ; i < MAX_BUDDIES; i++){
       msgtosend += to_sort[i]; 
    }

    return 0x00;
}

int DP5RegClient::complete_reg(const string &replymsg, unsigned int next_epoch){
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
    unsigned int next_epoch = client.current_epoch() + 1;

    string s;
    dump("In string ", (unsigned char *) s.c_str(), s.length());

    int err1 = client.start_reg(s, next_epoch, buds);
    printf("Result 1 ok: %s\n", (err1==0x00)?("True"):("False"));    

    dump("Out string ", (unsigned char *) s.c_str(), s.length());


    unsigned char rmsg[1+dp5.EPOCH_BYTES];
    rmsg[0] = 0x00;
    // unsigned int next_epoch = dp5.current_epoch() + 1;
    dp5.epoch_num_to_bytes(1+rmsg, next_epoch);
    string rstr;
    rstr.assign((char*)rmsg, 1+dp5.EPOCH_BYTES);

    int err2 = client.complete_reg(rstr, next_epoch);
    printf("Result 2 ok: %s\n", (err2==0x00)?("True"):("False"));
}
#endif // TEST_CLIENT


