#include <sys/types.h>

#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdexcept>


#include <algorithm>
#include "dp5regclient.h"

using namespace std;

// Initialize the client by storing its private key
DP5RegClient::DP5RegClient(const DP5Metadata & md, const unsigned char privkey[PRIVKEY_BYTES]) : DP5Metadata(md) {
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
    
    char epoch_bytes[EPOCH_BYTES];
    epoch_num_to_bytes(epoch_bytes, next_epoch);

    // Placeholder for the output message
    size_t record_length = SHAREDKEY_BYTES+dataenc_bytes;
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
        unsigned char shared_key[SHAREDKEY_BYTES];
        unsigned char data_key[DATAKEY_BYTES];
        H1H2(shared_key, data_key, epoch, mypub, shared_dh_secret);

        s.assign((char *) shared_key, SHAREDKEY_BYTES);

        s += Enc(data_key, current_buddy.data);
        to_sort.push_back(s);        
    }
    
    // Now pad the end of the array with random entries
    for(unsigned int i = buddies.size(); i < MAX_BUDDIES; i++)
    {
        char record[record_length];
        random_bytes((unsigned char *) record, record_length);
        string s(record, record_length);
        to_sort.push_back(s);
    }    

    // Sort the records and construct the message
    msgtosend.assign(epoch_bytes, EPOCH_BYTES);
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
    const char * buffer = replymsg.c_str();
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
    DP5Metadata dp5;
    
    // Make up a client
    unsigned char client_privkey[dp5.PRIVKEY_BYTES];
    unsigned char client_pubkey[dp5.PUBKEY_BYTES];
    dp5.genkeypair(client_pubkey, client_privkey);
    dp5.dataenc_bytes = 16;
    dp5.epoch_len = 1800;
    dp5.usePairings = false;

    DP5RegClient client = DP5RegClient(dp5, client_privkey);

    // Make up some friends
    vector<BuddyInfo> buddies(10);
    
    for(unsigned int i = 0; i < 10; i++){
        unsigned char bud_privkey[dp5.PRIVKEY_BYTES];
        unsigned char* bud_pubkey = buddies[i].pubkey;
        dp5.genkeypair(bud_pubkey, bud_privkey);

        for (unsigned int j=0; j<dp5.dataenc_bytes; ++j) {
            buddies[i].data.push_back(0x00 + j);
        }
        printf("Buddy %d PK: ", i);
        dump(NULL, buddies[i].pubkey, dp5.PUBKEY_BYTES);
        printf("Buddy %d data: ", i);
        dump(NULL, (unsigned char  *) buddies[i].data.c_str(), dp5.dataenc_bytes);
    }

    // Make the first message
    unsigned int next_epoch = dp5.current_epoch() + 1;

    string s;
    dump("In string ", (unsigned char *) s.c_str(), s.length());

    int err1 = client.start_reg(s, next_epoch, buddies);
    printf("Result 1 ok: %s\n", (err1==0x00)?("True"):("False"));    

    dump("Out string ", (unsigned char *) s.c_str(), s.length());


    char rmsg[1+dp5.EPOCH_BYTES];
    rmsg[0] = 0x00;
    // unsigned int next_epoch = dp5.current_epoch() + 1;
    dp5.epoch_num_to_bytes(1+rmsg, next_epoch);
    string rstr;
    rstr.assign(rmsg, 1+dp5.EPOCH_BYTES);

    int err2 = client.complete_reg(rstr, next_epoch);
    printf("Result 2 ok: %s\n", (err2==0x00)?("True"):("False"));
}
#endif // TEST_CLIENT


