#include <vector>
#include <set>
#include <sys/types.h>
#include <sys/stat.h>


#include <unistd.h>
#include <string.h>

#include "dp5params.h"
#include "dp5regclient.h"
#include "dp5combregclient.h"
#include "dp5regserver.h"

#include "dp5lookupserver.h"
#include "dp5lookupclient.h"

#include <stdio.h>
#include <stdlib.h>

#include <iostream>
#include <fstream>

using namespace std;
using namespace dp5;
using namespace dp5::internal;

template<typename Public,typename Private, typename LookupClient>
struct dp5TestClientTemplate {
    Private privkey;
    Public pubkey;
    LookupClient * cli;
    unsigned int index;
    std::set<dp5TestClientTemplate<Public,Private,LookupClient> *> friends;
    bool online;
    void keygen() {
        genkeypair(pubkey, privkey);
    }
    void newLookupClient();
    void registerClient(const DP5Config & config, Epoch epoch,
         DP5RegServer & server);
    dp5TestClientTemplate() : index(counter++) {}
    bool verifyData(const DP5Config & config,
        const dp5TestClientTemplate<Public,Private,LookupClient> * friendp,
        const typename LookupClient::Presence & presence);
private:
    static unsigned int counter;
};

template<typename Public,typename Private, typename LookupClient>
unsigned int dp5TestClientTemplate<Public,Private,LookupClient>::counter = 0;



template<>
void dp5TestClientTemplate<PubKey,PrivKey,DP5LookupClient>::newLookupClient() {
    cli = new DP5LookupClient(privkey);
}

template<>
void dp5TestClientTemplate<BLSPubKey,BLSPrivKey,DP5CombinedLookupClient>::newLookupClient() {
    cli = new DP5CombinedLookupClient();
}

template<>
void dp5TestClientTemplate<PubKey,PrivKey,DP5LookupClient>::registerClient(
    const DP5Config & config, Epoch epoch, DP5RegServer & server) {
    DP5RegClient regClient(config, privkey);
    vector<BuddyInfo> buds;
    for(std::set<dp5TestClientTemplate<PubKey,PrivKey,DP5LookupClient> *>::iterator ix = friends.begin();
        ix!=friends.end(); ++ix) {
        dp5TestClientTemplate<PubKey,PrivKey,DP5LookupClient> * f2 = *ix;
        BuddyInfo b;
        b.pubkey = f2->pubkey;
        b.data.push_back(0x99);
        b.data.append((char *) &index, sizeof(index));
        b.data.append((char *) &f2->index, sizeof(index));
        b.data.append(config.dataplain_bytes() - 2*sizeof(index) - 1, 0);
        buds.push_back(b);
    }

    printf("Number of friends: %lu\n", (unsigned long)(buds.size()));

    // Run the registration process with the server
    string msgCtoS;
    unsigned int next_epoch = epoch + 1;
    int err1 = regClient.start_reg(msgCtoS, next_epoch, buds);
    printf("Result 1 ok: %s\n", (err1==0x00)?("True"):("False"));

    string msgStoC;
    server.client_reg(msgStoC, msgCtoS);

    int err2 = regClient.complete_reg(msgStoC, next_epoch);
    printf("Result 2 ok: %s\n", (err2==0x00)?("True"):("False"));
}

template<>
void dp5TestClientTemplate<BLSPubKey,BLSPrivKey,DP5CombinedLookupClient>::registerClient(
    const DP5Config & config, Epoch epoch, DP5RegServer & server) {
    DP5CombinedRegClient regClient(privkey);
    stringstream ss;
    ss << index;
    string data(ss.str());
    data.append(config.dataplain_bytes() - data.size(), (char ) 0x99);

    string msgCtoS;
    int err1 = regClient.start_reg(msgCtoS, epoch+1, data);
    printf("Result 1 ok: %s\n", (err1==0x00)?("True"):("False"));

    string msgStoC;
    server.client_reg(msgStoC, msgCtoS);

    int err2 = regClient.complete_reg(msgStoC, epoch+1);
    printf("Result 2 ok: %s\n", (err2==0x00)?("True"):("False"));
}


template<>
bool dp5TestClientTemplate<PubKey,PrivKey,DP5LookupClient>::verifyData(
    const DP5Config & config,
    const dp5TestClientTemplate<PubKey,PrivKey,DP5LookupClient> * friendp,
    const DP5LookupClient::Presence & presence) {
    if (presence.data.size() != config.dataplain_bytes())
        return 0;   // wrong sized output
    unsigned char data[config.dataplain_bytes()];
    memset(data, 0, config.dataplain_bytes());
    data[0] = 0x99; // Just a random marker
    memmove(data + 1,
        reinterpret_cast<const char *>(&friendp->index), sizeof(unsigned int));
    memmove(data + 1 + sizeof(unsigned int),
        reinterpret_cast<const char *>(&index), sizeof(unsigned int));

    return (memcmp(data, presence.data.data(), sizeof(data)) == 0);
}

template<>
bool dp5TestClientTemplate<BLSPubKey,BLSPrivKey,DP5CombinedLookupClient>::verifyData(
    const DP5Config & config,
    const dp5TestClientTemplate<BLSPubKey,BLSPrivKey,DP5CombinedLookupClient> * friendp,
    const DP5CombinedLookupClient::Presence & presence) {
    stringstream ss;
    ss << friendp->index;
    string data(ss.str());
    data.append(config.dataplain_bytes() - data.size(), (char ) 0x99);

    return data == presence.data;
}

template<typename Public,typename Private,typename LookupClient, bool combined>
int mainfunc(unsigned int NUMBEROFCLIENTS, unsigned int NUMBEROFFRIENDS) {
    typedef dp5TestClientTemplate<Public,Private,LookupClient> dp5TestClient;
    DP5Config dp5;
    dp5.epoch_len = 1800;
    dp5.dataenc_bytes = 32;
    dp5.combined = combined;
    Epoch epoch = dp5.current_epoch();

    vector<dp5TestClient> tcs;

    // Allocate some clients
    for (unsigned int f = 0; f < NUMBEROFCLIENTS; f++)
    {
        dp5TestClient person;
        person.online = false;
        if (f % 2 == 0) person.online = true;
        person.keygen();
        tcs.push_back(person);
    }

    // Make up some friends for the clients
    for (unsigned int f = 0; f < NUMBEROFCLIENTS; f++)
    {
        for (unsigned int k = 0; k < NUMBEROFFRIENDS; k++)
        {
            unsigned int f2 = rand() % NUMBEROFCLIENTS;

            if (tcs[f].friends.size() < MAX_BUDDIES &&
                tcs[f2].friends.size() < MAX_BUDDIES){
                    tcs[f].friends.insert(&tcs[f2]);
                    tcs[f2].friends.insert(&tcs[f]);
                }
        }
    }
    mkdir("regdir", 0777);
    mkdir("datadir", 0777);

    // Make a registration server
    DP5RegServer * rs =
        new DP5RegServer(dp5, epoch, "regdir", "datadir");

    // Now register buddies for all on-line clients
    for (unsigned int f = 0; f < NUMBEROFCLIENTS; f++)
    {
        tcs[f].newLookupClient();
        if (tcs[f].online == false) continue;
        tcs[f].registerClient(dp5, epoch, *rs);
    }

    // Signal the end of an epoch, when the registration file is
    // transfered to the PIR servers,
    ofstream md("integrated_metadata.out");
    ofstream d("integrated_data.out");
    rs->epoch_change(md, d);
    d.close();
    md.close();

    // And now we are going to build a number of lookup servers
    epoch = epoch + 1;
    const unsigned int num_servers = 5;

    // FIXME: Assumes library is initialized later.
    //         This is rather opaque to the user
    //         (and segfaults if it is not).
    ZZ_p::init(to_ZZ(256));

    // Create the right number of lookup servers
    DP5LookupServer *servers = new DP5LookupServer[num_servers];

    // Initialize them.  NOTE: You must have run test_rsreg prior to
    // this to create the metadata.out and data.out files.
    for(unsigned int s=0; s<num_servers; ++s) {
	    servers[s].init("integrated_metadata.out", "integrated_data.out");
    }

    // Each (online) client does the PIR business
    for (unsigned int f = 0; f < NUMBEROFCLIENTS; f++)
    {
        string msgCtoS;
        // Pick up the metadata
        tcs[f].cli->metadata_request(msgCtoS, epoch);

        // Pick a random server
        string msgStoC;
        const int serverid = rand() % num_servers;
        servers[serverid].process_request(msgStoC, msgCtoS);

        int err3 = tcs[f].cli->metadata_reply(msgStoC);
        printf("Metadata 1 ok: %s\n", (err3==0x00)?("True"):("False"));

        // Make a list of friends
        vector<Public> buds;
        for(typename std::set<dp5TestClientTemplate<Public,Private,LookupClient> *>::iterator ix = tcs[f].friends.begin();
            ix!=tcs[f].friends.end(); ++ix){
            buds.push_back((*ix)->pubkey);
        }

        // Build a request object
        typename LookupClient::Request req;
        tcs[f].cli->lookup_request(req, buds, num_servers, num_servers-1);

        // Send PIR request messages to servers
        vector<string> msgCtoSpir = req.get_msgs();
        vector<string> msgStoCpir;
        for(unsigned int s = 0; s < msgCtoSpir.size(); s++){
            if (msgCtoSpir[s] == "") {
                msgStoCpir.push_back("");
            }
            else
            {
                string rep;
                servers[s].process_request(rep, msgCtoSpir[s]);
                msgStoCpir.push_back(rep);
            }
        }

        // Process the PIR responses from servers
        vector<typename LookupClient::Presence> presence;
        int err4 = req.lookup_reply(presence, msgStoCpir);
        printf("Presence 1 ok (%X): %s\n",  err4, (err4==0x00)?("True"):("False"));

        // check length
        bool len_ok = (presence.size() == tcs[f].friends.size());
        printf("Len 1 ok: %s (%lu?=%lu)\n", (len_ok)?("True"):("False"),(unsigned long)(presence.size()),(unsigned long)(tcs[f].friends.size()));

        // Check the presence resutls are correct
        unsigned int idx = 0;


        for(typename std::set<dp5TestClientTemplate<Public,Private,LookupClient> *>::iterator ix = tcs[f].friends.begin();
            idx < presence.size() && ix!=tcs[f].friends.end(); ++ix){
            dp5TestClientTemplate<Public,Private,LookupClient> * f2 = *ix;
            bool mem_ok = (f2->pubkey == presence[idx].pubkey);
            bool online_ok = (f2->online == presence[idx].is_online);
            bool data_ok = true;

            if (presence[idx].is_online) {
                data_ok = tcs[f].verifyData(dp5, f2, presence[idx]);
            }


            bool all_ok = mem_ok && online_ok && data_ok;


            if (!all_ok){
                printf("Presence 2 ok: %s\n", all_ok?("True"):("False"));
                printf("    pubkey ok: %s\n", mem_ok?("True"):("False"));
                printf("    online ok: %s\n", online_ok?("True"):("False"));
                printf("         actual online: (%s)\n", (f2->online)?("True"):("False"));
                printf("    data ok: %s\n", data_ok?("True"):("False"));
            }

            idx++;
        }
    }
    return 0;

}

int main(int argc, char **argv){
    unsigned int NUMBEROFCLIENTS = 1000;
    unsigned int NUMBEROFFRIENDS = 2;

    if (argc > 1) {
        NUMBEROFCLIENTS = atoi(argv[1]);
    }
    if (argc > 2) {
        NUMBEROFFRIENDS = atoi(argv[2]);
    }
    cout << "Old school test" << endl;
    mainfunc<PubKey,PrivKey,DP5LookupClient,false>(NUMBEROFCLIENTS,
        NUMBEROFFRIENDS);
    cout << "New school test" << endl;
    initPairing();
    return mainfunc<BLSPubKey,BLSPrivKey,DP5CombinedLookupClient,true>(
        NUMBEROFCLIENTS, NUMBEROFFRIENDS);
}
