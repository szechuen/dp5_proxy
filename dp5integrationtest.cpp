#include <vector>
#include <set>
#include <sys/types.h>

#include <unistd.h>
#include <string.h>

#include "dp5params.h"
#include "dp5regclient.h"
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

struct dp5TestClient {
    PrivKey privkey;
    PubKey pubkey;
    DP5RegClient * reg;
    DP5LookupClient * cli;
    std::set<unsigned int> friends;
    bool online;
};

int main(int argc, char **argv){
    DP5Config dp5;
    dp5.epoch_len = 1800;
    dp5.dataenc_bytes = 16;
    Epoch epoch = dp5.current_epoch();
    unsigned int NUMBEROFCLIENTS = 1000;
    unsigned int NUMBEROFFRIENDS = 2;

    if (argc > 1) {
        NUMBEROFCLIENTS = atoi(argv[1]);
    }
    if (argc > 2) {
        NUMBEROFFRIENDS = atoi(argv[2]);
    }

    vector<dp5TestClient> tcs;

    // Allocate some clients
    for (unsigned int f = 0; f < NUMBEROFCLIENTS; f++)
    {
        dp5TestClient person;
        person.online = false;
        if (f % 2 == 0) person.online = true;
        genkeypair(person.pubkey, person.privkey);
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
                    tcs[f].friends.insert(f2);
                    tcs[f2].friends.insert(f);
                }
        }
    }

    // Make a registration server
    DP5RegServer * rs =
        new DP5RegServer(dp5, epoch, "regdir", "datadir");

    // Now register buddies for all on-line clients
    for (unsigned int f = 0; f < NUMBEROFCLIENTS; f++)
    {
        tcs[f].cli = new DP5LookupClient(tcs[f].privkey);
        if (tcs[f].online == false) continue;
        tcs[f].reg = new DP5RegClient(dp5, tcs[f].privkey);


        vector<BuddyInfo> buds;
        for(std::set<unsigned int>::iterator ix = tcs[f].friends.begin();
            ix!=tcs[f].friends.end(); ++ix){
            unsigned int f2 = *ix;
            BuddyInfo b;
            b.pubkey = tcs[f2].pubkey;
            b.data.push_back(0x99);
            b.data.append((char *) &f, sizeof(f));
            b.data.append((char *) &f2, sizeof(f2));
            b.data.append(dp5.dataenc_bytes - 2*sizeof(unsigned int) - 1, 0);
            buds.push_back(b);
        }

        printf("Number of friends: %lu\n", (unsigned long)(buds.size()));

        // Run the registration process with the server
        string msgCtoS;
        unsigned int next_epoch = epoch + 1;
        int err1 = tcs[f].reg->start_reg(msgCtoS, next_epoch, buds);
        printf("Result 1 ok: %s\n", (err1==0x00)?("True"):("False"));

        string msgStoC;
        rs->client_reg(msgStoC, msgCtoS);

        int err2 = tcs[f].reg->complete_reg(msgStoC, next_epoch);
        printf("Result 2 ok: %s\n", (err2==0x00)?("True"):("False"));

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
        vector<BuddyKey> buds;
        for(std::set<unsigned int>::iterator ix = tcs[f].friends.begin();
            ix!=tcs[f].friends.end(); ++ix){
            unsigned int f2 = *ix;
            BuddyKey b;
            b.pubkey = tcs[f2].pubkey;
            buds.push_back(b);
        }

        // Build a requesr object
        DP5LookupClient::Request req;
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
        vector<BuddyPresence> presence;
        int err4 = req.lookup_reply(presence, msgStoCpir);
        printf("Presence 1 ok (%X): %s\n",  err4, (err4==0x00)?("True"):("False"));

        // check length
        bool len_ok = (presence.size() == tcs[f].friends.size());
        printf("Len 1 ok: %s (%lu?=%lu)\n", (len_ok)?("True"):("False"),(unsigned long)(presence.size()),(unsigned long)(tcs[f].friends.size()));

        // Check the presence resutls are correct
        unsigned int idx = 0;

        for(std::set<unsigned int>::iterator ix = tcs[f].friends.begin();
            ix!=tcs[f].friends.end(); ++ix){
            unsigned int f2 = *ix;
            bool mem_ok = (memcmp(presence[idx].pubkey.c_str(),
                tcs[f2].pubkey, PUBKEY_BYTES) == 0);
            bool online_ok = (tcs[f2].online == presence[idx].is_online);

            bool data_ok = true;

            if (tcs[f2].online){
            unsigned char data[dp5.dataenc_bytes];
            memset(data, 0, dp5.dataenc_bytes);
            data[0] = 0x99; // Just a random marker
            memmove(data +1,
                (const char *) &f2, sizeof(unsigned int));
            memmove(data +1 + sizeof(unsigned int),
                (const char *) &f, sizeof(unsigned int));

            data_ok = (memcmp(data, presence[idx].data.data(), dp5.dataenc_bytes) == 0);
            }

            bool all_ok = mem_ok && online_ok && data_ok;


            if (!all_ok){
                printf("Presence 2 ok: %s\n", all_ok?("True"):("False"));
                printf("    pubkey ok: %s\n", mem_ok?("True"):("False"));
                printf("    online ok: %s\n", online_ok?("True"):("False"));
                printf("         actual online: (%s)\n", (tcs[f2].online)?("True"):("False"));
                printf("    data ok: %s\n", data_ok?("True"):("False"));
            }

            idx++;
        }
    }


}
