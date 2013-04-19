#include <vector>
#include <set>
#include <sys/types.h>

#include <unistd.h>
#include <string.h>

#include "dp5params.h"
#include "dp5regclient.h"
#include "dp5regserver.h"

#include <stdio.h>
#include <stdlib.h>

#include <iostream>
#include <fstream>

using namespace std;

struct dp5TestClient {
    unsigned char privkey[DP5Params::PRIVKEY_BYTES];
    unsigned char pubkey[DP5Params::PUBKEY_BYTES];
    DP5RegClient * reg;
    std::set<unsigned int> friends;
    bool online;
};

int main(int argc, char **argv){
    DP5Params dp5;
    const unsigned int NUMBEROFCLIENTS = 100;
    const unsigned int NUMBEROFFRIENDS = 10;


    vector<dp5TestClient> tcs;

    // Allocate some clients
    for (unsigned int f = 0; f < NUMBEROFCLIENTS; f++)
    {
        dp5TestClient person;
        person.online = false;
        if (f % 3 == 0) person.online = true;
        dp5.genkeypair(person.pubkey, person.privkey);
        tcs.push_back(person);
    }

    // Make up some friends for the clients
    for (unsigned int f = 0; f < NUMBEROFCLIENTS; f++)
    {
        tcs[f].reg = new DP5RegClient(tcs[f].privkey);

        for (unsigned int k = 0; k < NUMBEROFFRIENDS; k++)
        {
            unsigned int f2 = rand() % NUMBEROFCLIENTS;

            if (tcs[f].friends.size() < DP5Params::MAX_BUDDIES &&
                tcs[f2].friends.size() < DP5Params::MAX_BUDDIES){
                    tcs[f].friends.insert(f2);
                    tcs[f2].friends.insert(f);
                }
        }
    }

    // Make a registration server
    DP5RegServer * rs = 
        new DP5RegServer(DP5RegServer::current_epoch(), 
                            "regdir", "datadir");

    // Now register buddies for all on-line clients
    for (unsigned int f = 0; f < NUMBEROFCLIENTS; f++)
    {
        if (tcs[f].online == false) continue;

        vector<BuddyInfo> buds;
        for(std::set<unsigned int>::iterator ix = tcs[f].friends.begin();
            ix!=tcs[f].friends.end(); ++ix){
            unsigned int f2 = *ix;
            BuddyInfo b;
            memmove(b.pubkey, tcs[f2].pubkey, DP5Params::PUBKEY_BYTES);
            b.data[0] = 0x99; // Just a random marker
            memmove(b.data +1, 
                (const char *) &f, sizeof(unsigned int));
            memmove(b.data +1 + sizeof(unsigned int), 
                (const char *) &f2, sizeof(unsigned int));
            buds.push_back(b);
        }

        printf("Number of friends: %lu\n", buds.size());

        // Run the registration process with the server
        string msgCtoS;
        int err1 = tcs[f].reg->start_reg(msgCtoS, buds);
        printf("Result 1 ok: %s\n", (err1==0x00)?("True"):("False"));

        string msgStoC;
        rs->client_reg(msgStoC, msgCtoS);

        int err2 = tcs[f].reg->complete_reg(msgStoC);
        printf("Result 2 ok: %s\n", (err2==0x00)?("True"):("False"));
        
    }

    // Signal the end of an epoch, when the registration file is 
    // transfered to the PIR servers,
    ofstream md("integrated_metadata.out");
    ofstream d("integrated_data.out");
    rs->epoch_change(md, d);
    d.close();
    md.close();

}
