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

extern "C" {

    // Native buffer interface

    typedef struct {
    size_t len;
    char * buf;
    } nativebuffer;

    void nativebuffer_purge(nativebuffer buf);

    /* Init functions */

    void * Init_init();
    void Init_cleanup(void * p);

    /* DH functions */

    typedef struct _DHKey DHKey;

    DHKey * DHKey_alloc();
    void DHKey_free(DHKey * vkeys);
    void DHKey_keygen(DHKey * vkeys);
    size_t DHKey_size();
    size_t DHKey_pubsize();

    /* BLH functions */

    typedef struct _BLSKey BLSKey;

    BLSKey * BLSKey_alloc();
    void BLSKey_free(BLSKey * keys);
    void BLSKey_keygen(BLSKey * keys);
    size_t BLSKey_size();
    size_t BLSKey_pubsize();

    /* DP5 Config functions */

    struct DP5Config * Config_alloc(
        unsigned int epoch_len,
        unsigned int dataenc_bytes,
        bool combined);
    unsigned int Config_dataplain_bytes(struct DP5Config * config);
    dp5::Epoch Config_current_epoch(struct DP5Config * config);
    void Config_delete(struct DP5Config * config);

    /* Registration client */
    struct DP5RegClient * RegClient_alloc(
        struct DP5Config * config, 
        DHKey * keys);

    void RegClient_delete(struct DP5RegClient * p);

    int RegClient_start(
        struct DP5RegClient * reg, 
        struct DP5Config * config,
        unsigned int epoch,
        unsigned int friends_num,
        char * data,
        void processbuf(size_t, const void*));

    int RegClient_complete(
        DP5RegClient * reg,
        unsigned int epoch,
        nativebuffer buf);

    /* Combined registration client */

    DP5CombinedRegClient * RegClientCB_alloc(BLSKey * keys);

    void RegClientCB_delete(struct DP5CombinedRegClient * p);

    int RegClientCB_start(
        DP5CombinedRegClient * reg, 
        unsigned int epoch,
        nativebuffer data,
        void processbuf(size_t, const void*));

    int RegClientCB_complete(
        DP5CombinedRegClient * reg,
        unsigned int epoch,
        nativebuffer buffer);

    /* Registration Server */

    DP5RegServer * RegServer_alloc(
        DP5Config * config,
        unsigned int epoch,
        char* regdir,
        char* datadir);

    void RegServer_delete(DP5RegServer * p);

    void RegServer_register(
        DP5RegServer * reg,
        nativebuffer data,
        void processbuf(size_t, const void*));

    unsigned int RegServer_epoch_change(
        DP5RegServer * reg,
        char * metadata,
        char * data);


    /* Lookup server */

    DP5LookupServer * LookupServer_alloc(char* meta, char* data);

    void LookupServer_delete(DP5LookupServer * p);

    void LookupServer_process(
        DP5LookupServer * ser, 
        nativebuffer data,
        void processbuf(size_t, const void*));
}
