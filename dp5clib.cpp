
#include "dp5clib.h" 

using namespace std;
using namespace dp5;
using namespace dp5::internal;

// Initialize libraries
void * Init_init(){
    ZZ_p::init(to_ZZ(256));
    Pairing * p = new Pairing(); // initialize core
    return (void *) p;
}

void Init_cleanup(void * p){
    delete (Pairing *) p;
}

// --------- DH Key functions -----------------------

typedef struct _DHKey {
    PubKey pubkey;
    PrivKey privkey;
} DHKey;

DHKey * DHKey_alloc(){
    DHKey * keys = new DHKey();
    return keys; 
}



void DHKey_free(DHKey * keys){
    delete keys;
}

void DHKey_keygen(DHKey * keys){
    genkeypair(keys->pubkey, keys->privkey);
}

size_t DHKey_size(){
    return sizeof(DHKey);
}

size_t DHKey_pubsize(){
    return sizeof(PubKey);
}

// --------- BLS Key functions -----------------------

typedef struct _BLSKey {
    BLSPubKey pubkey;
    BLSPrivKey privkey;
} BLSKey;

BLSKey * BLSKey_alloc(){
    BLSKey * keys = new BLSKey();
    return keys; 
}

void BLSKey_free(BLSKey * keys){
    delete keys;
}

void BLSKey_keygen(BLSKey * keys){
    genkeypair<BLSPubKey,BLSPrivKey>(keys->pubkey, keys->privkey);
}

size_t BLSKey_size(){
    return sizeof(BLSKey);
}

size_t BLSKey_pubsize(){
    return sizeof(BLSPubKey);
}

// --------- Config functions -----------------------


struct DP5Config * Config_alloc(
    unsigned int epoch_len,
    unsigned int dataenc_bytes,
    bool combined){

    struct DP5Config * config = new struct DP5Config();
    config->epoch_len = epoch_len;
    config->dataenc_bytes = dataenc_bytes;
    config->combined = combined;

    return config;
}

unsigned int Config_dataplain_bytes(struct DP5Config * config){
    return config->dataplain_bytes();
}

Epoch Config_current_epoch(struct DP5Config * config){
    return config->current_epoch();
}

void Config_delete(struct DP5Config * config){
    delete config;
}

// ---------- Registration Client functions ------

struct DP5RegClient * RegClient_alloc(DP5Config * config, DHKey * keys){
    return new struct DP5RegClient(*config, keys->privkey);
}

void RegClient_delete(struct DP5RegClient * p){
    delete p;
}

int RegClient_start(
    DP5RegClient * reg, 
    DP5Config * config,
    unsigned int epoch,
    unsigned int friends_num,
    char * data,
    void processbuf(size_t, const void*)){

    vector<BuddyInfo> buds;
    unsigned int PKl = sizeof(PubKey);
    unsigned int Dl = config->dataplain_bytes();
    unsigned int RECl = PKl + Dl;
    for(unsigned int i=0 ; i< friends_num; i++){
        BuddyInfo b;
        memcpy(&b.pubkey, data + i*RECl, PKl);
        b.data.append((char *) data + i*RECl + PKl, Dl);
        buds.push_back(b);
    }

    string msgCtoS;
    unsigned int next_epoch = epoch + 1;
    int err1 = reg->start_reg(msgCtoS, next_epoch, buds);
    if (err1) return err1;

    processbuf(msgCtoS.size(), msgCtoS.data());

    return 0x00;
}

int RegClient_complete(
    DP5RegClient * reg,
    unsigned int epoch,
    size_t len,
    char * buffer){

    string data;
    data.append(buffer, len);

    int err = reg->complete_reg(data, epoch);
    return err;
}

// ----------- Combined Reg Client Functions ------



// ----------- Registration Server Functions ------


DP5RegServer * RegServer_alloc(
    DP5Config * config,
    unsigned int epoch,
    char* regdir,
    char* datadir){

    return new DP5RegServer(*config, epoch, regdir, datadir);

}

void RegServer_delete(DP5RegServer * p){
    delete p;
}

void RegServer_register(
    DP5RegServer * reg,
    size_t len,
    void * data,
    void processbuf(size_t, const void*)){

    string input;
    input.append((char*) data, len);
    string output;
    reg->client_reg(output, input);
    
    processbuf(output.size(), output.data());
}

unsigned int RegServer_epoch_change(
    DP5RegServer * reg,
    char * metadata,
    char * data){

    ofstream md(metadata);
    ofstream d(data);
    unsigned int epoch = reg->epoch_change(md, d);
    d.close();
    md.close();

    return epoch;
}

// ---------- Lookup client functions -----------

DP5LookupClient * LookupClient_alloc(DHKey * keys){
    return new DP5LookupClient(keys->privkey);
}





