
#include "dp5clib.h"

using namespace std;
using namespace dp5;
using namespace dp5::internal;

// ----------------------------

// Create a Buffer interface to exchange data

void nativebuffer_purge(nativebuffer buf){
    if (buf.buf != NULL) free(buf.buf);
}

// Initialize libraries
void Init_init(){
    ZZ_p::init(to_ZZ(256));
    initPairing();
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
    unsigned int next_epoch = epoch;
    int err1 = reg->start_reg(msgCtoS, next_epoch, buds);
    if (err1) return err1;

    processbuf(msgCtoS.size(), msgCtoS.data());

    return 0x00;
}

int RegClient_complete(
    DP5RegClient * reg,
    unsigned int epoch,
    nativebuffer buf){

    string data;
    data.append(buf.buf, buf.len);

    int err = reg->complete_reg(data, epoch);
    return err;
}

// ----------- Combined Reg Client Functions ------

struct DP5CombinedRegClient * RegClientCB_alloc(BLSKey * keys){
    return new struct DP5CombinedRegClient(keys->privkey);
}

void RegClientCB_delete(struct DP5CombinedRegClient * p){
    delete p;
}

int RegClientCB_start(
    DP5CombinedRegClient * reg,
    unsigned int epoch,
    nativebuffer data,
    void processbuf(size_t, const void*)){

    string msgCtoS;
    string sdata;
    sdata.append(data.buf, data.len);
    int err1 = reg->start_reg(msgCtoS, epoch, sdata);
    if (err1) return err1;

    processbuf(msgCtoS.size(), msgCtoS.data());
    return 0x00;
}

int RegClientCB_complete(
    DP5CombinedRegClient * reg,
    unsigned int epoch,
    nativebuffer buffer){

    string data;
    data.append(buffer.buf, buffer.len);

    int err = reg->complete_reg(data, epoch);
    return err;
}

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
    nativebuffer data,
    void processbuf(size_t, const void*)){

    string input;
    input.append((char*) data.buf, data.len);
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

// ---------- Combined Lookup client functions -----------

DP5CombinedLookupClient * LookupClientCB_alloc(){
    return new DP5CombinedLookupClient();
}

void LookupClientCB_delete(DP5CombinedLookupClient * p){
    delete p;
}

void LookupClientCB_metadata_req(
    DP5CombinedLookupClient * cli,
    unsigned int epoch,
    void processbuf(size_t, const void*)){

    string output;
    cli->metadata_request(output, epoch);

    processbuf(output.size(), output.data());
}

int LookupClientCB_metadata_rep(
    DP5CombinedLookupClient * cli,
    nativebuffer data){

    string msgStoC;
    msgStoC.append((char *) data.buf, data.len);
    int err = cli->metadata_reply(msgStoC);

    return err;
}

DP5CombinedLookupClient::Request * LookupRequestCB_lookup(
    DP5CombinedLookupClient * cli,
    unsigned int buds_len,
    void * buds,
    unsigned int num_servers,
    void processbuf(size_t, const void*)
    ){

    vector<BLSPubKey> vbuds;
    size_t pk_len = sizeof(BLSPubKey);
    for (unsigned int f = 0; f < buds_len; f++){
        BLSPubKey pub;
        memcpy(&pub, ((char *) buds) + f*pk_len, pk_len);
        vbuds.push_back(pub);

    }

    DP5CombinedLookupClient::Request * req = new DP5CombinedLookupClient::Request();

    // DP5Request * req = new DP5Request();
    cli->lookup_request(*req, vbuds, num_servers, num_servers-1);

    vector<string> msgCtoSpir = req->get_msgs();
    vector<string> msgStoCpir;
    for(unsigned int s = 0; s < msgCtoSpir.size(); s++){
        if (msgCtoSpir[s] == "") {
            processbuf(0, NULL);
        }
        else
        {
            processbuf(msgCtoSpir[s].size(), msgCtoSpir[s].data());
        }
    }

    return req;
}

int LookupRequestCB_reply(
    DP5CombinedLookupClient::Request * req,
    unsigned int num_servers,
    nativebuffer * replies,
    void processprez(char*, bool, size_t, const void*)
    ){

    vector<string> msgStoCpir;
    for (unsigned int i = 0; i < num_servers; i++){
        string msg;
        if (replies[i].len > 0){
            msg.append(replies[i].buf, replies[i].len);
        }
        else {
            msg = "";
        }
        msgStoCpir.push_back(msg);
    }

    vector<typename DP5CombinedLookupClient::Presence> presence;
    int err4 = req->lookup_reply(presence, msgStoCpir);
    if (err4) return err4;


    for (unsigned int j = 0; j < presence.size(); j++){
        processprez(
        (char*) & (presence[j].pubkey),
        presence[j].is_online,
        presence[j].data.size(),
        presence[j].data.data());
    }

    return 0;
}

void LookupRequestCB_delete(DP5CombinedLookupClient::Request * p){
    delete p;
}

// ---------- Lookup client functions -----------

DP5LookupClient * LookupClient_alloc(DHKey * keys){
    return new DP5LookupClient(keys->privkey);
}

void LookupClient_delete(DP5LookupClient * p){
    delete p;
}

void LookupClient_metadata_req(
    DP5LookupClient * cli,
    unsigned int epoch,
    void processbuf(size_t, const void*)){

    string output;
    cli->metadata_request(output, epoch);

    processbuf(output.size(), output.data());
}

int LookupClient_metadata_rep(
    DP5LookupClient * cli,
    nativebuffer data){

    string msgStoC;
    msgStoC.append((char *) data.buf, data.len);
    int err = cli->metadata_reply(msgStoC);

    return err;
}

DP5LookupClient::Request * LookupRequest_lookup(
    DP5LookupClient * cli,
    unsigned int buds_len,
    void * buds,
    unsigned int num_servers,
    void processbuf(size_t, const void*)
    ){

    vector<PubKey> vbuds;
    size_t pk_len = sizeof(PubKey);
    for (unsigned int f = 0; f < buds_len; f++){
        PubKey pub;
        memcpy(&pub, ((char *) buds) + f*pk_len, pk_len);
        vbuds.push_back(pub);

    }

    DP5LookupClient::Request * req = new DP5LookupClient::Request();

    // DP5Request * req = new DP5Request();
    cli->lookup_request(*req, vbuds, num_servers, num_servers-1);

    vector<string> msgCtoSpir = req->get_msgs();
    vector<string> msgStoCpir;
    for(unsigned int s = 0; s < msgCtoSpir.size(); s++){
        if (msgCtoSpir[s] == "") {
            processbuf(0, NULL);
        }
        else
        {
            processbuf(msgCtoSpir[s].size(), msgCtoSpir[s].data());
        }
    }

    return req;
}

int LookupRequest_reply(
    DP5LookupClient::Request * req,
    unsigned int num_servers,
    nativebuffer * replies,
    void processprez(char*, bool, size_t, const void*)
    ){

    vector<string> msgStoCpir;
    for (unsigned int i = 0; i < num_servers; i++){
        string msg;
        if (replies[i].len >0){
            msg.append(replies[i].buf, replies[i].len);
        }
        else {
            msg = "";
        }
        msgStoCpir.push_back(msg);
    }

    vector<typename DP5LookupClient::Presence> presence;
    int err4 = req->lookup_reply(presence, msgStoCpir);
    if (err4) return err4;


    for (unsigned int j = 0; j < presence.size(); j++){
        processprez(
        (char*) & (presence[j].pubkey),
        presence[j].is_online,
        presence[j].data.size(),
        presence[j].data.data());
    }

    return 0;
}

void LookupRequest_delete(DP5LookupClient::Request * p){
    delete p;
}


// --------- Lookup Server functios -------------

DP5LookupServer * LookupServer_alloc(char* meta, char* data){
        DP5LookupServer *server = new DP5LookupServer();
        server->init(meta, data);
        return server;
}

void LookupServer_delete(DP5LookupServer * p){
    delete p;
}

void LookupServer_process(DP5LookupServer * ser,
    nativebuffer data,
    void processbuf(size_t, const void*)){

    string msgCtoS;
    msgCtoS.append(data.buf, data.len);

    string msgStoC;
    ser->process_request(msgStoC, msgCtoS);

    processbuf(msgStoC.size(), msgStoC.data());
}





