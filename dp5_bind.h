#include <stdlib.h>

  /* Native buffer interface */

  typedef struct {
  size_t len;
  char * buf;
  } nativebuffer;

  void nativebuffer_purge(nativebuffer buf);

  /* Init functions */

  void * Init_init();

  typedef _Bool bool;

  /* DH Crypto */

  typedef struct _DHKey DHKey;

  DHKey * DHKey_alloc();
  void DHKey_free(DHKey * vkeys);
  void DHKey_keygen(DHKey * vkeys);
  size_t DHKey_size();
  size_t DHKey_pubsize();

  /* BLS Crypto */

  typedef struct _BLSKey BLSKey;

  BLSKey * BLSKey_alloc();
  void BLSKey_free(BLSKey * keys);
  void BLSKey_keygen(BLSKey * keys);
  size_t BLSKey_size();
  size_t BLSKey_pubsize();

  /* Configuration file */

  typedef struct _DP5Config DP5Config;

  DP5Config * Config_alloc(
      unsigned int epoch_len,
      unsigned int dataenc_bytes,
      bool combined);
  unsigned int Config_dataplain_bytes(DP5Config * config);
  unsigned int Config_current_epoch(DP5Config * config);
  void Config_delete(DP5Config * config);

  /* Registration client */

  typedef struct _DP5RegClient DP5RegClient;

  DP5RegClient * RegClient_alloc(
      DP5Config * config,
      DHKey * keys);

  int RegClient_start(
      DP5RegClient * reg,
      DP5Config * config,
      unsigned int epoch,
      unsigned int friends_num,
      char * data,
      nativebuffer * msg);

  int RegClient_complete(
      DP5RegClient * reg,
      unsigned int epoch,
      nativebuffer buf);

  void RegClient_delete(DP5RegClient * p);

  /* Combined registration server */

  typedef struct _regserver DP5RegServer;

  DP5RegServer * RegServer_alloc(
      DP5Config * config,
      unsigned int epoch,
      char* regdir,
      char* datadir);

  void RegServer_register(
      DP5RegServer * reg,
      nativebuffer data,
      void processbuf(size_t, const void*));

  unsigned int RegServer_epoch_change(
      DP5RegServer * reg,
      char * metadata,
      char * data);

  void RegServer_delete(DP5RegServer * p);

  /* Combined registration client */

  typedef struct _DP5CombinedRegClient DP5CombinedRegClient;

  DP5CombinedRegClient * RegClientCB_alloc(BLSKey * keys);

  void RegClientCB_delete(DP5CombinedRegClient * p);

  int RegClientCB_start(
      DP5CombinedRegClient * reg,
      unsigned int epoch,
      nativebuffer data,
      void processbuf(size_t, const void*));

  int RegClientCB_complete(
      DP5CombinedRegClient * reg,
      unsigned int epoch,
      nativebuffer buffer);

  /* Lookup client */

  typedef struct _DP5LookupClient DP5LookupClient;

  DP5LookupClient * LookupClient_alloc(DHKey * keys);
  void LookupClient_delete(DP5LookupClient * p);

  void LookupClient_metadata_req(
      DP5LookupClient * cli,
      unsigned int epoch,
      nativebuffer * msg);

  int LookupClient_metadata_rep(
      DP5LookupClient * cli,
      nativebuffer data);

  typedef struct _DP5LookupClient_Request DP5LookupClient_Request;

  DP5LookupClient_Request * LookupRequest_lookup(
      DP5LookupClient * cli,
      unsigned int buds_len,
      void * buds,
      unsigned int num_servers,
      nativebuffer * msg);

  int LookupRequest_reply(
      DP5LookupClient_Request * req,
      unsigned int num_servers,
      nativebuffer * replies,
      nativebuffer * msg);

  void LookupRequest_delete(DP5LookupClient_Request * p);

  /* Combined Lookup Client */

  typedef struct _DP5CombinedLookupClient DP5CombinedLookupClient;
  typedef struct _DP5CombinedLookupClient_Request DP5CombinedLookupClient_Request;

  DP5CombinedLookupClient * LookupClientCB_alloc();
  void LookupClientCB_delete(DP5CombinedLookupClient * p);

  void LookupClientCB_metadata_req(
      DP5CombinedLookupClient * cli,
      unsigned int epoch,
      void processbuf(size_t, const void*));

  int LookupClientCB_metadata_rep(
      DP5CombinedLookupClient * cli,
      nativebuffer data);

  DP5CombinedLookupClient_Request * LookupRequestCB_lookup(
      DP5CombinedLookupClient * cli,
      unsigned int buds_len,
      void * buds,
      unsigned int num_servers,
      void processbuf(size_t, const void*) );

  int LookupRequestCB_reply(
      DP5CombinedLookupClient_Request * req,
      unsigned int num_servers,
      nativebuffer * replies,
      void processprez(char*, bool, size_t, const void*)
      );

  void LookupRequestCB_delete(DP5CombinedLookupClient_Request * p);

  /* Lookup server */

  typedef struct _DP5LookupServer DP5LookupServer;

  DP5LookupServer * LookupServer_alloc(char* meta, char* data);

  void LookupServer_delete(DP5LookupServer * p);

  void LookupServer_process(
      DP5LookupServer * ser,
      nativebuffer data,
      void processbuf(size_t, const void*));
