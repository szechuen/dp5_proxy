#ifndef __DP5LOOKUPCLIENT_H__
#define __DP5LOOKUPCLIENT_H__

#include <vector>
#include <string>
#include <set>
#include <map>
#include <stdexcept>
#include <sstream>
#include "dp5params.h"
#include "dp5metadata.h"
#include "percyparams.h"
#include "percyclient.h"

namespace dp5 {

    namespace internal {

                // A class representing an in-progress lookup request
        class PIRRequest {
        private:
            typedef PercyClient_GF2E<GF28_Element> PercyClientGF28;

        public:
            PIRRequest(): _pirparams(NULL), _pirclient(NULL) {}

            ~PIRRequest() {
               delete _pirparams;
               delete _pirclient;
            }

            PIRRequest(const PIRRequest &other) :
                _num_servers(other._num_servers),
                _privacy_level(other._privacy_level),
                _record_size(other._record_size),
                _pirparams(NULL), _pirclient(NULL),
                _metadata_current(other._metadata_current)
            {
                if (other._pirparams) {
                    _pirparams = new PercyClientParams(*other._pirparams);
                }
                if (other._pirclient) {
                    _pirclient = new PercyClientGF28(*other._pirclient);
                }
            }

            PIRRequest& operator=(PIRRequest other) {
                // Swap the fields of the temporary "other" with ours
                // so things get properly freed

                PercyClientParams *tmpc = other._pirparams;
                other._pirparams = _pirparams;
                _pirparams = tmpc;

                PercyClientGF28 *tmpcl = other._pirclient;
                other._pirclient = _pirclient;
                _pirclient = tmpcl;

                // The non-dynamic members can be just copied
                _num_servers = other._num_servers;
                _privacy_level = other._privacy_level;
                _metadata_current = other._metadata_current;
                _record_size = other._record_size;
                return *this;
            }

            // Initialize the Request object
            void init(unsigned int num_servers, unsigned int privacy_level,
                const Metadata &metadata, unsigned int record_size) {
                _num_servers = num_servers;
                _privacy_level = privacy_level;
                _metadata_current = metadata;
                _record_size = record_size;
                _pirparams = new PercyClientParams(
                  _metadata_current.bucket_size *
                  _record_size,
                  _metadata_current.num_buckets, 0, to_ZZ(256), MODE_GF28,
                  NULL, false);

                _pirclient = (PercyClientGF28*)PercyClient::make_client(
                   *_pirparams, _num_servers, _privacy_level);
            }


            // The glue API to the PIR layer.  Pass a vector of the bucket
            // numbers to look up.  This should already be padded to one of
            // the valid sizes listed in QUERY_SIZES.  Place the querys to
            // send to the servers into requeststrs.  Return 0 on success,
            // non-0 on failure.
            int pir_query(std::vector<std::string> &requeststrs,
                const std::vector<unsigned int> &bucketnums);

            // The glue API to the PIR layer.  Pass the responses from the
            // servers into responsestrs.  buckets will be filled with the
            // contents of the buckets indexed by bucketnums.  Return 0 on
            // success, non-0 on failure.
            int pir_response(std::vector<std::string> &buckets,
                const std::vector<std::string> &responses);

        private:
            // The number of lookup servers
            unsigned int _num_servers;

            // The privacy level to use
            unsigned int _privacy_level;

            // FIXME: should be derivable from metadata
            unsigned int _record_size;

            // The PercyClientParams, constructed from the above pieces
            PercyClientParams *_pirparams;

            // The PercyClient in use
            PercyClientGF28 *_pirclient;

            Metadata _metadata_current;
        };

        template<typename BuddyKey>
        struct BuddyPresence {
            // A buddy's public key
            BuddyKey pubkey;
            // Is the buddy reporting to us that he/she is online?
            bool is_online;
            // If is_online is true, the plaintext associated data goes here
            std::string data;
        };

        template<typename BuddyKey, typename MyPrivKey>
        class GenericLookupClient;  // forward declarationma

        template<typename BuddyKey, typename MyPrivKey>
        class LookupRequest {
        private:
            struct BuddyState {
                BuddyKey pubkey;
                HashKey key;
                unsigned int bucket;
                unsigned int position;
            };

            friend class GenericLookupClient<BuddyKey,MyPrivKey>;
#ifdef TEST_REQCD
            friend void test_reqcd(LookupRequest &a);
#endif // TEST_REQCD

            vector<BuddyState> _buddy_states;

            PIRRequest pir_request;
            bool _do_PIR;
            Metadata _metadata;
            unsigned int _num_servers;
            unsigned int _privacy_level;
            MyPrivKey _privkey;


            // Initialize the Request object
            void init(unsigned int num_servers, unsigned int privacy_level,
                const Metadata &metadata,
                const std::vector<BuddyState> & buddy_states, bool do_PIR,
                const MyPrivKey & privkey) {
                _do_PIR = do_PIR;
                _buddy_states = buddy_states;
                _metadata = metadata;
                _num_servers = num_servers;
                _privacy_level = privacy_level;
                _privkey = privkey;
                if (_do_PIR) {
                    pir_request.init(num_servers, privacy_level,
                        metadata, HASHKEY_BYTES + metadata.dataenc_bytes);
                }
            }

            int get_data(string & data, const BuddyState & buddy,
                const string & ciphertext);

        public:
            // default constructors work for us

            // Get the messages to send to the lookup servers.  Send the ith
            // entry of the resulting vector to lookup server i, unless the
            // ith entry is the empty string (in which case don't send
            // anything to server i, and set the corresponding reply to the
            // empty string in lookup_reply).
            std::vector<std::string> get_msgs();
            // Process the replies to yield the BuddyPresence information.
            // This may only be called once for a given Request object.
            // The order of the reply messages must correspond to that of
            // the messages produced by get_msgs().  That is, the ith entry
            // of the result of get_msgs() should be sent to lookup server
            // i, and its response should be the ith entry of replies.  If a
            // server does not reply, put the empty string as that entry.
            // Return 0 on success, non-0 on error.
            int lookup_reply(std::vector<BuddyPresence<BuddyKey> > &presence,
                const std::vector<std::string> &replies);

        };


        template<typename BuddyKey, typename MyPrivKey>
        class GenericLookupClient {
        private:
            unsigned int _metadata_request_epoch;

            Metadata _metadata;
            MyPrivKey _privkey;

        public:
            GenericLookupClient(const MyPrivKey & privkey) :
                _privkey(privkey) {}

            void metadata_request(string &msgtosend, Epoch epoch);
            // Consume the reply to a metadata request.  Return 0 on success,
            // non-0 on failure.
            int metadata_reply(const std::string &metadata);

            // Look up some number of buddies.  Pass in the vector of buddies'
            // public keys, the number of lookup servers there are, and the
            // privacy level to use (the privacy level is the maximum number of
            // lookup servers that can collude without learning what you are
            // looking up).  It must be the case that privacy_level <
            // num_servers.  req will be filled in with a new Request object.
            // Use the get_msgs method on that object to obtain the messages to
            // send to the servers, and the lookup_reply method on that object
            // to obtain the BuddyPresence information.  Return 0 on success,
            // non-0 on failure.
            int lookup_request(LookupRequest<BuddyKey,MyPrivKey> & req,
                const std::vector<BuddyKey> & buddies,
                unsigned int num_servers, unsigned int privacy_level);

            typedef BuddyPresence<BuddyKey> Presence;
            typedef LookupRequest<BuddyKey,MyPrivKey> Request;

        private:
            int buddy_hash_key(HashKey hashkey, const BuddyKey & buddy_key);

        };

        // placeholder for private key
        struct Empty {
        };

    }   // namespace dp5::internal

    typedef internal::GenericLookupClient<PubKey,PrivKey> DP5LookupClient;

    class DP5CombinedLookupClient : public internal::GenericLookupClient<BLSPubKey,internal::Empty> {
    public:
        DP5CombinedLookupClient() : internal::GenericLookupClient<BLSPubKey,internal::Empty>(internal::Empty())
            {}
    };

}

#endif
/*



        template<typename BuddyKey>
    class DP5GenericLookupClient {
    private:
        // The epoch number for which we have an outstanding metadata request,
        // or 0 if there is no outstanding metadata request
        unsigned int _metadata_request_epoch;


        Metadata _metadata;

    public:

        struct BuddyPresence {
            // A buddy's public key
            BuddyKey pubkey;
            // Is the buddy reporting to us that he/she is online?
            bool is_online;
            // If is_online is true, the plaintext associated data goes here
            std::string data;
        };

        // A class representing an in-progress lookup request
        class Request {
        private:
            typedef PercyClient_GF2E<GF28_Element> PercyClientGF28;

        public:
            Request(): _pirparams(NULL), _pirclient(NULL) {}

            ~Request() {
               delete _pirparams;
               delete _pirclient;
            }

            Request(const Request &other) {
                _num_servers = other._num_servers;
                _privacy_level = other._privacy_level;
                _metadata_current = other._metadata_current;
                _friends = other._friends;
                _do_PIR = other._do_PIR;

                _pirparams = NULL;
                if (other._pirparams) {
                    _pirparams = new PercyClientParams(*other._pirparams);
                }
                _pirclient = NULL;
                if (other._pirclient) {
                    _pirclient = new PercyClientGF28(*other._pirclient);
                }
            }

            Request& operator=(Request other) {
                // Swap the fields of the temporary "other" with ours
                // so things get properly freed

                PercyClientParams *tmpc = other._pirparams;
                other._pirparams = _pirparams;
                _pirparams = tmpc;

                PercyClientGF28 *tmpcl = other._pirclient;
                other._pirclient = _pirclient;
                _pirclient = tmpcl;

                // The non-dynamic members can be just copied
                _num_servers = other._num_servers;
                _privacy_level = other._privacy_level;
                _metadata_current = other._metadata_current;
                _friends = other._friends;
                _do_PIR = other._do_PIR;
                return *this;
            }

            // FIXME: these should not be visible to clients
            struct Friend_state {
                BuddyKey pubkey;
                SharedKey shared_key;
                DataKey data_key;
                HashKey HKi;
                unsigned int bucket;
                unsigned int position;
            };

            // Initialize the Request object
            void init(unsigned int num_servers, unsigned int privacy_level,
                const Metadata &metadata,
                const std::vector<Friend_state> &friends, bool do_PIR) {
                _do_PIR = do_PIR;
                _friends = friends;
                _num_servers = num_servers;
                _privacy_level = privacy_level;
                _metadata_current = metadata;
                _pirparams = new PercyClientParams(
                  _metadata_current.bucket_size *
                  (internal::HASHKEY_BYTES + _metadata_current.dataenc_bytes),
                  _metadata_current.num_buckets, 0, to_ZZ(256), MODE_GF28,
                  NULL, false);

                _pirclient = (PercyClientGF28*)PercyClient::make_client(
                   *_pirparams, _num_servers, _privacy_level);
            }


        private:

            // The internal state of the fiends, inc. keys and bukets
            std::vector<Friend_state> _friends;

            // Flag indicating we do PIR, and not download.
            bool _do_PIR;

            // The number of lookup servers
            unsigned int _num_servers;

            // The privacy level to use
            unsigned int _privacy_level;

            // The PercyClientParams, constructed from the above pieces
            PercyClientParams *_pirparams;

            // The PercyClient in use
            PercyClientGF28 *_pirclient;

            dp5::internal::Metadata _metadata_current;

            // The glue API to the PIR layer.  Pass a vector of the bucket
            // numbers to look up.  This should already be padded to one of
            // the valid sizes listed in QUERY_SIZES.  Place the querys to
            // send to the servers into requeststrs.  Return 0 on success,
            // non-0 on failure.
            int pir_query(std::vector<std::string> &requeststrs,
                const std::vector<unsigned int> &bucketnums);

            // The glue API to the PIR layer.  Pass the responses from the
            // servers into responsestrs.  buckets will be filled with the
            // contents of the buckets indexed by bucketnums.  Return 0 on
            // success, non-0 on failure.
            int pir_response(std::vector<std::string> &buckets,
                const std::vector<std::string> &responses);
#ifdef TEST_PIRGLUE
            friend void test_pirglue();
#endif // TEST_PIRGLUE
#ifdef TEST_PIRGLUEMT
            friend void test_pirgluemt();
#endif // TEST_PIRGLUEMT

        };

        // These will be specialized to throw an error
        DP5GenericLookupClient(const MyPrivKey & privkey);
        DP5GenericLookupClient();


        // Create a request for the metadata file.  This (and the next
        // method) must complete in each epoch before invoking the lookup
        // functions.
        void metadata_request(std::string &msgtosend, unsigned int epoch);

        // Consume the reply to a metadata request.  Return 0 on success,
        // non-0 on failure.
        int metadata_reply(const std::string &metadata);


private:
    int buddy_bucket(const BuddyKey & key);

#ifdef TEST_REQCD
friend void test_reqcd(Request &a);
#endif // TEST_REQCD
#ifdef TEST_PIRGLUE
friend void test_pirglue();
#endif // TEST_PIRGLUE
#ifdef TEST_PIRGLUEMT
friend void test_pirgluemt();
#endif // TEST_PIRGLUEMT

};
}

    typedef internal::DP5GenericLookupClient<PrivKey, PubKey> DP5LookupClient;
}

#endif
*/
