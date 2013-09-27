#include "dp5lookupclient.h"


#include "gtest/gtest.h"

using namespace dp5;
using namespace dp5::internal;

typedef PubKey BuddyKey;

class LookupClientTest : public ::testing::Test {
protected:
	string metadata;
	string privkey;
	unsigned int epoch;
	vector<BuddyKey> validbuddy;
	vector<BuddyKey> randomPK;

	virtual void SetUp() {
		unsigned int len = 2 + EPOCH_BYTES + PRFKEY_BYTES + 4 * UINT_BYTES;
		metadata.assign(len, 0x01);
		metadata[0] = METADATA_VERSION;
		unsigned char epoch_bytes[EPOCH_BYTES];
		epoch = 0x2323;
		epoch_num_to_bytes(epoch_bytes, epoch);
		metadata.replace(2, 4, (char *) epoch_bytes, 4);
		privkey.assign(PRIVKEY_BYTES, 0x45);

		PubKey pubkey;
		PrivKey privkey;

		genkeypair(pubkey, privkey);
		validbuddy.push_back(pubkey);

		ZZ_p::init(to_ZZ(256));

		string buddy2;
		buddy2.assign(PUBKEY_BYTES, 0x55);
		randomPK.push_back(buddy2);
	}
};

TEST_F(LookupClientTest, ValidMetadata) {
	DP5LookupClient client(privkey);
	string metadata_request;

	// prime the client
	client.metadata_request(metadata_request, epoch);

	EXPECT_EQ(client.metadata_reply(metadata), 0);
}

TEST_F(LookupClientTest, LookupRequest) {
	DP5LookupClient client(privkey);
	string metadata_request;

	client.metadata_request(metadata_request, epoch);
	ASSERT_EQ(client.metadata_reply(metadata), 0);

	DP5LookupClient::Request request;

	// valid public key
	ASSERT_EQ(client.lookup_request(request, validbuddy, 2, 1), 0);

	ASSERT_EQ(client.lookup_request(request, randomPK, 2, 1), 0);
}
