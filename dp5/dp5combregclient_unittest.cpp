#include "dp5params.h"
#include "dp5combregclient.h"
#include <Pairing.h>
#include "gtest/gtest.h"

using namespace dp5;
using namespace dp5::internal;

class CombRegClient : public ::testing::Test {
protected:
	unsigned char blskey_bytes[BLS_PRIV_BYTES];
	BLSPrivKey blskey;
	virtual void SetUp(void) {
		initPairing();
		Zr keyzr(23);
		keyzr.toBin((char *) blskey_bytes);
		blskey.assign(blskey_bytes, BLS_PRIV_BYTES);
	}
};

TEST_F(CombRegClient, Constructor) {
	DP5CombinedRegClient client(blskey);
}

TEST_F(CombRegClient, BadKey) {
	BLSPrivKey badkey;
	DP5CombinedRegClient client(badkey);

	string result;
	string data(16, 0x0);
	client.start_reg(result, 1234, data);
}

TEST_F(CombRegClient, StartReg) {
	DP5CombinedRegClient client(blskey);

	string result;
	string data(16, 0x0);

	EXPECT_EQ(client.start_reg(result, 0, data), 0);
	EXPECT_EQ(result.length(), EPOCH_BYTES + EPOCH_SIG_BYTES + data.size() + ENCRYPTION_OVERHEAD);
}

TEST_F(CombRegClient, FinishReg) {
	DP5CombinedRegClient client(blskey);

	// OK response for epoch 0
	EXPECT_EQ(client.complete_reg(string("\0\0\0\0\0", 5), 0), 0);
	// Server failure
	EXPECT_NE(client.complete_reg(string("\1\0\0\0\0", 5), 0), 0);
	// Epoch mismatch
	EXPECT_NE(client.complete_reg(string("\0\1\2\3\4", 5), 0), 0);
	// Wrong length
	EXPECT_NE(client.complete_reg(string(""), 0), 0);
	EXPECT_NE(client.complete_reg(string("abcdefghijklmonp"), 0), 0);
}
