#include "dp5params.h"
#include "dp5combregclient.h"
#include <Pairing.h>
#include "gtest/gtest.h"

using namespace dp5;
using namespace dp5::internal;

class CombRegClient : public ::testing::Test {
protected:
	Pairing pairing; // this will make sure core is initialized
	unsigned char blskey[PRIVKEY_BYTES];
	unsigned char prekey[PREKEY_BYTES];
	virtual void SetUp(void) {
		Zr keyzr(23);
		keyzr.toBin((char *) blskey);
		memset(prekey, 0x23, PREKEY_BYTES);
	}
};

TEST_F(CombRegClient, Constructor) {
	DP5CombinedRegClient client(blskey, prekey);
}

TEST_F(CombRegClient, StartReg) {
	DP5CombinedRegClient client(blskey, prekey);

	string result;
	string data(16, 0x0);

	EXPECT_EQ(client.start_reg(result, 0, data), 0);
	EXPECT_EQ(result.length(), EPOCH_BYTES + EPOCH_SIG_BYTES + 16);
}

TEST_F(CombRegClient, FinishReg) {
	DP5CombinedRegClient client(blskey, prekey);

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
