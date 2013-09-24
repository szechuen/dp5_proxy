#include "dp5params.h"
#include "dp5combregclient.h"
#include <Pairing.h>
#include "gtest/gtest.h"

class CombRegClient : public ::testing::Test, public DP5Params {
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