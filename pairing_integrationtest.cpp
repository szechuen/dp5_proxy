#include "dp5combregclient.h"
#include "dp5regserver.h"
#include "gtest/gtest.h"
#include <unistd.h>
#include <Pairing.h>

class PairingIntegration : public ::testing::Test, public DP5Params {
protected:
	Pairing pairing;
	Zr blskey;
	unsigned char blsbytes[PRIVKEY_BYTES];
	unsigned char prekey[PREKEY_BYTES];
	unsigned char regdata[DATAPLAIN_BYTES];
	const char *regdir;
	const char *datadir;
	unsigned int epoch;
	virtual void SetUp(void) {
		regdir = "regdir.pairing_integration";
		datadir = "datadir.pairing_integration";
		epoch = 0x2323;
		blskey = 23;
		blskey.toBin((char *) blsbytes);
		memset(prekey, 0x23, PREKEY_BYTES);
		memset(regdata, '-', DATAPLAIN_BYTES);
		mkdir(regdir, 0700);
		mkdir(datadir, 0700);
	}
	// FIXME: teardown should wipe the directories!
};

TEST_F(PairingIntegration, RegIntegration) {
	DP5CombinedRegClient client(blsbytes, prekey);

	DP5RegServer server(epoch, regdir, datadir, true);

	string regmsg;
	EXPECT_EQ(client.start_reg(regmsg, epoch+1, regdata), 0);

	string result;
	server.client_reg(result, regmsg);

	EXPECT_EQ(client.complete_reg(result, epoch+1), 0);
}