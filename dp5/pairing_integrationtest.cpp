#include "dp5combregclient.h"
#include "dp5regserver.h"
#include "gtest/gtest.h"
#include <unistd.h>
#include <dirent.h>
#include <Pairing.h>

using namespace dp5;
using namespace dp5::internal;

static const unsigned int DATAPLAIN_BYTES = 16;

class PairingIntegration : public ::testing::Test {
protected:
	Pairing pairing;
	Zr blskey;
	unsigned char blsbytes[PRIVKEY_BYTES];
	unsigned char prekey[PREKEY_BYTES];
	string regdata;
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
		regdata.assign(DATAPLAIN_BYTES, '-');
		mkdir(regdir, 0700);
		mkdir(datadir, 0700);
	}

	virtual void TearDown(void) {
		erasedir(regdir);
		erasedir(datadir);
	}
private:
	void erasedir(const char * dirname) {
		DIR *dir;

		dir = opendir(dirname);
		if (dir != NULL) {
			while (1) {
				dirent *dentry = readdir(dir);
				if (dentry == NULL)
					break;
				string path = string(regdir) + "/" + string(dentry->d_name);
				unlink(path.c_str());
			}
		}
		closedir(dir);
		rmdir(dirname);
	}
	// FIXME: teardown should wipe the directories!
};

TEST_F(PairingIntegration, RegIntegration) {
	DP5CombinedRegClient client(blsbytes, prekey);

	DP5Config config;
	config.epoch_len = 1800;
	config.dataenc_bytes = 16;
	config.combined = true;

	DP5RegServer server(config, epoch, regdir, datadir);

	string regmsg;
	EXPECT_EQ(client.start_reg(regmsg, epoch+1, regdata), 0);

	string result;
	server.client_reg(result, regmsg);

	EXPECT_EQ(client.complete_reg(result, epoch+1), 0);
}
