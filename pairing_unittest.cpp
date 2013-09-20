#include "dp5params.h"
#include "gtest/gtest.h"

TEST(H4Test, ZeroInput) {
	unsigned char verifybytes[DP5Params::SIG_VERIFY_BYTES];

	memset(verifybytes, 0, DP5Params::SIG_VERIFY_BYTES);

	unsigned char H4_out[DP5Params::HASHKEY_BYTES];

	DP5Params::H4(H4_out, verifybytes);

	// Digest obtained using python + hashlib
	EXPECT_EQ(memcmp(H4_out, "%\x1d\x0b\t?Q\x1f\xc2,g\xc5\xaa\x98\xfc\x15\x15l\xb6\xe8kW\x81Q\xa6\xd1\x17\x86\x05|\xed|\x12", DP5Params::HASHKEY_BYTES), 0);
}

TEST(H5Test, ZeroInput) {
	unsigned char E[DP5Params::EPOCH_BYTES];
	unsigned char prekey[DP5Params::PREKEY_BYTES];
	unsigned char H5_out[DP5Params::DATAKEY_BYTES];

	memset(E, 0, DP5Params::EPOCH_BYTES);
	memset(prekey, 0, DP5Params::PREKEY_BYTES);

	DP5Params::H5(H5_out, E, prekey);

	// Digest obtained using python + hashlib
	EXPECT_EQ(memcmp(H5_out, "\xa0\x8f\xcb\x1aS3\x8a\x00t\xa8\xfd" "D\xf5\xab\xe8\x8c\xafI\x85\xebq\xb1" "8\xe5\xd2" "5UZgj\x96g'", DP5Params::DATAKEY_BYTES), 0);
}