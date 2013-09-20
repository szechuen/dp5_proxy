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