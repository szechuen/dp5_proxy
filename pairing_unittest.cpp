#include "dp5params.h"
#include <Pairing.h>
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

class BLSTest : public ::testing::Test {
protected:
	Pairing pairing;
	unsigned char E[DP5Params::EPOCH_BYTES];
	unsigned char epoch_sig_bytes[DP5Params::EPOCH_SIG_BYTES];
	unsigned char pubkey_bytes[DP5Params::BLS_PUB_BYTES];

	virtual void SetUp() {
		Zr exponent(23);
		DP5Params::epoch_num_to_bytes(E, 0);

		G2 epoch_hash(pairing, E, DP5Params::EPOCH_BYTES);

		G2 epoch_sig = epoch_hash ^ exponent;
		epoch_sig.toBin((char *) epoch_sig_bytes);

		G1 pubkey = pairing.g1_get_gen() ^ exponent;
		pubkey.toBin((char *) pubkey_bytes);
	}
};
TEST_F(BLSTest, HashSigNoError) {
	unsigned char hashkey[DP5Params::HASHKEY_BYTES];
	EXPECT_EQ(DP5Params::hash_key_from_sig(hashkey, epoch_sig_bytes), 0);
}

TEST_F(BLSTest, HashPKNoError) {
	unsigned char hashkey[DP5Params::HASHKEY_BYTES];
	EXPECT_EQ(DP5Params::hash_key_from_pk(hashkey, pubkey_bytes, 0), 0);
}

TEST_F(BLSTest, HashSigPKEqual) {
	unsigned char hashkeysig[DP5Params::HASHKEY_BYTES];
	ASSERT_EQ(DP5Params::hash_key_from_sig(hashkeysig, epoch_sig_bytes), 0);
	unsigned char hashkeypk[DP5Params::HASHKEY_BYTES];
	ASSERT_EQ(DP5Params::hash_key_from_pk(hashkeypk, pubkey_bytes, 0), 0);

	EXPECT_EQ(memcmp(hashkeysig, hashkeypk, DP5Params::HASHKEY_BYTES), 0);
}