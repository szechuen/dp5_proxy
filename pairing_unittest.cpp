#include "dp5params.h"
#include <Pairing.h>
#include "gtest/gtest.h"

using namespace dp5;
using namespace dp5::internal;

TEST(H4Test, ZeroInput) {
	unsigned char verifybytes[SIG_VERIFY_BYTES];

	memset(verifybytes, 0, SIG_VERIFY_BYTES);

	unsigned char H4_out[HASHKEY_BYTES];

	H4(H4_out, verifybytes);

	// Digest obtained using python + hashlib
	EXPECT_EQ(memcmp(H4_out, "%\x1d\x0b\t?Q\x1f\xc2,g\xc5\xaa\x98\xfc\x15\x15l\xb6\xe8kW\x81Q\xa6\xd1\x17\x86\x05|\xed|\x12", HASHKEY_BYTES), 0);
}

/*
TEST(H5Test, ZeroInput) {
	unsigned char prekey[PREKEY_BYTES];
	unsigned char H5_out[DATAKEY_BYTES];

	Epoch e = 0;

	memset(prekey, 0, PREKEY_BYTES);

	H5(H5_out, e, prekey);

	// Digest obtained using python + hashlib
	EXPECT_EQ(memcmp(H5_out, "\xa0\x8f\xcb\x1aS3\x8a\x00t\xa8\xfd" "D\xf5\xab\xe8\x8c\xafI\x85\xebq\xb1" "8\xe5\xd2" "5UZgj\x96g'", DATAKEY_BYTES), 0);
}
*/

class BLSTest : public ::testing::Test {
protected:
	Pairing pairing;
	unsigned char E[EPOCH_BYTES];
	unsigned char epoch_sig_bytes[EPOCH_SIG_BYTES];
	unsigned char pubkey_bytes[BLS_PUB_BYTES];
	BLSPubKey pubkey2;

	virtual void SetUp() {
		Zr exponent(23);
		epoch_num_to_bytes(E, 0);

		G2 epoch_hash(pairing, E, EPOCH_BYTES);

		G2 epoch_sig = epoch_hash ^ exponent;
		epoch_sig.toBin((char *) epoch_sig_bytes);

		G1 pubkey = pairing.g1_get_gen() ^ exponent;
		pubkey.toBin((char *) pubkey_bytes);
		pubkey2.assign(pubkey_bytes, BLS_PUB_BYTES);

	}
};
TEST_F(BLSTest, HashSigNoError) {
	unsigned char hashkey[HASHKEY_BYTES];
	EXPECT_EQ(hash_key_from_sig(hashkey, epoch_sig_bytes), 0);
}

TEST_F(BLSTest, HashPKNoError) {
	unsigned char hashkey[HASHKEY_BYTES];
	EXPECT_EQ(hash_key_from_pk(hashkey, pubkey2, 0), 0);
}

TEST_F(BLSTest, HashSigPKEqual) {
	unsigned char hashkeysig[HASHKEY_BYTES];
	ASSERT_EQ(hash_key_from_sig(hashkeysig, epoch_sig_bytes), 0);
	unsigned char hashkeypk[HASHKEY_BYTES];
	ASSERT_EQ(hash_key_from_pk(hashkeypk, pubkey2, 0), 0);

	EXPECT_EQ(memcmp(hashkeysig, hashkeypk, HASHKEY_BYTES), 0);
}

TEST_F(BLSTest, HashSigErrorInvalid) {
	unsigned char hashkey[HASHKEY_BYTES];
	memset(epoch_sig_bytes, 0, EPOCH_SIG_BYTES);
	epoch_sig_bytes[0] = 1;

	EXPECT_NE(hash_key_from_sig(hashkey, epoch_sig_bytes), 0);
}

TEST_F(BLSTest, HashPKErrorInvalid) {
	unsigned char hashkey[HASHKEY_BYTES];
	BLSPubKey pubkey3;
	pubkey3[0u] = 1;

	EXPECT_NE(hash_key_from_pk(hashkey, pubkey3, 0), 0);
}
