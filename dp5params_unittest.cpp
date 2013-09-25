#include <iostream>
#include <string>
#include <stdexcept>
#include "dp5params.h"

#include "gtest/gtest.h"

using namespace std;

class MetadataTest : public ::testing::Test {
protected:
	string valid_metadata;

	virtual void SetUp(void) {
		valid_metadata.assign(0x23, 1 + PRFKEY_BYTES + DP5Metadata::UINT_BYTES*5 + 1);
	}
};

TEST_F(MetadataTest, DefaultConstructor) {
	DP5Metadata md;
}

TEST_F(MetadataTest, CopyConstructor) {
	DP5Metadata md1;

	memset(md1.prfkey, 0x23, sizeof(md1.prfkey));
	md1.epoch = 1234;
	md1.epoch_len = 5678;
	md1.usePairing = true;
	md1.num_buckets = 44;
	md1.bucket_size = 66;

	DP5Metadata md2(md1);
	EXPECT_EQ(memcmp(md1.prfkey, md2.prfkey, sizeof(PRFKey)), 0);
	EXPECT_EQ(md1.epoch, md2.epoch);
	EXPECT_EQ(md1.epoch_len, md2.epoch_len);
	EXPECT_EQ(md1.usePairing, md2.usePairing);
	EXPECT_EQ(md1.num_buckets, md2.num_buckets);
	EXPECT_EQ(md1.bucket_size, md2.bucket_size);	
}

TEST_F(MetadataTest, StringConstructorInvalidInput) {
	EXPECT_THROW({ DP5Metadata md(""); }, runtime_error);
}