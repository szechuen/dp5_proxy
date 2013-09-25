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
		int len = 2 + PRFKEY_BYTES + DP5Metadata::UINT_BYTES*4 + DP5Metadata::EPOCH_BYTES;
		valid_metadata.push_back(DP5Metadata::METADATA_VERSION);
		valid_metadata.push_back(1);
		for (int i = 2; i < len; i++) {
			valid_metadata.push_back(i);
		}
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
	string short_metadata(valid_metadata);
	short_metadata.erase(short_metadata.end()-1, short_metadata.end());
	ASSERT_EQ(valid_metadata.length()-1, short_metadata.length());
	EXPECT_THROW({ DP5Metadata md(short_metadata); }, runtime_error);
}

TEST_F(MetadataTest, StringConstructorValidInput) {
	DP5Metadata md(valid_metadata);
	EXPECT_EQ(md.usePairing, true);
	EXPECT_EQ(md.epoch, (unsigned) 0x02030405);
}

TEST_F(MetadataTest, ConsistentInOut) {
	DP5Metadata md(valid_metadata);

	string s = md.toString();
	EXPECT_EQ(s, valid_metadata);	
}



