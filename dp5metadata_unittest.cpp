#include <stdexcept>
#include <sstream>

#include "dp5metadata.h"
#include "gtest/gtest.h"

using namespace std;

using namespace dp5;
using namespace dp5::internal;

TEST(TestConfig, DefaultConstructor) {
    DP5Config dp5;
    EXPECT_EQ(dp5.epoch_len, 0u);
    EXPECT_EQ(dp5.dataenc_bytes, 0u);
}

TEST(TestConfig, CopyConstructor) {
    DP5Config dp5;
    dp5.epoch_len = 1234;
    dp5.dataenc_bytes = 5678;

    DP5Config copy(dp5);
    EXPECT_EQ(dp5.epoch_len, copy.epoch_len);
    EXPECT_EQ(dp5.dataenc_bytes, copy.dataenc_bytes);
}

TEST(TestConfig, Valid) {
    DP5Config invalid;
    EXPECT_EQ(invalid.valid(), false);

    DP5Config valid;
    valid.epoch_len = 1234;

    EXPECT_EQ(valid.valid(), true);
}

TEST(TestConfig, CurrentEpoch) {
    DP5Config dp5;

    EXPECT_THROW(dp5.current_epoch(), runtime_error);

    dp5.epoch_len = 1234;
    EXPECT_NE(dp5.current_epoch(), 0u);
}

TEST(TestUint, ToFromBytes) {
    unsigned int test_uint = 0x5678;
    unsigned char bytes[UINT_BYTES];
    uint_num_to_bytes(bytes, test_uint);
    EXPECT_EQ(bytes[UINT_BYTES-1], 0x78);
    EXPECT_EQ(bytes[UINT_BYTES-2], 0x56);
    EXPECT_EQ(uint_bytes_to_num(bytes), test_uint);

    if (UINT_BYTES >= 4) {
        test_uint = 0x12345678;
        uint_num_to_bytes(bytes, test_uint);
        EXPECT_EQ(bytes[UINT_BYTES-1], 0x78);
        EXPECT_EQ(bytes[UINT_BYTES-2], 0x56);
        EXPECT_EQ(bytes[UINT_BYTES-3], 0x34);
        EXPECT_EQ(bytes[UINT_BYTES-4], 0x12);
        EXPECT_EQ(uint_bytes_to_num(bytes), test_uint);
    }
}

TEST(TestUint, ReadWrite) {
    string s(UINT_BYTES, 0);
    s[UINT_BYTES-1] = 0x78;
    s[UINT_BYTES-2] = 0x56;
    unsigned int expected = 0x5678;
    if (UINT_BYTES >= 4) {
        s[UINT_BYTES-3] = 0x34;
        s[UINT_BYTES-4] = 0x12;
        expected = 0x12345678;
    }
    stringstream stream(s);
    EXPECT_EQ(read_uint(stream), expected);

    stringstream ostream;
    write_uint(ostream, expected);
    EXPECT_EQ(ostream.str(), s);
}

TEST(TestUint, ReadWriteEpoch) {
    string s("\x12\x34\x56\x78");
    Epoch epoch = 0x12345678;
    s[UINT_BYTES-1] = 0x78;
    s[UINT_BYTES-2] = 0x56;
    s[UINT_BYTES-3] = 0x34;
    s[UINT_BYTES-4] = 0x12;
    stringstream stream(s);
    EXPECT_EQ(read_epoch(stream), epoch);

    stringstream ostream;
    write_epoch(ostream, epoch);
    EXPECT_EQ(ostream.str(), s);
}


class MetadataTest : public ::testing::Test {
protected:
    string valid_metadata;

    virtual void SetUp(void) {
        int len = 1 + PRFKEY_BYTES + UINT_BYTES*4 + EPOCH_BYTES;
        valid_metadata.push_back(METADATA_VERSION);
        for (int i = 1; i < len; i++) {
            valid_metadata.push_back(i);
        }
    }
};

TEST_F(MetadataTest, DefaultConstructor) {
    Metadata md;
    EXPECT_EQ(md.bucket_size, 0u);
    EXPECT_EQ(md.num_buckets, 0u);
    EXPECT_EQ(md.epoch, 0u);
    PRFKey zeroes;
    memset(zeroes, 0, sizeof(PRFKey));
    EXPECT_EQ(memcmp(md.prfkey, zeroes, sizeof(PRFKey)), 0);
}

TEST_F(MetadataTest, CopyConstructor) {
    Metadata md1;

    memset(md1.prfkey, 0x23, sizeof(md1.prfkey));
    md1.epoch = 1234;
    md1.epoch_len = 5678;
    md1.num_buckets = 44;
    md1.bucket_size = 66;

    Metadata md2(md1);
    EXPECT_EQ(memcmp(md1.prfkey, md2.prfkey, sizeof(PRFKey)), 0);
    EXPECT_EQ(md1.epoch, md2.epoch);
    EXPECT_EQ(md1.epoch_len, md2.epoch_len);
    EXPECT_EQ(md1.num_buckets, md2.num_buckets);
    EXPECT_EQ(md1.bucket_size, md2.bucket_size);
}

TEST_F(MetadataTest, FromStream) {
    stringstream stream(valid_metadata);

    Metadata md;

    EXPECT_EQ(md.fromStream(stream), 0);
}

TEST_F(MetadataTest, FromString) {
    Metadata md;
    EXPECT_EQ(md.fromString(valid_metadata), 0);
}

TEST_F(MetadataTest, FromStringInvalid) {
    Metadata md;
    EXPECT_NE(md.fromString(""), 0);
    string short_metadata(valid_metadata);
    short_metadata.erase(short_metadata.end()-1, short_metadata.end());
    ASSERT_EQ(valid_metadata.length()-1, short_metadata.length());
    EXPECT_NE(md.fromString(short_metadata), 0);

    string wrongversion(valid_metadata);
    wrongversion[0] = 0;
    EXPECT_NE(md.fromString(wrongversion), 0);
}

TEST_F(MetadataTest, ToString) {
    Metadata md;
    md.fromString(valid_metadata);
    EXPECT_EQ(md.toString(), valid_metadata);
}

TEST_F(MetadataTest, StringConstructor) {
    Metadata md(valid_metadata);

    EXPECT_THROW( { Metadata md2(""); }, runtime_error);
}

TEST_F(MetadataTest, StreamConstructor) {
    stringstream stream(valid_metadata);
    Metadata md(stream);    // no throw

    // now the stream is empty, should throw
    EXPECT_THROW( { Metadata md2(stream); }, runtime_error);
}

TEST_F(MetadataTest, ConfigConstructor) {
    DP5Config config;
    config.epoch_len = 1234;
    config.dataenc_bytes = 5678;
    Metadata md(config);

    EXPECT_EQ(md.epoch_len, config.epoch_len);
    EXPECT_EQ(md.dataenc_bytes, config.dataenc_bytes);
}
