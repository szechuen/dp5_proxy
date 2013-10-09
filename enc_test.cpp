#include <string.h>

#include "dp5params.h"

#include "gtest/gtest.h"

using namespace dp5;
using namespace dp5::internal;
using namespace std;

TEST(EncryptionTest, GCMTestVector1) {
    byte key_bytes[DATAKEY_BYTES];
    memset(key_bytes, 0, sizeof(key_bytes));
    string result = Enc(key_bytes, ""); // encrypt zero-length text
    EXPECT_EQ(result.size(), 16); // should contain only the tag
    EXPECT_EQ(result, "\x58\xe2\xfc\xce\xfa\x7e\x30\x61\x36\x7f\x1d\x57\xa4\xe7\x45\x5a");
}

TEST(EncryptionTest, GCMTestVector2) {
    byte key_bytes[DATAKEY_BYTES];
    memset(key_bytes, 0, sizeof(key_bytes));
    string plaintext(16u, (char) 0);
    string result = Enc(key_bytes, plaintext);
    EXPECT_EQ(result.size(), 32);
    EXPECT_EQ(result, "\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf");
}

TEST(EncryptionTest, EncDecTest) {
    byte key_bytes[DATAKEY_BYTES];
    for (unsigned i = 0; i < sizeof(key_bytes); i++) {
        key_bytes[i] = i + 0x33;
    }
    string plaintext;
    for (unsigned i = 0; i < 32; i++) {
        plaintext.push_back(i + 0x55);
    }
    string ciphertext = Enc(key_bytes, plaintext);
    EXPECT_EQ(ciphertext.size(), plaintext.size() + ENCRYPTION_OVERHEAD);
    string plaintext2;
    EXPECT_EQ(Dec(plaintext2, key_bytes, ciphertext), 0);
    EXPECT_EQ(plaintext2, plaintext);
}
