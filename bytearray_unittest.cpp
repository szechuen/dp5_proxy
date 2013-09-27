#include "dp5util.h"
#include "gtest/gtest.h"

using namespace std;
using namespace dp5::internal;

template<typename T>
class ByteArrayTest : public ::testing::Test {
public:
    string teststring;

    virtual void SetUp() {
        for (unsigned int i = 0; i < T::size; i++) {
            teststring.push_back(i);
        }
    }
};

typedef ::testing::Types<ByteArray<1>,
    ByteArray<2>, ByteArray<20>, ByteArray<100> > ByteArraySizes;

TYPED_TEST_CASE(ByteArrayTest, ByteArraySizes);

TYPED_TEST(ByteArrayTest, DefaultConstructor) {
    TypeParam array;

    for (unsigned int i = 0; i < array.size; i++) {
        EXPECT_EQ(array[i], (byte) 0);
    }
}

TYPED_TEST(ByteArrayTest, CopyConstructor) {
    TypeParam initial;

    for (unsigned int i = 0; i < initial.size; i++) {
        initial[i] = i;
    }
    TypeParam copy(initial);

    for (unsigned int i = 0; i < initial.size; i++) {
        EXPECT_EQ(initial[i], copy[i]);
    }
}

TYPED_TEST(ByteArrayTest, StringConstructor) {
    TypeParam array(this->teststring);

    for (unsigned i = 0; i < array.size; i++) {
        EXPECT_EQ((byte) this->teststring[i], array[i]);
    }

    string shortstring(this->teststring);
    shortstring.erase(shortstring.end() - 1, shortstring.end());

    EXPECT_THROW({ TypeParam shortArray(shortstring); }, domain_error);
    if (array.size > 0) {
        EXPECT_THROW({ TypeParam shortArray(""); }, domain_error);
    }
}

TYPED_TEST(ByteArrayTest, ConstOperator) {
    const TypeParam constarray(this->teststring);

    for (unsigned i = 0; i < constarray.size; i++) {
        EXPECT_EQ((byte) this->teststring[i], constarray[i]);
    }

    EXPECT_THROW({ byte x = constarray[constarray.size]; x++; }, out_of_range);
}

TYPED_TEST(ByteArrayTest, Operator) {
    TypeParam array(this->teststring);
    string swapped(this->teststring);

    for (unsigned i = 0; i < array.size; i++) {
        swap(array[i], array[array.size-i-1]);
        swap(swapped[i], swapped[array.size-i-1]);
        array[i] += 7;
        swapped[i] += 7;
    }

    for (unsigned i = 0; i < array.size; i++) {
        EXPECT_EQ(array[i], swapped[i]);
    }
}

TYPED_TEST(ByteArrayTest, OperatorString) {
    const TypeParam array(this->teststring);
    string result = array;
    EXPECT_EQ(result, this->teststring);
}

TYPED_TEST(ByteArrayTest, OperatorByte) {
    const TypeParam array(this->teststring);
    const byte * result = array;

    for (unsigned i = 0; i < array.size; i++) {
        EXPECT_EQ(result[i], (byte) this->teststring[i]);
    }
}
