#include "dp5lookupserver.h"

#include "gtest/gtest.h"

using namespace dp5;
using namespace dp5::internal;

#include <unistd.h>

class EmptyFileTest : public ::testing::Test {
protected:
    string metadatafilename;
    string datafilename;

    virtual void SetUp() {
        char tempmetadata[] = "/tmp/.dp5.metadata.XXXXXXX";
  //      char tempdata[] = "/tmp/.dp5.data.XXXXXXXX";

        int metadatafd = mkstemp(tempmetadata);
        ASSERT_GE(metadatafd, 0);   // fail out if mkstemp failed

        Metadata metadata;
        metadata.num_buckets = 0;
        metadata.bucket_size = 0;

        string metadataStr = metadata.toString();

        write(metadatafd, metadataStr.c_str(), metadataStr.length());
        close(metadatafd);

        metadatafilename.assign(tempmetadata, strlen(tempmetadata));
    }

    virtual void TearDown() {
        unlink(metadatafilename.c_str());
    }
};

TEST_F(EmptyFileTest, Constructor) {
    DP5LookupServer ls(metadatafilename.c_str(), datafilename.c_str());

}
