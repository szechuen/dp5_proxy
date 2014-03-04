#include "dp5lookupserver.h"

#include "gtest/gtest.h"

using namespace dp5;
using namespace dp5::internal;

#include <unistd.h>

class EmptyFileTest : public ::testing::Test {
protected:
    string metadatafilename;
    string datafilename;
    static const int epoch = 1234;

    virtual void SetUp() {
        char tempmetadata[] = "/tmp/.dp5.metadata.XXXXXXX";
        char tempdata[] = "/tmp/.dp5.data.XXXXXXXX";

        int metadatafd = mkstemp(tempmetadata);
        ASSERT_GE(metadatafd, 0);   // fail out if mkstemp failed

        Metadata metadata;
        metadata.epoch = epoch;
        metadata.num_buckets = 0;
        metadata.bucket_size = 0;

        string metadataStr = metadata.toString();

        write(metadatafd, metadataStr.c_str(), metadataStr.length());
        close(metadatafd);

        int datafd = mkstemp(tempdata);
        ASSERT_GE(datafd, 0);

        close(datafd); // keep data file empty

        metadatafilename.assign(tempmetadata, strlen(tempmetadata));
        datafilename.assign(tempdata, strlen(tempdata));
    }

    virtual void TearDown() {
        unlink(metadatafilename.c_str());
        unlink(datafilename.c_str());
    }
};

TEST_F(EmptyFileTest, Constructor) {
    DP5LookupServer ls(metadatafilename.c_str(), datafilename.c_str());
}

TEST_F(EmptyFileTest, PIRRequest) {
    DP5LookupServer ls(metadatafilename.c_str(), datafilename.c_str());
    unsigned char request[5];
    request[0] = 0xfe;
    epoch_num_to_bytes(request+1, epoch);
    string requeststr((char *) request, 5);
    string reply;

    ls.process_request(reply, requeststr);

    // error expected
    EXPECT_EQ(reply[0], '\x80');
}

TEST_F(EmptyFileTest, Download) {
    DP5LookupServer ls(metadatafilename.c_str(), datafilename.c_str());
    unsigned char request[5];
    request[0] = 0xfd;
    epoch_num_to_bytes(request+1, epoch);
    string requeststr((char *) request, 5);
    string reply;

    ls.process_request(reply, requeststr);

    EXPECT_EQ(reply[0], '\x82');
    EXPECT_EQ(reply.length(), 5);
}

