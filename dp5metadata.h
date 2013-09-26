#ifndef __DP5_METADATA__
#define __DP5_METADATA__

namespace dp5 {

    // Runtime configurable variables
    struct DP5Config {
        unsigned int epoch_len;
        unsigned int dataenc_bytes;

        unsigned int current_epoch();
    };

    namespace internal {
        // Metadata for a given database

        struct _MetadataStruct : public DP5Config {
            PRFKey prfkey;
            unsigned int epoch;
            unsigned int num_buckets;
            unsigned int bucket_size;
        };

        static const unsigned int UINT_BYTES = 4;
        static const unsigned int METADATA_VERSION = 0x02;
        class Metadata : public DP5Config {
            Metadata(std::istream & is);

            Metadata(const std::string & metadata);

            Metadata();  // Sets default values

            Metadata(const Metadata & other);

            Metadata(const DP5Config & config);

            void fromStream(std::istream & is);
            void toStream(std::ostream & os) const;
            std::string toString(void) const;
            void fromString(const std::string & str);
        };

        unsigned int read_uint(std::istream & is);
        void write_uint(std::ostream & os, unsigned int n);
        unsigned int read_epoch(std::istream & is);
        void write_epoch(std::ostream & os, unsigned int epoch);

        // Convert an uint number to an uint byte array in network order
        void uint_num_to_bytes(char uint_bytes[UINT_BYTES],
           unsigned int uint_num);

        // Convert an uint byte array in networkorder to an uint number
        unsigned int uint_bytes_to_num(const char uint_bytes[UINT_BYTES]);

    }
}

#endif
