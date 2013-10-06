#ifndef __DP5UTIL__
#define __DP5UTIL__

#include <string>
#include <cstddef>
#include <cstring>
#include <stdexcept>

namespace dp5 {
    typedef unsigned char byte;

    namespace internal {

        template<std::size_t N>
        class ByteArray {
        private:
            byte data[N];

        public:
            ByteArray() {
                memset(data, 0, sizeof(data));
            }
            ByteArray(const ByteArray<N> & other) {
                memmove(data, other.data, sizeof(data));
            }
            // FIXME: this should eventually be explicit
            ByteArray(const std::string & str) {
                if (str.length() != N) {
                    throw std::domain_error("Constructing ByteArray from wrong-size string");
                }
                memmove(data, str.data(), N);
            }

            byte & operator[](std::size_t i) {
                if (i >= N)
                    throw std::out_of_range("ByteArray::operator[]");
                return data[i];
            }
            const byte & operator[](std::size_t i) const {
                if (i >= N)
                    throw std::out_of_range("ByteArray::operator[]");
                return data[i];
            }

            bool operator==(const ByteArray<N> & other) const {
                return (memcmp(data, other.data, N) == 0);
            }

            // FIXME: these should eventually be explicit
            operator std::string() const {
                return std::string((char *) data, N);
            }
            operator const byte *() const {
                return (const byte *) data;
            }

            static const std::size_t size = N;

            // initialize to random
            void random();

            void assign(const byte * input, std::size_t len) {
                if (len != N) {
                    throw std::domain_error("Assigning from wrong-size string");
                }
                memmove(data, input, N);
            }
        };
    }
}

#endif
