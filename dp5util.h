#ifndef __DP5UTIL__
#define __DP5UTIL__

#include <string>
#include <cstddef>
#include <cstring>
#include <stdexcept>

namespace dp5 {
    namespace internal {
        typedef unsigned char byte;

        template<int N>
        class ByteArray {
        private:
            byte data[N];

        public:
            ByteArray() {
                memset(data, 0, sizeof(data));
            }
            ByteArray(const ByteArray<N> & other) {
                memcpy(data, other.data, sizeof(data));
            }
            ByteArray(const std::string & str) {
                if (str.length() != N) {
                    throw std::domain_error("Constructing ByteArray from wrong-size string");
                }
                memcpy(data, str.data(), N);
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

            operator std::string() const {
                return std::string((char *) data, N);
            }
            operator const char *() const {
                return (const char *) data;
            }
        };
    }
}

#endif
