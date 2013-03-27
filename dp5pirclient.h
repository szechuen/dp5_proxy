#ifndef __DP5PIRCLIENT_H__
#define __DP5PIRCLIENT_H__

#include "dp5params.h"

class DP5PIRClient : public DP5Params {

    // The number of valid numbers of buddies a client can send at
    // lookup time
    static const unsigned int NUM_QUERY_SIZES = 2;

    // The array of valid numbers of buddies a client can send at lookup
    // time (The actual values are set in the cpp file.)
    static unsigned int QUERY_SIZES[NUM_QUERY_SIZES];

    // The number of PIR servers that can collude without revealing a
    // client's query
    static const unsigned int PRIVACY_LEVEL = 2;

};

#endif
