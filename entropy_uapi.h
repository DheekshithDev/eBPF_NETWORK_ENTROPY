//
// Created by user on 8/8/25.
//

/* NOT USING THIS HEADER FILE FOR NOW */
#ifndef ENTROPY_UAPI_H
#define ENTROPY_UAPI_H

#include <stdint.h>

struct pcap_record {
    uint32_t ts_sec, ts_usec;
    uint32_t incl_len, orig_len;
    uint8_t data[];
};

#endif //ENTROPY_UAPI_H
