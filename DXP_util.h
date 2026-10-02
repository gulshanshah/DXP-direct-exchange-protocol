#ifndef DXP_UTIL_H
#define DXP_UTIL_H

#include <cstddef>
#include <cstdint>

inline void dxp_secure_wipe(void* data, size_t length) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(data);
    while (length > 0) {
        *p = 0;
        ++p;
        --length;
    }
}

inline bool dxp_constant_time_equal(const uint8_t* a, const uint8_t* b, size_t length) {
    uint8_t diff = 0;
    for (size_t i = 0; i < length; i++)
        diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

#endif
