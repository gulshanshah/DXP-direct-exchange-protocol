#ifndef DXP_CRC_H
#define DXP_CRC_H

#include <cstdint>
#include <cstddef>

class DXP_CRC {
public:
    static uint16_t calculate(const uint8_t* data, size_t length);
    static bool verify(const uint8_t* data, size_t length, uint16_t expectedCRC);
};

#endif
