#include "DXP_CRC.h"

uint16_t DXP_CRC::calculate(const uint8_t* data, size_t length) {
    if (!data && length > 0)
        return 0;

    uint16_t crc = 0xFFFF;

    for (size_t i = 0; i < length; ++i) {
        crc ^= static_cast<uint16_t>(data[i]) << 8;
        for (uint8_t bit = 0; bit < 8; ++bit) {
            if (crc & 0x8000)
                crc = static_cast<uint16_t>((crc << 1) ^ 0x1021);
            else
                crc = static_cast<uint16_t>(crc << 1);
        }
    }
    return crc;
}

bool DXP_CRC::verify(const uint8_t* data, size_t length, uint16_t expectedCRC) {
    if (!data && length > 0)
        return false;
    return calculate(data, length) == expectedCRC;
}
