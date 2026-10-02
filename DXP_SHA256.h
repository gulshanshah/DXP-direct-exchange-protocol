#ifndef DXP_SHA256_H
#define DXP_SHA256_H

#include <cstdint>
#include <cstddef>

#define DXP_SHA256_SIZE 32

class DXP_SHA256 {
public:
    static void hash(const uint8_t* data, size_t length, uint8_t out[DXP_SHA256_SIZE]);
};

class DXP_HMAC {
public:
    static void compute(const uint8_t* key, size_t keyLength,
                        const uint8_t* data, size_t dataLength,
                        uint8_t out[DXP_SHA256_SIZE]);
    static bool verify(const uint8_t* key, size_t keyLength,
                       const uint8_t* data, size_t dataLength,
                       const uint8_t expected[DXP_SHA256_SIZE]);
};

void dxp_deriveMacKey(const uint8_t* key, size_t keyLength,
                      uint8_t out[DXP_SHA256_SIZE]);

#endif
