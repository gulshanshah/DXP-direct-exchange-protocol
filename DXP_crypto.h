#ifndef DXP_CRYPTO_H
#define DXP_CRYPTO_H

#include <cstdint>
#include "DXP_AES.h"

#ifndef DXP_AES_KEY_SIZE
#define DXP_AES_KEY_SIZE 16
#endif
#ifndef DXP_BLOCK_SIZE
#define DXP_BLOCK_SIZE 16
#endif

class DXP_Crypto {
public:
    DXP_Crypto();
    ~DXP_Crypto();

    bool setKey(const uint8_t* key);

    bool encrypt(uint8_t* data, int length, const uint8_t* iv);
    bool decrypt(uint8_t* data, int length, const uint8_t* iv);

private:
    uint8_t aesKey[DXP_AES_KEY_SIZE];
    bool keyValid;
    DXP_AES aes;
};

#endif
