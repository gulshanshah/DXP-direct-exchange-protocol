#ifndef DXP_KEYS_H
#define DXP_KEYS_H

#include <cstdint>
#include <cstddef>

#ifndef DXP_AES_KEY_SIZE
#define DXP_AES_KEY_SIZE 16
#endif
#ifndef DXP_AES_IV_SIZE
#define DXP_AES_IV_SIZE 16
#endif

class DXP_Keys {
public:
    DXP_Keys();

    static bool fillRandom(uint8_t* out, size_t length);
    bool generateKey(uint8_t key[DXP_AES_KEY_SIZE]);
    bool generateIV(uint8_t iv[DXP_AES_IV_SIZE]);
};

#endif
