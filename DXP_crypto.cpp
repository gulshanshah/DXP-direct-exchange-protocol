#include "DXP_crypto.h"
#include "DXP_AES.h"
#include "DXP_util.h"
#include <cstring>

DXP_Crypto::DXP_Crypto() {
    memset(aesKey, 0, DXP_AES_KEY_SIZE);
    keyValid = false;
}

DXP_Crypto::~DXP_Crypto() {
    dxp_secure_wipe(aesKey, sizeof(aesKey));
}

bool DXP_Crypto::setKey(const uint8_t* key) {
    if (!key) {
        keyValid = false;
        return false;
    }
    memcpy(aesKey, key, DXP_AES_KEY_SIZE);
    aes.setKey(aesKey);
    keyValid = aes.hasKey();
    return keyValid;
}

bool DXP_Crypto::encrypt(uint8_t* data, int length, const uint8_t* iv) {

    if (!data || !iv || !keyValid)
        return false;
    if (length <= 0 || length % DXP_BLOCK_SIZE != 0)
        return false;

    uint8_t previousBlock[DXP_BLOCK_SIZE];
    memcpy(previousBlock, iv, DXP_BLOCK_SIZE);

    for (int i = 0; i < length; i += DXP_BLOCK_SIZE) {
        for (int j = 0; j < DXP_BLOCK_SIZE; j++)
            data[i + j] ^= previousBlock[j];

        aes.encryptBlock(&data[i]);

        memcpy(previousBlock, &data[i], DXP_BLOCK_SIZE);
    }

    dxp_secure_wipe(previousBlock, sizeof(previousBlock));
    return true;
}

bool DXP_Crypto::decrypt(uint8_t* data, int length, const uint8_t* iv) {

    if (!data || !iv || !keyValid)
        return false;
    if (length <= 0 || length % DXP_BLOCK_SIZE != 0)
        return false;

    uint8_t previousBlock[DXP_BLOCK_SIZE];
    uint8_t currentBlock[DXP_BLOCK_SIZE];

    memcpy(previousBlock, iv, DXP_BLOCK_SIZE);

    for (int i = 0; i < length; i += DXP_BLOCK_SIZE) {

        memcpy(currentBlock, &data[i], DXP_BLOCK_SIZE);

        aes.decryptBlock(&data[i]);

        for (int j = 0; j < DXP_BLOCK_SIZE; j++)
            data[i + j] ^= previousBlock[j];

        memcpy(previousBlock, currentBlock, DXP_BLOCK_SIZE);
    }

    dxp_secure_wipe(previousBlock, sizeof(previousBlock));
    dxp_secure_wipe(currentBlock, sizeof(currentBlock));
    return true;
}
