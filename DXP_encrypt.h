#ifndef DXP_ENCRYPT_H
#define DXP_ENCRYPT_H

#include <vector>
#include <cstdint>
#include <cstring>

#include "DXP_crypto.h"
#include "DXP_keys.h"

class DXP_Encrypt {
public:

    struct EncryptedResult {
        std::vector<uint8_t> encryptedPayload;
        uint8_t iv[DXP_AES_IV_SIZE];
    };

    static EncryptedResult encrypt(
        const std::vector<uint8_t>& payload,
        const uint8_t* key
    ) {
        DXP_Encrypt encryptor;
        return encryptor.process(payload, key);
    }

private:

    static void applyPadding(std::vector<uint8_t>& data) {
        size_t padSize = DXP_BLOCK_SIZE - (data.size() % DXP_BLOCK_SIZE);
        for (size_t i = 0; i < padSize; i++)
            data.push_back(static_cast<uint8_t>(padSize));
    }

    EncryptedResult process(
        const std::vector<uint8_t>& payload,
        const uint8_t* key
    ) {
        EncryptedResult result;
        memset(result.iv, 0, DXP_AES_IV_SIZE);

        if (!key || payload.empty())
            return result;

        std::vector<uint8_t> buffer = payload;
        applyPadding(buffer);

        int length = static_cast<int>(buffer.size());

        DXP_Keys keyGen;
        if (!keyGen.generateIV(result.iv))
            return result;

        DXP_Crypto crypto;
        if (!crypto.setKey(key))
            return result;

        if (!crypto.encrypt(buffer.data(), length, result.iv))
            return result;

        result.encryptedPayload = buffer;
        return result;
    }
};

#endif
