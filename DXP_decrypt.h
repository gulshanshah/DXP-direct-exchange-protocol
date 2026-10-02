#ifndef DXP_DECRYPT_H
#define DXP_DECRYPT_H

#include <vector>
#include <cstdint>
#include <cstring>

#include "DXP_crypto.h"
#include "DXP_keys.h"

class DXP_Decrypt {
public:

    static std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& encryptedPayload,
        const uint8_t* key,
        const uint8_t* iv
    ) {
        DXP_Decrypt decryptor;
        return decryptor.process(encryptedPayload, key, iv);
    }

private:

    static bool removePadding(std::vector<uint8_t>& data) {
        if (data.empty() || data.size() % DXP_BLOCK_SIZE != 0)
            return false;

        uint8_t padSize = data.back();
        if (padSize < 1 || padSize > DXP_BLOCK_SIZE || padSize > data.size())
            return false;

        uint8_t diff = 0;
        size_t start = data.size() - padSize;
        for (size_t i = start; i < data.size(); i++)
            diff = static_cast<uint8_t>(diff | (data[i] ^ padSize));

        if (diff != 0)
            return false;

        data.resize(data.size() - padSize);
        return true;
    }

    std::vector<uint8_t> process(
        const std::vector<uint8_t>& encryptedPayload,
        const uint8_t* key,
        const uint8_t* iv
    ) {
        std::vector<uint8_t> plain;

        if (!key || !iv || encryptedPayload.empty())
            return plain;

        std::vector<uint8_t> buffer = encryptedPayload;

        int length = static_cast<int>(buffer.size());

        DXP_Crypto crypto;
        if (!crypto.setKey(key))
            return plain;

        if (!crypto.decrypt(buffer.data(), length, iv))
            return plain;

        if (!removePadding(buffer))
            return plain;

        return buffer;
    }
};

#endif
