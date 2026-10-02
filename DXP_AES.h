#ifndef DXP_AES_H
#define DXP_AES_H

#include <cstdint>

#define AES_BLOCK_SIZE 16
#define DXP_AES_KEY_SIZE 16
#define AES_ROUNDS 10

class DXP_AES {
public:
    DXP_AES();
    ~DXP_AES();
    void setKey(const uint8_t* key);
    bool hasKey() const;
    void encryptBlock(uint8_t* block);
    void decryptBlock(uint8_t* block);

private:
    uint8_t RoundKey[176];
    bool keyLoaded;

    void KeyExpansion(const uint8_t* key);
    void SubBytes(uint8_t* state);
    void ShiftRows(uint8_t* state);
    void MixColumns(uint8_t* state);
    void AddRoundKey(uint8_t* state, uint8_t round);

    void InvSubBytes(uint8_t* state);
    void InvShiftRows(uint8_t* state);
    void InvMixColumns(uint8_t* state);
};

#endif
