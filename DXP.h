#ifndef DXP_H
#define DXP_H

#include <cstdint>
#include "DXP_packet.h"
#include "DXP_process.h"

#define DXP_AES_KEY_WORDS 8

class DXP
{
public:
    DXP();
    ~DXP();

    void Type(uint8_t type);
    void Sender(uint16_t sender);
    void Receiver(uint16_t receiver);
    void HopCount(uint8_t hopCount);
    bool Route(const uint16_t* route, uint8_t count);
    bool Payload(const uint8_t* payload, uint16_t length);
    void Encryption(bool enabled);
    bool AESKeys(const uint16_t* keys, uint8_t count);
    void AESKey(const uint8_t* key);

    DXPPacket process() const;
    DXPStatus status() const;
    void printProcessedPacket(const DXPPacket& packet) const;

    void print() const;

private:
    uint8_t type;
    uint16_t sender;
    uint16_t receiver;
    uint8_t hopCount;
    uint16_t sequence;

    uint16_t route[DXP_MAX_ROUTE];
    uint8_t routeCount;

    uint8_t payload[DXP_MAX_PAYLOAD];
    uint16_t payloadLength;

    uint16_t aesKeys[DXP_AES_KEY_WORDS];
    uint8_t aesKeyCount;
    bool encryptionEnabled;

    mutable DXPStatus lastStatus;

    void generateSequence();
    void reset();
};

bool DXP_PayloadString(DXP* dxp, const char* str);

#endif
