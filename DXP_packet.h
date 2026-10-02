#ifndef DXP_PACKET_H
#define DXP_PACKET_H

#include <cstdint>
#include <cstddef>

#define DXP_MAX_SEQUENCE 10
#define DXP_MAX_ROUTE 10
#define DXP_MAX_PAYLOAD 256
#define DXP_AES_IV_SIZE 16
#define DXP_MAC_SIZE 32
#define DXP_KEY_SIZE 16

#define DXP_SEPARATOR 0x7E
#define DXP_BROADCAST 0xFFFF

#define DXP_FLAG_ENCRYPTED 0x01
#define DXP_FLAG_AUTHENTICATED 0x02

struct DXPPacket {

    uint8_t separator;

    uint8_t type;
    uint8_t flags;
    uint8_t hopCount;

    uint8_t sequenceCount;
    uint16_t sequence[DXP_MAX_SEQUENCE];

    uint16_t senderId;
    uint16_t receiverId;

    uint8_t routeCount;
    uint16_t route[DXP_MAX_ROUTE];

    uint16_t payloadLength;
    uint8_t payload[DXP_MAX_PAYLOAD];

    uint8_t iv[DXP_AES_IV_SIZE];

    uint16_t crc;
};

void dxp_computeFrameTag(const uint8_t* key, size_t keyLength,
                         const uint8_t* body, size_t bodyLength,
                         uint8_t tag[DXP_MAC_SIZE]);
bool dxp_verifyFrameTag(const uint8_t* key, size_t keyLength,
                        const uint8_t* body, size_t bodyLength,
                        const uint8_t tag[DXP_MAC_SIZE]);

void printDXPPacket(const DXPPacket &packet);

#endif
