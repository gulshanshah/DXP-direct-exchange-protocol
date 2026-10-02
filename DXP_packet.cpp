#include "DXP_packet.h"
#include "DXP_SHA256.h"
#include "DXP_util.h"
#include <cstring>
#include <cctype>
#include <iostream>
#include <iomanip>
#include <vector>

void dxp_computeFrameTag(const uint8_t* key, size_t keyLength,
                         const uint8_t* body, size_t bodyLength,
                         uint8_t tag[DXP_MAC_SIZE]) {
    if (!key || !body || bodyLength < 4) {
        memset(tag, 0, DXP_MAC_SIZE);
        return;
    }

    uint8_t macKey[DXP_SHA256_SIZE];
    dxp_deriveMacKey(key, keyLength, macKey);

    std::vector<uint8_t> macInput(body, body + bodyLength);
    macInput[3] = 0;

    DXP_HMAC::compute(macKey, sizeof(macKey), macInput.data(), macInput.size(), tag);

    dxp_secure_wipe(macKey, sizeof(macKey));
    dxp_secure_wipe(macInput.data(), macInput.size());
}

bool dxp_verifyFrameTag(const uint8_t* key, size_t keyLength,
                        const uint8_t* body, size_t bodyLength,
                        const uint8_t tag[DXP_MAC_SIZE]) {
    if (!key || !body || !tag || bodyLength < 4)
        return false;

    uint8_t computed[DXP_MAC_SIZE];
    dxp_computeFrameTag(key, keyLength, body, bodyLength, computed);
    bool ok = dxp_constant_time_equal(computed, tag, DXP_MAC_SIZE);
    dxp_secure_wipe(computed, sizeof(computed));
    return ok;
}

void printDXPPacket(const DXPPacket &packet)
{
    std::cout << "\n========== DXP PACKET ==========\n";

    std::cout << "Separator   : 0x"
              << std::hex << std::setw(2)
              << std::setfill('0')
              << (int)packet.separator << std::dec << "\n";

    std::cout << "Type        : " << (int)packet.type << "\n";
    std::cout << "Flags       : 0x" << std::hex << (int)packet.flags << std::dec << "\n";
    std::cout << "Hop Count   : " << (int)packet.hopCount << "\n";

    std::cout << "Sender ID   : " << packet.senderId << "\n";
    std::cout << "Receiver ID : " << packet.receiverId << "\n";

    std::cout << "\nSequence Count : "
              << (int)packet.sequenceCount << "\n";

    for (uint8_t i = 0; i < packet.sequenceCount; i++)
        std::cout << "  Sequence[" << (int)i << "] = "
                  << packet.sequence[i] << "\n";

    std::cout << "\nRoute Count : "
              << (int)packet.routeCount << "\n";

    for (uint8_t i = 0; i < packet.routeCount; i++)
        std::cout << "  Route[" << (int)i << "] = "
                  << packet.route[i] << "\n";

    std::cout << "\nPayload Length : "
              << packet.payloadLength << "\n";

    std::cout << "Payload (ASCII) : ";
    for (uint16_t i = 0; i < packet.payloadLength; i++)
    {
        if (std::isprint(packet.payload[i]))
            std::cout << (char)packet.payload[i];
        else
            std::cout << '.';
    }
    std::cout << "\n";

    std::cout << "Payload (HEX)   : ";
    for (uint16_t i = 0; i < packet.payloadLength; i++)
    {
        std::cout << std::hex << std::setw(2)
                  << std::setfill('0')
                  << (int)packet.payload[i] << " ";
    }
    std::cout << std::dec << "\n";

    std::cout << "\nIV (HEX) : ";
    for (int i = 0; i < DXP_AES_IV_SIZE; i++)
    {
        std::cout << std::hex << std::setw(2)
                  << std::setfill('0')
                  << (int)packet.iv[i] << " ";
    }
    std::cout << std::dec << "\n";

    std::cout << "\nCRC : 0x"
              << std::hex << std::setw(4)
              << std::setfill('0')
              << packet.crc
              << std::dec << "\n";

    std::cout << "=================================\n";
}
