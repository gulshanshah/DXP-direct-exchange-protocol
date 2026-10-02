#include "DXP_receive.h"
#include "DXP_CRC.h"
#include "DXP_decrypt.h"
#include <cstring>

static uint16_t readU16(const std::vector<uint8_t>& bytes, size_t& idx) {
    uint16_t value = static_cast<uint16_t>((bytes[idx] << 8) | bytes[idx + 1]);
    idx += 2;
    return value;
}

bool deserializePacket(const std::vector<uint8_t> &bytes, DXPPacket &packet,
                       const uint8_t* aesKey) {
    size_t idx = 0;
    auto need = [&](size_t n) { return idx + n <= bytes.size(); };

    if (!need(5))
        return false;

    if (bytes[idx++] != DXP_SEPARATOR)
        return false;

    memset(&packet, 0, sizeof(DXPPacket));
    packet.separator = DXP_SEPARATOR;
    packet.type = bytes[idx++];
    packet.flags = bytes[idx++];
    packet.hopCount = bytes[idx++];
    packet.sequenceCount = bytes[idx++];

    if (packet.sequenceCount > DXP_MAX_SEQUENCE)
        return false;
    if (!need(2u * packet.sequenceCount))
        return false;
    for (uint8_t i = 0; i < packet.sequenceCount; i++)
        packet.sequence[i] = readU16(bytes, idx);

    if (!need(5))
        return false;
    packet.senderId = readU16(bytes, idx);
    packet.receiverId = readU16(bytes, idx);
    packet.routeCount = bytes[idx++];

    if (packet.routeCount > DXP_MAX_ROUTE)
        return false;
    if (!need(2u * packet.routeCount))
        return false;
    for (uint8_t i = 0; i < packet.routeCount; i++)
        packet.route[i] = readU16(bytes, idx);

    if (!need(2))
        return false;
    packet.payloadLength = readU16(bytes, idx);

    if (packet.payloadLength > DXP_MAX_PAYLOAD)
        return false;

    if (packet.flags & DXP_FLAG_ENCRYPTED) {
        if (!need(DXP_AES_IV_SIZE))
            return false;
        memcpy(packet.iv, &bytes[idx], DXP_AES_IV_SIZE);
        idx += DXP_AES_IV_SIZE;
    }

    if (!need(packet.payloadLength))
        return false;
    memcpy(packet.payload, &bytes[idx], packet.payloadLength);
    idx += packet.payloadLength;

    size_t bodyEnd = idx;

    bool authenticated = (packet.flags & DXP_FLAG_AUTHENTICATED) != 0;

    if (authenticated) {
        if (!need(DXP_MAC_SIZE))
            return false;
        idx += DXP_MAC_SIZE;
    }

    if (!need(2))
        return false;
    packet.crc = readU16(bytes, idx);

    if (idx != bytes.size())
        return false;

    if (!DXP_CRC::verify(bytes.data(), bytes.size() - 2, packet.crc))
        return false;

    if (authenticated) {
        if (!aesKey)
            return false;
        const uint8_t* tag = &bytes[bodyEnd];
        if (!dxp_verifyFrameTag(aesKey, DXP_KEY_SIZE, bytes.data(), bodyEnd, tag))
            return false;
    } else {
        if (aesKey)
            return false;
        if (packet.flags & DXP_FLAG_ENCRYPTED)
            return false;
    }

    return true;
}

bool processReceivedPacket(DXPPacket &packet, const uint8_t *aesKey) {
    if (!(packet.flags & DXP_FLAG_ENCRYPTED))
        return true;

    if (!aesKey)
        return false;

    std::vector<uint8_t> cipher(packet.payload, packet.payload + packet.payloadLength);
    std::vector<uint8_t> plain = DXP_Decrypt::decrypt(cipher, aesKey, packet.iv);

    if (plain.empty() || plain.size() > DXP_MAX_PAYLOAD)
        return false;

    packet.payloadLength = static_cast<uint16_t>(plain.size());
    memcpy(packet.payload, plain.data(), plain.size());
    return true;
}
