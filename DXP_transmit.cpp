#include "DXP_transmit.h"
#include "DXP_CRC.h"
#include "DXP_util.h"

static void pushU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

std::vector<uint8_t> serializePacket(const DXPPacket &packet, const uint8_t* aesKey) {
    std::vector<uint8_t> frame;
    frame.reserve(72u + packet.payloadLength);

    bool authenticated = (packet.flags & DXP_FLAG_AUTHENTICATED) != 0;
    if (authenticated && !aesKey)
        return frame;

    frame.push_back(DXP_SEPARATOR);
    frame.push_back(packet.type);
    frame.push_back(packet.flags);
    frame.push_back(packet.hopCount);

    uint8_t seqCount = packet.sequenceCount > DXP_MAX_SEQUENCE ? DXP_MAX_SEQUENCE : packet.sequenceCount;
    frame.push_back(seqCount);
    for (uint8_t i = 0; i < seqCount; i++)
        pushU16(frame, packet.sequence[i]);

    pushU16(frame, packet.senderId);
    pushU16(frame, packet.receiverId);

    uint8_t routeCount = packet.routeCount > DXP_MAX_ROUTE ? DXP_MAX_ROUTE : packet.routeCount;
    frame.push_back(routeCount);
    for (uint8_t i = 0; i < routeCount; i++)
        pushU16(frame, packet.route[i]);

    uint16_t payloadLength = packet.payloadLength > DXP_MAX_PAYLOAD
        ? static_cast<uint16_t>(DXP_MAX_PAYLOAD) : packet.payloadLength;
    pushU16(frame, payloadLength);

    if (packet.flags & DXP_FLAG_ENCRYPTED)
        frame.insert(frame.end(), packet.iv, packet.iv + DXP_AES_IV_SIZE);

    frame.insert(frame.end(), packet.payload, packet.payload + payloadLength);

    if (authenticated) {
        uint8_t tag[DXP_MAC_SIZE];
        dxp_computeFrameTag(aesKey, DXP_KEY_SIZE, frame.data(), frame.size(), tag);
        frame.insert(frame.end(), tag, tag + DXP_MAC_SIZE);
        dxp_secure_wipe(tag, sizeof(tag));
    }

    uint16_t crc = DXP_CRC::calculate(frame.data(), frame.size());
    pushU16(frame, crc);

    return frame;
}
