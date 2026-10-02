#include "DXP_process.h"
#include "DXP_encrypt.h"
#include <cstring>
#include <vector>

DXP_Process::DXP_Process() {
}

void DXP_Process::setDefaultPayload(DXPPacket &packet, const std::string &text) {
    size_t length = text.size() > DXP_MAX_PAYLOAD ? DXP_MAX_PAYLOAD : text.size();
    packet.payloadLength = static_cast<uint16_t>(length);
    memcpy(packet.payload, text.c_str(), length);
}

DXPStatus DXP_Process::processPacket(
    DXPPacket &packet,
    uint8_t type,
    uint8_t flags,
    uint8_t hopCount,
    uint16_t senderId,
    uint16_t receiverId,
    const uint16_t* sequence,
    uint8_t sequenceCount,
    const uint16_t* route,
    uint8_t routeCount,
    const uint8_t* data,
    uint16_t dataLength,
    const uint8_t* aesKey
) {
    memset(&packet, 0, sizeof(DXPPacket));
    packet.separator = DXP_SEPARATOR;
    packet.type = type;
    packet.flags = flags;
    packet.hopCount = hopCount;
    packet.senderId = senderId;
    packet.receiverId = receiverId;
    packet.crc = 0;

    uint8_t seqCount = 0;
    if (sequence && sequenceCount > 0) {
        seqCount = sequenceCount > DXP_MAX_SEQUENCE ? DXP_MAX_SEQUENCE : sequenceCount;
        memcpy(packet.sequence, sequence, seqCount * sizeof(uint16_t));
    }
    packet.sequenceCount = seqCount;

    uint8_t rtCount = 0;
    if (route && routeCount > 0) {
        rtCount = routeCount > DXP_MAX_ROUTE ? DXP_MAX_ROUTE : routeCount;
        memcpy(packet.route, route, rtCount * sizeof(uint16_t));
    }
    packet.routeCount = rtCount;

    bool encrypted = (flags & DXP_FLAG_ENCRYPTED) != 0;
    bool authenticated = (flags & DXP_FLAG_AUTHENTICATED) != 0;

    if (encrypted || authenticated) {
        if (!aesKey)
            return DXP_ERROR_INVALID_KEY;
    }

    uint16_t maxPlain = encrypted ? static_cast<uint16_t>(DXP_MAX_PAYLOAD - DXP_BLOCK_SIZE) : DXP_MAX_PAYLOAD;

    switch (type) {
        case 1:
            if (!data || dataLength == 0)
                return DXP_ERROR_MISSING_PAYLOAD;
            if (dataLength > maxPlain)
                return DXP_ERROR_PAYLOAD_TOO_LARGE;
            packet.payloadLength = dataLength;
            memcpy(packet.payload, data, dataLength);
            break;

        case 2:
            setDefaultPayload(packet, "ack");
            break;

        case 3:
            if (!data || dataLength == 0)
                return DXP_ERROR_MISSING_PAYLOAD;
            if (hopCount == 0)
                return DXP_ERROR_MISSING_HOPCOUNT;
            if (dataLength > maxPlain)
                return DXP_ERROR_PAYLOAD_TOO_LARGE;
            packet.payloadLength = dataLength;
            memcpy(packet.payload, data, dataLength);
            break;

        case 4:
            if (!data || dataLength == 0)
                return DXP_ERROR_MISSING_PAYLOAD;
            if (rtCount == 0)
                return DXP_ERROR_MISSING_ROUTE;
            if (dataLength > maxPlain)
                return DXP_ERROR_PAYLOAD_TOO_LARGE;
            packet.payloadLength = dataLength;
            memcpy(packet.payload, data, dataLength);
            break;

        case 5:
            if (hopCount == 0)
                return DXP_ERROR_MISSING_HOPCOUNT;
            setDefaultPayload(packet, "discover");
            break;

        default:
            return DXP_ERROR_UNKNOWN_TYPE;
    }

    if (encrypted) {
        if (!aesKey)
            return DXP_ERROR_ENCRYPTION_FAILED;

        std::vector<uint8_t> payloadVec(packet.payload, packet.payload + packet.payloadLength);
        DXP_Encrypt::EncryptedResult result = DXP_Encrypt::encrypt(payloadVec, aesKey);

        if (result.encryptedPayload.empty())
            return DXP_ERROR_ENCRYPTION_FAILED;
        if (result.encryptedPayload.size() > DXP_MAX_PAYLOAD)
            return DXP_ERROR_PAYLOAD_TOO_LARGE;

        memcpy(packet.iv, result.iv, DXP_AES_IV_SIZE);
        packet.payloadLength = static_cast<uint16_t>(result.encryptedPayload.size());
        memcpy(packet.payload, result.encryptedPayload.data(), packet.payloadLength);
    }

    return DXP_SUCCESS;
}
