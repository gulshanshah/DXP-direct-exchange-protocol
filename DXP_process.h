#ifndef DXP_PROCESS_H
#define DXP_PROCESS_H

#include <cstdint>
#include <string>
#include "DXP_packet.h"

enum DXPStatus : uint8_t {
    DXP_SUCCESS,
    DXP_ERROR_MISSING_PAYLOAD,
    DXP_ERROR_MISSING_HOPCOUNT,
    DXP_ERROR_MISSING_ROUTE,
    DXP_ERROR_ENCRYPTION_FAILED,
    DXP_ERROR_UNKNOWN_TYPE,
    DXP_ERROR_PAYLOAD_TOO_LARGE,
    DXP_ERROR_INVALID_KEY,
    DXP_ERROR_INVALID_ARGUMENT
};

class DXP_Process {
public:
    DXP_Process();

    DXPStatus processPacket(
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
    );

private:
    void setDefaultPayload(DXPPacket &packet, const std::string &text);
};

#endif
