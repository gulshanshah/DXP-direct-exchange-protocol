#ifndef DXP_RECEIVE_H
#define DXP_RECEIVE_H

#include "DXP_packet.h"
#include <vector>
#include <cstdint>

bool deserializePacket(const std::vector<uint8_t> &bytes, DXPPacket &packet,
                       const uint8_t* aesKey = nullptr);
bool processReceivedPacket(DXPPacket &packet, const uint8_t *aesKey);

#endif
