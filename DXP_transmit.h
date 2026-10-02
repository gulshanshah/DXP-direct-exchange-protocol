#ifndef DXP_TRANSMIT_H
#define DXP_TRANSMIT_H

#include "DXP_packet.h"
#include <vector>
#include <cstdint>

std::vector<uint8_t> serializePacket(const DXPPacket &packet, const uint8_t* aesKey = nullptr);

#endif
