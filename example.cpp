#include "DXP.h"
#include "DXP_transmit.h"
#include "DXP_receive.h"
#include "DXP_keys.h"
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    DXP_Keys keys;
    uint8_t key[16];
    if (!keys.generateKey(key)) {
        std::printf("key generation failed\n");
        return 1;
    }

    DXP dxp;
    dxp.Type(1);
    dxp.Sender(1);
    dxp.Receiver(2);
    dxp.Encryption(true);
    dxp.AESKey(key);
    DXP_PayloadString(&dxp, "hello from a DXP library consumer");

    DXPPacket packet = dxp.process();
    if (packet.separator != DXP_SEPARATOR) {
        std::printf("process failed with status %d\n", static_cast<int>(dxp.status()));
        return 1;
    }

    std::vector<uint8_t> frame = serializePacket(packet, key);
    if (frame.empty()) {
        std::printf("serialization failed\n");
        return 1;
    }

    DXPPacket received;
    if (!deserializePacket(frame, received, key)) {
        std::printf("frame rejected\n");
        return 1;
    }
    if (!processReceivedPacket(received, key)) {
        std::printf("decryption failed\n");
        return 1;
    }

    std::printf("round trip ok: node %u -> node %u, %u bytes: %.*s\n",
                received.senderId, received.receiverId,
                received.payloadLength,
                static_cast<int>(received.payloadLength),
                reinterpret_cast<const char*>(received.payload));
    return 0;
}
