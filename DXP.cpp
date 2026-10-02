#include "DXP.h"
#include "DXP_process.h"
#include "DXP_transmit.h"
#include "DXP_util.h"
#include <atomic>
#include <cstring>
#include <iostream>
#include <iomanip>

DXP::DXP() {
    reset();
}

DXP::~DXP() {
    dxp_secure_wipe(aesKeys, sizeof(aesKeys));
}

void DXP::reset() {
    type = 0;
    sender = 0;
    receiver = 0;
    hopCount = 0;
    sequence = 0;
    routeCount = 0;
    payloadLength = 0;
    aesKeyCount = 0;
    encryptionEnabled = false;
    lastStatus = DXP_SUCCESS;

    memset(route, 0, sizeof(route));
    memset(payload, 0, sizeof(payload));
    memset(aesKeys, 0, sizeof(aesKeys));

    generateSequence();
}

void DXP::generateSequence() {
    static std::atomic<uint16_t> globalSeq{100};
    sequence = static_cast<uint16_t>(globalSeq.fetch_add(1) + 1);
}

void DXP::Type(uint8_t t) { type = t; }
void DXP::Sender(uint16_t s) { sender = s; }
void DXP::Receiver(uint16_t r) { receiver = r; }
void DXP::HopCount(uint8_t h) { hopCount = h; }

bool DXP::Route(const uint16_t* r, uint8_t count) {
    if (count > 0 && !r) {
        lastStatus = DXP_ERROR_INVALID_ARGUMENT;
        return false;
    }
    if (count > DXP_MAX_ROUTE) {
        lastStatus = DXP_ERROR_INVALID_ARGUMENT;
        return false;
    }
    routeCount = count;
    if (r && routeCount > 0) {
        memcpy(route, r, routeCount * sizeof(uint16_t));
    }
    lastStatus = DXP_SUCCESS;
    return true;
}

bool DXP::Payload(const uint8_t* p, uint16_t length) {
    if (length > 0 && !p) {
        lastStatus = DXP_ERROR_INVALID_ARGUMENT;
        return false;
    }
    if (length > DXP_MAX_PAYLOAD) {
        lastStatus = DXP_ERROR_PAYLOAD_TOO_LARGE;
        return false;
    }
    payloadLength = length;
    if (p && payloadLength > 0) {
        memcpy(payload, p, payloadLength);
    }
    lastStatus = DXP_SUCCESS;
    return true;
}

void DXP::Encryption(bool enabled) { encryptionEnabled = enabled; }

bool DXP::AESKeys(const uint16_t* keys, uint8_t count) {
    if (count > 0 && !keys) {
        lastStatus = DXP_ERROR_INVALID_ARGUMENT;
        return false;
    }
    if (count > DXP_AES_KEY_WORDS) {
        lastStatus = DXP_ERROR_INVALID_KEY;
        return false;
    }
    aesKeyCount = count;
    if (keys && aesKeyCount > 0) {
        memcpy(aesKeys, keys, aesKeyCount * sizeof(uint16_t));
    }
    lastStatus = DXP_SUCCESS;
    return true;
}

void DXP::AESKey(const uint8_t* key) {
    if (!key) {
        aesKeyCount = 0;
        memset(aesKeys, 0, sizeof(aesKeys));
        return;
    }
    memcpy(aesKeys, key, sizeof(aesKeys));
    aesKeyCount = DXP_AES_KEY_WORDS;
}

DXPStatus DXP::status() const {
    return lastStatus;
}

DXPPacket DXP::process() const {
    DXPPacket packet;
    memset(&packet, 0, sizeof(DXPPacket));

    if (aesKeyCount != 0 && aesKeyCount != DXP_AES_KEY_WORDS) {
        lastStatus = DXP_ERROR_INVALID_KEY;
        return packet;
    }

    if (encryptionEnabled && aesKeyCount != DXP_AES_KEY_WORDS) {
        lastStatus = aesKeyCount == 0 ? DXP_ERROR_ENCRYPTION_FAILED
                                      : DXP_ERROR_INVALID_KEY;
        return packet;
    }

    DXP_Process processor;

    uint8_t flags = 0;
    if (encryptionEnabled)
        flags |= DXP_FLAG_ENCRYPTED;
    if (aesKeyCount == DXP_AES_KEY_WORDS)
        flags |= DXP_FLAG_AUTHENTICATED;

    uint8_t rawKey[DXP_KEY_SIZE] = {0};
    const uint8_t* keyPtr = nullptr;
    if (aesKeyCount == DXP_AES_KEY_WORDS) {
        memcpy(rawKey, aesKeys, sizeof(rawKey));
        keyPtr = rawKey;
    }

    DXPStatus status = processor.processPacket(
        packet, type, flags, hopCount, sender, receiver,
        &sequence, 1, route, routeCount, payload, payloadLength, keyPtr
    );

    if (status != DXP_SUCCESS) {
        dxp_secure_wipe(rawKey, sizeof(rawKey));
        memset(&packet, 0, sizeof(DXPPacket));
        lastStatus = status;
        return packet;
    }

    std::vector<uint8_t> frame = serializePacket(packet, keyPtr);
    dxp_secure_wipe(rawKey, sizeof(rawKey));

    size_t size = frame.size();
    if (size < 2) {
        memset(&packet, 0, sizeof(DXPPacket));
        lastStatus = DXP_ERROR_ENCRYPTION_FAILED;
        return packet;
    }

    packet.crc = static_cast<uint16_t>((frame[size - 2] << 8) | frame[size - 1]);
    lastStatus = DXP_SUCCESS;

    return packet;
}

void DXP::printProcessedPacket(const DXPPacket& packet) const {
    auto printHex = [](const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << (int)data[i] << " ";
        }
    };

    std::cout << "\n==================================================" << std::endl;
    std::cout << "           FULL PROCESSED DXP PACKET             " << std::endl;
    std::cout << "==================================================" << std::endl;

    std::cout << "Separator:    0x" << std::hex << (int)packet.separator << std::dec << std::endl;
    std::cout << "Type:         "   << (int)packet.type << std::endl;
    std::cout << "Flags:        0x" << std::hex << (int)packet.flags << std::dec
              << (packet.flags & DXP_FLAG_ENCRYPTED ? " (Encrypted)" : " (Plaintext)") << std::endl;

    std::cout << "Hop Count:    "   << (int)packet.hopCount << std::endl;
    std::cout << "Sender ID:    0x" << std::hex << packet.senderId << std::dec << std::endl;
    std::cout << "Receiver ID:  0x" << std::hex << packet.receiverId << std::dec << std::endl;

    std::cout << "Seq Count:    " << (int)packet.sequenceCount << std::endl;
    std::cout << "Sequence:     ";
    for (int i = 0; i < packet.sequenceCount; i++)
        std::cout << packet.sequence[i] << " ";
    std::cout << std::endl;

    std::cout << "Route Count:  " << (int)packet.routeCount << std::endl;
    std::cout << "Route Path:   ";
    for (int i = 0; i < packet.routeCount; i++)
        std::cout << "0x" << std::hex << packet.route[i] << " ";
    std::cout << std::dec << std::endl;

    std::cout << "IV:           ";
    printHex(packet.iv, DXP_AES_IV_SIZE);
    std::cout << std::endl;

    std::cout << "Payload Len:  " << packet.payloadLength << std::endl;
    std::cout << "Payload Data: ";
    if (packet.payloadLength > 0) {
        printHex(packet.payload, packet.payloadLength);
    } else {
        std::cout << "[EMPTY]";
    }

    std::cout << "\nCRC:          0x" << std::hex << std::setw(4) << std::setfill('0') << packet.crc << std::dec;

    std::cout << "\n==================================================\n" << std::endl;
}

void DXP::print() const {
    std::cout << "[DXP State] Type: " << (int)type << " | Sender: " << sender << std::endl;
}

bool DXP_PayloadString(DXP* dxp, const char* str) {
    if (!dxp || !str)
        return false;
    size_t length = strlen(str);
    if (length > DXP_MAX_PAYLOAD)
        return false;
    return dxp->Payload(reinterpret_cast<const uint8_t*>(str),
                        static_cast<uint16_t>(length));
}
