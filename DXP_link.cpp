#include "DXP_link.h"
#include "DXP_process.h"
#include "DXP_transmit.h"
#include "DXP_receive.h"
#include "DXP_util.h"
#include <cstring>
#include <chrono>

DXP_Link::DXP_Link(DXP_Transport& t)
    : transport(t), nodeId(0), keySet(false), hopLimit(8),
      retryIntervalMs(100), maxAttempts(4), nextSequence(1000),
      seenHead(0), counterFramesSent(0), counterRetries(0),
      counterReceived(0), counterDuplicates(0), counterRelayed(0),
      counterFailed(0), counterDropped(0)
{
    memset(aesKey, 0, sizeof(aesKey));
    memset(seenSender, 0, sizeof(seenSender));
    memset(seenSequence, 0, sizeof(seenSequence));
    memset(seenValid, 0, sizeof(seenValid));
    memset(seenAck, 0, sizeof(seenAck));
    for (int i = 0; i < 8; i++)
        pending[i].active = false;
}

DXP_Link::~DXP_Link() {
    dxp_secure_wipe(aesKey, sizeof(aesKey));
}

uint64_t DXP_Link::nowMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

const uint8_t* DXP_Link::activeKey() const {
    return keySet ? aesKey : nullptr;
}

void DXP_Link::setNodeAddress(uint16_t id) {
    std::lock_guard<std::mutex> lock(mutex);
    nodeId = id;
}

void DXP_Link::setAESKey(const uint8_t* key) {
    std::lock_guard<std::mutex> lock(mutex);
    if (!key) {
        dxp_secure_wipe(aesKey, sizeof(aesKey));
        keySet = false;
        return;
    }
    memcpy(aesKey, key, 16);
    keySet = true;
}

void DXP_Link::setHopLimit(uint8_t hops) {
    std::lock_guard<std::mutex> lock(mutex);
    hopLimit = hops;
}

void DXP_Link::setRetryPolicy(uint16_t intervalMs, uint8_t maxAttempts) {
    std::lock_guard<std::mutex> lock(mutex);
    retryIntervalMs = intervalMs;
    this->maxAttempts = maxAttempts;
}

bool DXP_Link::send(uint16_t receiver, const uint8_t* payload, uint16_t length,
                    const uint16_t* route, uint8_t routeCount) {
    std::lock_guard<std::mutex> lock(mutex);

    if (!payload || length == 0)
        return false;

    uint16_t sequence = ++nextSequence;
    uint8_t flags = keySet ? (DXP_FLAG_ENCRYPTED | DXP_FLAG_AUTHENTICATED) : 0;

    DXPPacket packet;
    DXP_Process processor;
    if (processor.processPacket(packet, 1, flags, hopLimit, nodeId, receiver,
                                &sequence, 1, route, routeCount,
                                payload, length, activeKey()) != DXP_SUCCESS)
        return false;

    std::vector<uint8_t> frame = serializePacket(packet, activeKey());
    if (frame.empty())
        return false;

    int freeSlot = -1;
    if (receiver != DXP_BROADCAST) {
        for (int i = 0; i < 8; i++) {
            if (!pending[i].active) {
                freeSlot = i;
                break;
            }
        }
        if (freeSlot < 0)
            return false;

        pending[freeSlot].active = true;
        pending[freeSlot].sequence = sequence;
        pending[freeSlot].receiver = receiver;
        pending[freeSlot].frame = frame;
        pending[freeSlot].lastSentMs = nowMs();
        pending[freeSlot].attempts = 1;
    }

    if (!transport.write(frame.data(), frame.size())) {
        if (freeSlot >= 0)
            pending[freeSlot].active = false;
        return false;
    }

    counterFramesSent++;
    return true;
}

bool DXP_Link::sendString(uint16_t receiver, const char* text,
                          const uint16_t* route, uint8_t routeCount) {
    if (!text)
        return false;
    size_t length = strlen(text);
    if (length > DXP_MAX_PAYLOAD)
        return false;
    return send(receiver, reinterpret_cast<const uint8_t*>(text),
                static_cast<uint16_t>(length), route, routeCount);
}

void DXP_Link::poll() {
    std::lock_guard<std::mutex> lock(mutex);

    uint8_t buffer[512];

    for (int i = 0; i < 64; i++) {
        int n = transport.read(buffer, sizeof(buffer));
        if (n <= 0)
            break;
        size_t length = static_cast<size_t>(n);
        if (length > sizeof(buffer))
            length = sizeof(buffer);
        stream.feed(buffer, length);
    }

    std::vector<uint8_t> frame;
    while (stream.nextFrame(frame))
        handleFrame(frame);

    uint64_t now = nowMs();
    for (int i = 0; i < 8; i++) {
        if (!pending[i].active)
            continue;
        if (now - pending[i].lastSentMs < retryIntervalMs)
            continue;
        if (pending[i].attempts >= maxAttempts) {
            pending[i].active = false;
            counterFailed++;
            continue;
        }
        if (!transport.write(pending[i].frame.data(), pending[i].frame.size()))
            continue;
        pending[i].lastSentMs = now;
        pending[i].attempts++;
        counterRetries++;
        counterFramesSent++;
    }
}

void DXP_Link::handleFrame(const std::vector<uint8_t>& frame) {
    DXPPacket packet;
    if (!deserializePacket(frame, packet, activeKey()))
        return;

    if (packet.senderId == nodeId)
        return;
    if (packet.sequenceCount < 1)
        return;

    counterReceived++;

    uint16_t sender = packet.senderId;
    uint16_t sequence = packet.sequence[0];

    if (packet.type == 2) {
        if (isDuplicate(sender, sequence, true)) {
            counterDuplicates++;
            return;
        }
        remember(sender, sequence, true);

        if (packet.receiverId == nodeId) {
            for (int i = 0; i < 8; i++) {
                if (pending[i].active && pending[i].sequence == sequence &&
                    pending[i].receiver == sender) {
                    pending[i].active = false;
                    break;
                }
            }
            return;
        }

        relayFrame(packet);
        return;
    }

    if (packet.type == 1 || packet.type == 3 || packet.type == 4 || packet.type == 5) {
        if (isDuplicate(sender, sequence, false)) {
            counterDuplicates++;
            if (packet.receiverId == nodeId)
                sendAck(sender, sequence);
            return;
        }
        remember(sender, sequence, false);
        handleData(packet);
    }
}

void DXP_Link::handleData(DXPPacket& packet) {
    uint16_t sender = packet.senderId;
    uint16_t sequence = packet.sequence[0];
    bool forMe = packet.receiverId == nodeId || packet.receiverId == DXP_BROADCAST;

    if (packet.receiverId != nodeId)
        relayFrame(packet);

    if (!forMe)
        return;

    if (packet.flags & DXP_FLAG_ENCRYPTED) {
        if (!processReceivedPacket(packet, activeKey()))
            return;
    }

    if (packet.receiverId == nodeId)
        sendAck(sender, sequence);

    if (inbox.size() >= 16) {
        inbox.erase(inbox.begin());
        counterDropped++;
    }

    InboxItem item;
    item.sender = sender;
    item.payload.assign(packet.payload, packet.payload + packet.payloadLength);
    inbox.push_back(item);
}

void DXP_Link::sendAck(uint16_t to, uint16_t sequence) {
    uint8_t flags = keySet ? (DXP_FLAG_ENCRYPTED | DXP_FLAG_AUTHENTICATED) : 0;

    DXPPacket packet;
    DXP_Process processor;
    if (processor.processPacket(packet, 2, flags, hopLimit, nodeId, to,
                                &sequence, 1, nullptr, 0, nullptr, 0,
                                activeKey()) != DXP_SUCCESS)
        return;

    std::vector<uint8_t> frame = serializePacket(packet, activeKey());
    if (frame.empty())
        return;

    if (transport.write(frame.data(), frame.size()))
        counterFramesSent++;
}

void DXP_Link::relayFrame(DXPPacket& packet) {
    if (packet.hopCount == 0)
        return;

    packet.hopCount--;
    std::vector<uint8_t> frame = serializePacket(packet, activeKey());
    if (frame.empty())
        return;

    if (transport.write(frame.data(), frame.size())) {
        counterRelayed++;
        counterFramesSent++;
    }
}

bool DXP_Link::isDuplicate(uint16_t sender, uint16_t sequence, bool ack) {
    for (int i = 0; i < 32; i++) {
        if (seenValid[i] && seenSequence[i] == sequence &&
            seenSender[i] == sender && seenAck[i] == ack)
            return true;
    }
    return false;
}

void DXP_Link::remember(uint16_t sender, uint16_t sequence, bool ack) {
    seenSender[seenHead] = sender;
    seenSequence[seenHead] = sequence;
    seenAck[seenHead] = ack;
    seenValid[seenHead] = true;
    seenHead = static_cast<uint8_t>((seenHead + 1) % 32);
}

bool DXP_Link::nextReceived(uint16_t& sender, std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lock(mutex);
    if (inbox.empty())
        return false;
    sender = inbox.front().sender;
    payload = inbox.front().payload;
    inbox.erase(inbox.begin());
    return true;
}

uint8_t DXP_Link::pendingCount() const {
    std::lock_guard<std::mutex> lock(mutex);
    uint8_t count = 0;
    for (int i = 0; i < 8; i++) {
        if (pending[i].active)
            count++;
    }
    return count;
}

uint32_t DXP_Link::framesSent() const {
    std::lock_guard<std::mutex> lock(mutex);
    return counterFramesSent;
}

uint32_t DXP_Link::retriesSent() const {
    std::lock_guard<std::mutex> lock(mutex);
    return counterRetries;
}

uint32_t DXP_Link::framesReceived() const {
    std::lock_guard<std::mutex> lock(mutex);
    return counterReceived;
}

uint32_t DXP_Link::duplicatesDropped() const {
    std::lock_guard<std::mutex> lock(mutex);
    return counterDuplicates;
}

uint32_t DXP_Link::relayedCount() const {
    std::lock_guard<std::mutex> lock(mutex);
    return counterRelayed;
}

uint32_t DXP_Link::deliveryFailures() const {
    std::lock_guard<std::mutex> lock(mutex);
    return counterFailed;
}

uint32_t DXP_Link::droppedMessages() const {
    std::lock_guard<std::mutex> lock(mutex);
    return counterDropped;
}
