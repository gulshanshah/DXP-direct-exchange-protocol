#ifndef DXP_LINK_H
#define DXP_LINK_H

#include "DXP_transport.h"
#include "DXP_stream.h"
#include "DXP_packet.h"
#include <vector>
#include <cstdint>
#include <mutex>

class DXP_Link {
public:
    explicit DXP_Link(DXP_Transport& transport);
    ~DXP_Link();

    void setNodeAddress(uint16_t id);
    void setAESKey(const uint8_t* key);
    void setHopLimit(uint8_t hops);
    void setRetryPolicy(uint16_t intervalMs, uint8_t maxAttempts);

    bool send(uint16_t receiver, const uint8_t* payload, uint16_t length,
              const uint16_t* route = nullptr, uint8_t routeCount = 0);
    bool sendString(uint16_t receiver, const char* text,
                    const uint16_t* route = nullptr, uint8_t routeCount = 0);

    void poll();

    bool nextReceived(uint16_t& sender, std::vector<uint8_t>& payload);

    uint8_t pendingCount() const;
    uint32_t framesSent() const;
    uint32_t retriesSent() const;
    uint32_t framesReceived() const;
    uint32_t duplicatesDropped() const;
    uint32_t relayedCount() const;
    uint32_t deliveryFailures() const;
    uint32_t droppedMessages() const;

private:
    struct Pending {
        bool active;
        uint16_t sequence;
        uint16_t receiver;
        std::vector<uint8_t> frame;
        uint64_t lastSentMs;
        uint8_t attempts;
    };

    struct InboxItem {
        uint16_t sender;
        std::vector<uint8_t> payload;
    };

    DXP_Transport& transport;
    DXP_Stream stream;

    uint16_t nodeId;
    uint8_t aesKey[16];
    bool keySet;
    uint8_t hopLimit;
    uint16_t retryIntervalMs;
    uint8_t maxAttempts;
    uint16_t nextSequence;

    Pending pending[8];
    uint16_t seenSender[32];
    uint16_t seenSequence[32];
    bool seenValid[32];
    bool seenAck[32];
    uint8_t seenHead;

    std::vector<InboxItem> inbox;

    uint32_t counterFramesSent;
    uint32_t counterRetries;
    uint32_t counterReceived;
    uint32_t counterDuplicates;
    uint32_t counterRelayed;
    uint32_t counterFailed;
    uint32_t counterDropped;

    mutable std::mutex mutex;

    static uint64_t nowMs();
    void handleFrame(const std::vector<uint8_t>& frame);
    void handleData(DXPPacket& packet);
    void sendAck(uint16_t to, uint16_t sequence);
    void relayFrame(DXPPacket& packet);
    bool isDuplicate(uint16_t sender, uint16_t sequence, bool ack);
    void remember(uint16_t sender, uint16_t sequence, bool ack);
    const uint8_t* activeKey() const;
};

#endif
