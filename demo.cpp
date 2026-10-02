#include "DXP.h"
#include "DXP_transmit.h"
#include "DXP_receive.h"
#include "DXP_keys.h"
#include "DXP_link.h"
#include "DXP_CRC.h"
#include "DXP_AES.h"
#include "DXP_crypto.h"
#include "DXP_SHA256.h"
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <utility>
#include <vector>

static int failures = 0;

static void check(bool ok, const char* name) {
    std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << "\n";
    if (!ok)
        failures++;
}

static void printFrame(const std::vector<uint8_t>& frame) {
    for (size_t i = 0; i < frame.size(); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)frame[i] << " ";
        if ((i + 1) % 16 == 0)
            std::cout << "\n";
    }
    if (frame.size() % 16 != 0)
        std::cout << "\n";
    std::cout << std::dec << "Frame size: " << frame.size() << " bytes\n";
}

static void runKnownAnswerTests() {
    {
        DXP_AES aes;
        uint8_t k[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
        uint8_t block[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                             0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        uint8_t original[16];
        memcpy(original, block, 16);
        static const uint8_t expected[16] = {
            0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
            0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};

        aes.setKey(k);
        aes.encryptBlock(block);
        check(memcmp(block, expected, 16) == 0, "AES-128 known-answer test (FIPS-197)");
        aes.decryptBlock(block);
        check(memcmp(block, original, 16) == 0, "AES-128 inverse round trip");
    }

    {
        uint8_t digest[32];
        const char* abc = "abc";
        DXP_SHA256::hash(reinterpret_cast<const uint8_t*>(abc), 3, digest);
        static const uint8_t expected[32] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
        check(memcmp(digest, expected, 32) == 0, "SHA-256 known-answer test");
    }

    {
        uint8_t mac[32];
        const char* keyStr = "Jefe";
        const char* msgStr = "what do ya want for nothing?";
        DXP_HMAC::compute(reinterpret_cast<const uint8_t*>(keyStr), 4,
                          reinterpret_cast<const uint8_t*>(msgStr), 28, mac);
        static const uint8_t expected[32] = {
            0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
            0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43};
        check(memcmp(mac, expected, 32) == 0, "HMAC-SHA256 known-answer test (RFC 4231)");
    }

    {
        uint8_t ck[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                          0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
        uint8_t civ[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                           0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
        uint8_t cpt[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                           0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
        static const uint8_t expectedCt[16] = {
            0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
            0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d};
        uint8_t original[16];
        memcpy(original, cpt, 16);

        DXP_Crypto crypto;
        check(crypto.setKey(ck), "CBC key loaded");
        check(crypto.encrypt(cpt, 16, civ), "CBC encryption ran");
        check(memcmp(cpt, expectedCt, 16) == 0, "AES-CBC known-answer test (SP 800-38A)");
        check(crypto.decrypt(cpt, 16, civ), "CBC decryption ran");
        check(memcmp(cpt, original, 16) == 0, "CBC inverse round trip");
    }
}

class VirtualNet {
public:
    void connect(uint16_t a, uint16_t b) {
        edges.push_back(std::make_pair(a, b));
        edges.push_back(std::make_pair(b, a));
    }

    void clearLinks() { edges.clear(); }

    void broadcast(uint16_t from, const std::vector<uint8_t>& frame) {
        for (size_t i = 0; i < edges.size(); i++) {
            if (edges[i].first == from)
                queues[edges[i].second].push_back(frame);
        }
    }

    int take(uint16_t id, uint8_t* buffer, size_t maxLength) {
        std::map<uint16_t, std::deque<std::vector<uint8_t> > >::iterator it = queues.find(id);
        if (it == queues.end() || it->second.empty())
            return 0;
        std::vector<uint8_t> frame = it->second.front();
        it->second.pop_front();
        if (frame.size() > maxLength)
            return -1;
        memcpy(buffer, frame.data(), frame.size());
        return static_cast<int>(frame.size());
    }

    void dropQueued(uint16_t id) { queues[id].clear(); }

private:
    std::map<uint16_t, std::deque<std::vector<uint8_t> > > queues;
    std::vector<std::pair<uint16_t, uint16_t> > edges;
};

class VirtualTransport : public DXP_Transport {
public:
    VirtualTransport(VirtualNet& n, uint16_t id) : net(n), nodeId(id), dropsLeft(0) {}

    bool write(const uint8_t* data, size_t length) {
        std::vector<uint8_t> frame(data, data + length);
        written.push_back(frame);
        if (dropsLeft > 0) {
            dropsLeft--;
            return true;
        }
        net.broadcast(nodeId, frame);
        return true;
    }

    int read(uint8_t* buffer, size_t maxLength) {
        return net.take(nodeId, buffer, maxLength);
    }

    VirtualNet& net;
    uint16_t nodeId;
    int dropsLeft;
    std::vector<std::vector<uint8_t> > written;
};

static bool pumpUntil(std::function<bool()> cond, DXP_Link& x, DXP_Link& y,
                      DXP_Link* z, int timeoutMs) {
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    while (!cond()) {
        x.poll();
        y.poll();
        if (z)
            z->poll();
        long long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > timeoutMs)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}

static void drain(DXP_Link& link) {
    uint16_t sender;
    std::vector<uint8_t> payload;
    while (link.nextReceived(sender, payload)) {}
}

int main() {
    std::cout << "=== DXP transmission demo ===\n";

    DXP_Keys keyGen;
    uint8_t key[16];
    check(keyGen.generateKey(key), "AES key generated from CSPRNG");
    std::cout << "\n";

    runKnownAnswerTests();
    std::cout << "\n";

    std::string message = "Heyy Its me! lawda pudina!! shivank bhaiya namaste!!";

    DXP dxp;
    dxp.Type(1);
    dxp.Sender(843);
    dxp.Receiver(314);
    dxp.HopCount(0);

    uint16_t routeArr[3] = {10, 20, 30};
    dxp.Route(routeArr, 3);

    DXP_PayloadString(&dxp, message.c_str());
    dxp.Encryption(true);
    dxp.AESKey(key);

    DXPPacket sent = dxp.process();
    check(sent.separator == DXP_SEPARATOR, "encrypted packet built");
    check(sent.flags == (DXP_FLAG_ENCRYPTED | DXP_FLAG_AUTHENTICATED),
          "encrypted packet flagged authenticated");

    std::vector<uint8_t> frame = serializePacket(sent, key);
    check(!frame.empty() && frame[0] == DXP_SEPARATOR, "packet serialized to frame");

    std::cout << "\nFrame bytes going over the wire:\n";
    printFrame(frame);
    std::cout << "\n";

    DXPPacket got;
    check(deserializePacket(frame, got, key), "frame parsed, CRC and MAC verified");
    check(processReceivedPacket(got, key), "payload decrypted");

    check(got.payloadLength == message.size() &&
          memcmp(got.payload, message.data(), message.size()) == 0,
          "decrypted payload matches original");

    check(got.senderId == 843 && got.receiverId == 314, "sender and receiver intact");
    check(got.routeCount == 3 && got.route[0] == 10 && got.route[2] == 30, "route intact");
    check(got.sequenceCount == 1 && got.sequence[0] == sent.sequence[0], "sequence intact");

    std::cout << "\nReceived payload: "
              << std::string(got.payload, got.payload + got.payloadLength) << "\n\n";

    std::vector<uint8_t> tampered = frame;
    tampered[tampered.size() - 2 - DXP_MAC_SIZE - 1] ^= 0x01;
    uint16_t forgedCrc = DXP_CRC::calculate(tampered.data(), tampered.size() - 2);
    tampered[tampered.size() - 2] = static_cast<uint8_t>(forgedCrc >> 8);
    tampered[tampered.size() - 1] = static_cast<uint8_t>(forgedCrc & 0xFF);
    DXPPacket forgedPacket;
    check(!deserializePacket(tampered, forgedPacket, key),
          "tampered frame with recomputed CRC rejected by MAC");

    check(!deserializePacket(frame, forgedPacket, nullptr),
          "authenticated frame rejected when no key is configured");

    DXPPacket downgraded = sent;
    downgraded.flags = 0;
    std::vector<uint8_t> downgradedFrame = serializePacket(downgraded, nullptr);
    check(!downgradedFrame.empty() &&
          !deserializePacket(downgradedFrame, forgedPacket, key),
          "unauthenticated frame rejected when key is configured");

    const char* plainText = "plain text round trip";
    size_t plainLen = strlen(plainText);
    DXP plain;
    plain.Type(1);
    plain.Sender(1);
    plain.Receiver(2);
    plain.HopCount(0);
    DXP_PayloadString(&plain, plainText);
    plain.Encryption(false);

    DXPPacket plainSent = plain.process();
    check(plainSent.separator == DXP_SEPARATOR, "plaintext packet built");

    std::vector<uint8_t> plainFrame = serializePacket(plainSent);
    DXPPacket plainGot;
    check(deserializePacket(plainFrame, plainGot), "plaintext frame parsed and CRC verified");
    check(processReceivedPacket(plainGot, key), "plaintext needs no key");
    check(plainGot.payloadLength == plainLen &&
          memcmp(plainGot.payload, plainText, plainLen) == 0,
          "plaintext payload matches");

    std::vector<uint8_t> corrupted = frame;
    corrupted[corrupted.size() / 2] ^= 0xFF;
    DXPPacket junk;
    check(!deserializePacket(corrupted, junk, key), "corrupted frame rejected");

    std::vector<uint8_t> truncated(frame.begin(), frame.begin() + frame.size() / 2);
    check(!deserializePacket(truncated, junk, key), "truncated frame rejected");

    std::string big240(240, 'A');
    DXP big;
    big.Type(1);
    big.Sender(5);
    big.Receiver(6);
    DXP_PayloadString(&big, big240.c_str());
    big.Encryption(true);
    big.AESKey(key);
    check(big.process().separator == DXP_SEPARATOR, "240 byte encrypted payload accepted");

    std::string big250(250, 'B');
    DXP over;
    over.Type(1);
    over.Sender(5);
    over.Receiver(6);
    DXP_PayloadString(&over, big250.c_str());
    over.Encryption(true);
    over.AESKey(key);
    DXPPacket rejected = over.process();
    check(rejected.separator == 0 && over.status() == DXP_ERROR_PAYLOAD_TOO_LARGE,
          "250 byte encrypted payload rejected");

    DXP noKey;
    noKey.Type(1);
    noKey.Sender(1);
    noKey.Receiver(2);
    DXP_PayloadString(&noKey, "secret");
    noKey.Encryption(true);
    DXPPacket noKeyPacket = noKey.process();
    check(noKeyPacket.separator == 0 && noKey.status() == DXP_ERROR_ENCRYPTION_FAILED,
          "encryption without key fails closed");

    DXP partialKey;
    partialKey.Type(1);
    partialKey.Sender(1);
    partialKey.Receiver(2);
    DXP_PayloadString(&partialKey, "secret");
    partialKey.Encryption(true);
    uint16_t shortKey[4] = {1, 2, 3, 4};
    partialKey.AESKeys(shortKey, 4);
    DXPPacket partialPacket = partialKey.process();
    check(partialPacket.separator == 0 && partialKey.status() == DXP_ERROR_INVALID_KEY,
          "partial AES key rejected");

    std::cout << "\n";

    VirtualNet net;
    VirtualTransport ta(net, 10), tb(net, 20), tc(net, 30);
    DXP_Link a(ta), b(tb), c(tc);

    a.setNodeAddress(10);
    b.setNodeAddress(20);
    c.setNodeAddress(30);

    uint8_t linkKey[16];
    check(keyGen.generateKey(linkKey), "link key generated from CSPRNG");
    a.setAESKey(linkKey);
    b.setAESKey(linkKey);
    c.setAESKey(linkKey);

    a.setHopLimit(8);
    b.setHopLimit(8);
    c.setHopLimit(8);

    a.setRetryPolicy(50, 5);
    b.setRetryPolicy(50, 5);
    c.setRetryPolicy(50, 5);

    net.connect(10, 20);

    uint16_t from = 0;
    std::vector<uint8_t> payload;

    std::string m1 = "protocol direct message";
    a.sendString(20, m1.c_str());
    bool ok = pumpUntil([&] {
        return b.nextReceived(from, payload);
    }, a, b, nullptr, 3000);
    check(ok && from == 10 && payload.size() == m1.size() &&
          memcmp(payload.data(), m1.data(), m1.size()) == 0,
          "direct encrypted delivery");

    check(pumpUntil([&] {
        return a.pendingCount() == 0;
    }, a, b, nullptr, 3000), "ack clears pending");

    std::vector<uint8_t> capturedAck;
    for (size_t i = 0; i < tb.written.size(); i++) {
        if (tb.written[i].size() > 1 && tb.written[i][1] == 2)
            capturedAck = tb.written[i];
    }
    check(!capturedAck.empty(), "ack frame captured");
    uint32_t dupBefore = a.duplicatesDropped();
    net.broadcast(20, capturedAck);
    net.broadcast(20, capturedAck);
    for (int i = 0; i < 8; i++)
        a.poll();
    check(a.duplicatesDropped() >= dupBefore + 1, "replayed ack dropped by dedup");
    check(a.pendingCount() == 0, "replayed ack does not disturb pending state");

    ta.dropsLeft = 2;
    std::string m2 = "message that loses its first tries";
    a.sendString(20, m2.c_str());
    ok = pumpUntil([&] {
        return b.nextReceived(from, payload);
    }, a, b, nullptr, 3000);
    check(ok && payload.size() == m2.size() &&
          memcmp(payload.data(), m2.data(), m2.size()) == 0,
          "retransmission recovers loss");
    check(a.retriesSent() >= 2, "sender retried at least twice");
    pumpUntil([&] {
        return a.pendingCount() == 0;
    }, a, b, nullptr, 3000);

    ta.written.clear();
    a.sendString(20, "duplicate frame test");
    check(!ta.written.empty(), "frame captured for duplication");
    std::vector<uint8_t> dupFrame = ta.written.back();
    net.dropQueued(20);
    net.broadcast(10, dupFrame);
    net.broadcast(10, dupFrame);

    ok = pumpUntil([&] {
        return b.nextReceived(from, payload);
    }, a, b, nullptr, 3000);
    check(ok && payload.size() == 20 &&
          memcmp(payload.data(), "duplicate frame test", 20) == 0,
          "first copy delivered");
    check(!b.nextReceived(from, payload), "second copy dropped as duplicate");
    check(b.duplicatesDropped() >= 1, "duplicate counted");
    pumpUntil([&] {
        return a.pendingCount() == 0;
    }, a, b, nullptr, 3000);

    ta.written.clear();
    a.sendString(20, "survives stream garbage");
    check(!ta.written.empty(), "frame captured for corruption test");
    std::vector<uint8_t> good = ta.written.back();
    net.dropQueued(20);

    std::vector<uint8_t> noise;
    noise.push_back(0xDE);
    noise.push_back(0xAD);
    noise.push_back(0xBE);
    noise.push_back(0xEF);
    net.broadcast(10, noise);

    std::vector<uint8_t> bad = good;
    bad[bad.size() / 2] ^= 0xFF;
    net.broadcast(10, bad);
    net.broadcast(10, good);

    ok = pumpUntil([&] {
        return b.nextReceived(from, payload);
    }, a, b, nullptr, 3000);
    check(ok && payload.size() == 23 &&
          memcmp(payload.data(), "survives stream garbage", 23) == 0,
          "stream resync after garbage and corruption");
    pumpUntil([&] {
        return a.pendingCount() == 0;
    }, a, b, nullptr, 3000);

    drain(a);
    drain(b);
    drain(c);

    net.clearLinks();
    net.connect(10, 20);
    net.connect(20, 30);

    std::string m3 = "routed across two hops";
    a.sendString(30, m3.c_str());
    ok = pumpUntil([&] {
        return c.nextReceived(from, payload);
    }, a, b, &c, 4000);
    check(ok && from == 10 && payload.size() == m3.size() &&
          memcmp(payload.data(), m3.data(), m3.size()) == 0,
          "delivery through relay node");

    check(pumpUntil([&] {
        return a.pendingCount() == 0;
    }, a, b, &c, 4000), "ack returned through relay");
    check(b.relayedCount() >= 1, "intermediate node relayed frames");

    std::string m4 = "broadcast to everyone";
    a.sendString(DXP_BROADCAST, m4.c_str());
    check(a.pendingCount() == 0, "broadcast needs no ack");

    uint16_t fromB = 0, fromC = 0;
    std::vector<uint8_t> gotB, gotC;
    bool gotBFlag = false, gotCFlag = false;
    ok = pumpUntil([&] {
        if (!gotBFlag)
            gotBFlag = b.nextReceived(fromB, gotB);
        if (!gotCFlag)
            gotCFlag = c.nextReceived(fromC, gotC);
        return gotBFlag && gotCFlag;
    }, a, b, &c, 4000);

    check(ok && gotB.size() == m4.size() &&
          memcmp(gotB.data(), m4.data(), m4.size()) == 0,
          "broadcast reaches neighbour node");
    check(gotC.size() == m4.size() &&
          memcmp(gotC.data(), m4.data(), m4.size()) == 0,
          "broadcast reaches far node through relay");

    net.clearLinks();
    net.connect(10, 20);

    drain(b);
    ta.dropsLeft = 100;
    a.sendString(20, "this one never arrives");
    check(pumpUntil([&] {
        return a.pendingCount() == 0 && a.deliveryFailures() >= 1;
    }, a, b, nullptr, 3000), "gives up after max attempts");
    ta.dropsLeft = 0;

    VirtualNet net2;
    VirtualTransport t40(net2, 40), t50(net2, 50);
    DXP_Link d40(t40), d50(t50);
    d40.setNodeAddress(40);
    d50.setNodeAddress(50);
    d40.setAESKey(linkKey);
    d50.setAESKey(linkKey);
    d40.setRetryPolicy(50, 5);
    d50.setRetryPolicy(50, 5);
    net2.connect(40, 50);

    std::string ping = "ping from forty";
    std::string pong = "pong from fifty";
    d40.sendString(50, ping.c_str());
    d50.sendString(40, pong.c_str());

    uint16_t s40 = 0, s50 = 0;
    std::vector<uint8_t> p40, p50;
    bool gotPing = false, gotPong = false;
    ok = pumpUntil([&] {
        if (!gotPing)
            gotPing = d50.nextReceived(s40, p40);
        if (!gotPong)
            gotPong = d40.nextReceived(s50, p50);
        return gotPing && gotPong;
    }, d40, d50, nullptr, 4000);
    check(ok && s40 == 40 && p40.size() == ping.size() &&
          memcmp(p40.data(), ping.data(), ping.size()) == 0,
          "bidirectional delivery A to B");
    check(gotPong && s50 == 50 && p50.size() == pong.size() &&
          memcmp(p50.data(), pong.data(), pong.size()) == 0,
          "bidirectional delivery B to A");
    check(pumpUntil([&] {
        return d40.pendingCount() == 0 && d50.pendingCount() == 0;
    }, d40, d50, nullptr, 4000), "both directions acked");
    check(d40.deliveryFailures() == 0 && d50.deliveryFailures() == 0,
          "no delivery failures in bidirectional traffic");

    {
        std::atomic<bool> stopPoller(false);
        std::thread poller([&] {
            while (!stopPoller.load()) {
                d40.poll();
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });

        std::string threaded = "sent while another thread polls";
        bool sentOk = d40.sendString(50, threaded.c_str());

        uint16_t ts = 0;
        std::vector<uint8_t> tp;
        bool gotThreaded = pumpUntil([&] {
            return d50.nextReceived(ts, tp);
        }, d40, d50, nullptr, 4000);

        stopPoller.store(true);
        poller.join();

        check(sentOk && gotThreaded && ts == 40 && tp.size() == threaded.size() &&
              memcmp(tp.data(), threaded.data(), threaded.size()) == 0,
              "concurrent poll while sending is safe");
    }

    std::cout << "\n";
    if (failures == 0)
        std::cout << "ALL CHECKS PASSED\n";
    else
        std::cout << failures << " CHECK(S) FAILED\n";

    return failures == 0 ? 0 : 1;
}
