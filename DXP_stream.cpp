#include "DXP_stream.h"
#include "DXP_packet.h"
#include "DXP_CRC.h"
#include <algorithm>

static const size_t STREAM_BUFFER_LIMIT = 4096;
static const size_t STREAM_BUFFER_KEEP = 2048;

void DXP_Stream::reset() {
    buffer.clear();
}

void DXP_Stream::feed(const uint8_t* data, size_t length) {
    if (data && length > 0) {
        buffer.insert(buffer.end(), data, data + length);
        if (buffer.size() > STREAM_BUFFER_LIMIT)
            buffer.erase(buffer.begin(), buffer.begin() + (buffer.size() - STREAM_BUFFER_KEEP));
    }
}

bool DXP_Stream::nextFrame(std::vector<uint8_t>& frame) {
    while (true) {
        if (buffer.empty())
            return false;

        if (buffer[0] != DXP_SEPARATOR) {
            std::vector<uint8_t>::iterator it =
                std::find(buffer.begin(), buffer.end(), DXP_SEPARATOR);
            if (it == buffer.end()) {
                buffer.clear();
                return false;
            }
            buffer.erase(buffer.begin(), it);
        }

        size_t n = buffer.size();
        if (n < 5)
            return false;

        uint8_t seqCount = buffer[4];
        if (seqCount > DXP_MAX_SEQUENCE) {
            buffer.erase(buffer.begin());
            continue;
        }

        size_t routePos = 5u + 2u * seqCount + 5u;
        if (n < routePos)
            return false;

        uint8_t routeCount = buffer[routePos - 1];
        if (routeCount > DXP_MAX_ROUTE) {
            buffer.erase(buffer.begin());
            continue;
        }

        size_t lenPos = routePos + 2u * routeCount;
        if (n < lenPos + 2)
            return false;

        uint16_t payloadLength = static_cast<uint16_t>((buffer[lenPos] << 8) | buffer[lenPos + 1]);
        if (payloadLength > DXP_MAX_PAYLOAD) {
            buffer.erase(buffer.begin());
            continue;
        }

        size_t ivSize = (buffer[2] & DXP_FLAG_ENCRYPTED) ? DXP_AES_IV_SIZE : 0;
        size_t tagSize = (buffer[2] & DXP_FLAG_AUTHENTICATED) ? DXP_MAC_SIZE : 0;
        size_t total = lenPos + 2 + ivSize + payloadLength + tagSize + 2;
        if (n < total)
            return false;

        uint16_t frameCrc = static_cast<uint16_t>((buffer[total - 2] << 8) | buffer[total - 1]);
        if (!DXP_CRC::verify(buffer.data(), total - 2, frameCrc)) {
            buffer.erase(buffer.begin());
            continue;
        }

        frame.assign(buffer.begin(), buffer.begin() + total);
        buffer.erase(buffer.begin(), buffer.begin() + total);
        return true;
    }
}
