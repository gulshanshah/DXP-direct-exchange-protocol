#ifndef DXP_STREAM_H
#define DXP_STREAM_H

#include <vector>
#include <cstdint>
#include <cstddef>

class DXP_Stream {
public:
    void reset();
    void feed(const uint8_t* data, size_t length);
    bool nextFrame(std::vector<uint8_t>& frame);

private:
    std::vector<uint8_t> buffer;
};

#endif
