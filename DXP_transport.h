#ifndef DXP_TRANSPORT_H
#define DXP_TRANSPORT_H

#include <cstdint>
#include <cstddef>

class DXP_Transport {
public:
    virtual ~DXP_Transport() {}
    virtual bool write(const uint8_t* data, size_t length) = 0;
    virtual int read(uint8_t* buffer, size_t maxLength) = 0;
};

#endif
