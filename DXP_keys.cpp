#include "DXP_keys.h"
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#elif defined(__linux__)
#include <sys/types.h>
#include <sys/random.h>
#include <unistd.h>
#include <errno.h>
#include <fstream>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>
#else
#include <fstream>
#endif

#if !defined(_WIN32)
static bool readUrandom(uint8_t* out, size_t length) {
    std::ifstream stream("/dev/urandom", std::ios::in | std::ios::binary);
    if (!stream)
        return false;
    stream.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(length));
    return stream.gcount() == static_cast<std::streamsize>(length);
}
#endif

DXP_Keys::DXP_Keys() {}

bool DXP_Keys::fillRandom(uint8_t* out, size_t length) {
    if (!out || length == 0)
        return false;

#if defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(NULL, out, static_cast<ULONG>(length),
                                       BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status >= 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(out, length);
    return true;
#elif defined(__linux__)
    size_t done = 0;
    while (done < length) {
        ssize_t n = getrandom(out + done, length - done, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        done += static_cast<size_t>(n);
    }
    if (done == length)
        return true;
    return readUrandom(out, length);
#else
    return readUrandom(out, length);
#endif
}

bool DXP_Keys::generateKey(uint8_t key[DXP_AES_KEY_SIZE]) {
    if (!key)
        return false;
    if (!fillRandom(key, DXP_AES_KEY_SIZE)) {
        memset(key, 0, DXP_AES_KEY_SIZE);
        return false;
    }
    return true;
}

bool DXP_Keys::generateIV(uint8_t iv[DXP_AES_IV_SIZE]) {
    if (!iv)
        return false;
    if (!fillRandom(iv, DXP_AES_IV_SIZE)) {
        memset(iv, 0, DXP_AES_IV_SIZE);
        return false;
    }
    return true;
}
