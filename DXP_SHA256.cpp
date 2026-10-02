#include "DXP_SHA256.h"
#include "DXP_util.h"
#include <cstring>

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

struct Sha256Ctx {
    uint32_t h[8];
    uint64_t totalLength;
    uint8_t block[64];
    size_t blockLength;
};

static uint32_t rotr(uint32_t x, int n) {
    return static_cast<uint32_t>((x >> n) | (x << (32 - n)));
}

static void sha256Transform(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];

    for (int i = 0; i < 16; i++) {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<uint32_t>(block[i * 4 + 3]);
    }

    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;

        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

static void sha256Init(Sha256Ctx& ctx) {
    ctx.h[0] = 0x6a09e667u;
    ctx.h[1] = 0xbb67ae85u;
    ctx.h[2] = 0x3c6ef372u;
    ctx.h[3] = 0xa54ff53au;
    ctx.h[4] = 0x510e527fu;
    ctx.h[5] = 0x9b05688cu;
    ctx.h[6] = 0x1f83d9abu;
    ctx.h[7] = 0x5be0cd19u;
    ctx.totalLength = 0;
    ctx.blockLength = 0;
    memset(ctx.block, 0, sizeof(ctx.block));
}

static void sha256Update(Sha256Ctx& ctx, const uint8_t* data, size_t length) {
    if (!data || length == 0)
        return;

    ctx.totalLength += length;

    while (length > 0) {
        size_t take = 64 - ctx.blockLength;
        if (take > length)
            take = length;

        memcpy(ctx.block + ctx.blockLength, data, take);
        ctx.blockLength += take;
        data += take;
        length -= take;

        if (ctx.blockLength == 64) {
            sha256Transform(ctx.h, ctx.block);
            ctx.blockLength = 0;
        }
    }
}

static void sha256Final(Sha256Ctx& ctx, uint8_t out[DXP_SHA256_SIZE]) {
    uint64_t bitLength = ctx.totalLength * 8;

    ctx.block[ctx.blockLength++] = 0x80;

    if (ctx.blockLength > 56) {
        while (ctx.blockLength < 64)
            ctx.block[ctx.blockLength++] = 0;
        sha256Transform(ctx.h, ctx.block);
        ctx.blockLength = 0;
    }

    while (ctx.blockLength < 56)
        ctx.block[ctx.blockLength++] = 0;

    for (int i = 7; i >= 0; i--)
        ctx.block[ctx.blockLength++] = static_cast<uint8_t>(bitLength >> (i * 8));

    sha256Transform(ctx.h, ctx.block);

    for (int i = 0; i < 8; i++) {
        out[i * 4] = static_cast<uint8_t>(ctx.h[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(ctx.h[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(ctx.h[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(ctx.h[i]);
    }

    dxp_secure_wipe(&ctx, sizeof(ctx));
}

void DXP_SHA256::hash(const uint8_t* data, size_t length, uint8_t out[DXP_SHA256_SIZE]) {
    Sha256Ctx ctx;
    sha256Init(ctx);
    sha256Update(ctx, data, length);
    sha256Final(ctx, out);
}

void DXP_HMAC::compute(const uint8_t* key, size_t keyLength,
                       const uint8_t* data, size_t dataLength,
                       uint8_t out[DXP_SHA256_SIZE]) {
    uint8_t keyBlock[64];
    memset(keyBlock, 0, sizeof(keyBlock));

    if (key && keyLength > 0) {
        if (keyLength > 64)
            DXP_SHA256::hash(key, keyLength, keyBlock);
        else
            memcpy(keyBlock, key, keyLength);
    }

    uint8_t pad[64];
    uint8_t innerHash[DXP_SHA256_SIZE];

    Sha256Ctx ctx;
    sha256Init(ctx);
    for (int i = 0; i < 64; i++)
        pad[i] = static_cast<uint8_t>(keyBlock[i] ^ 0x36);
    sha256Update(ctx, pad, 64);
    sha256Update(ctx, data, dataLength);
    sha256Final(ctx, innerHash);

    sha256Init(ctx);
    for (int i = 0; i < 64; i++)
        pad[i] = static_cast<uint8_t>(keyBlock[i] ^ 0x5c);
    sha256Update(ctx, pad, 64);
    sha256Update(ctx, innerHash, DXP_SHA256_SIZE);
    sha256Final(ctx, out);

    dxp_secure_wipe(keyBlock, sizeof(keyBlock));
    dxp_secure_wipe(pad, sizeof(pad));
    dxp_secure_wipe(innerHash, sizeof(innerHash));
}

bool DXP_HMAC::verify(const uint8_t* key, size_t keyLength,
                      const uint8_t* data, size_t dataLength,
                      const uint8_t expected[DXP_SHA256_SIZE]) {
    uint8_t computed[DXP_SHA256_SIZE];
    compute(key, keyLength, data, dataLength, computed);
    bool ok = dxp_constant_time_equal(computed, expected, DXP_SHA256_SIZE);
    dxp_secure_wipe(computed, sizeof(computed));
    return ok;
}

void dxp_deriveMacKey(const uint8_t* key, size_t keyLength,
                      uint8_t out[DXP_SHA256_SIZE]) {
    static const uint8_t label[] = {
        'D', 'X', 'P', 'v', '1', '-', 'm', 'a', 'c', '-', 'k', 'e', 'y'
    };
    DXP_HMAC::compute(key, keyLength, label, sizeof(label), out);
}
