/*
 * Copyright 2025 Optimized for modern hardware
 * ARM Crypto Extensions implementation for SHA256
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 */

#include "config.h"
#include "driver-cpu.h"

#ifdef WANT_ARM64_CRYPTO

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <arm_neon.h>

#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#elif defined(__FreeBSD__)
#include <sys/auxv.h>
#include <elf.h>
#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#ifdef __GNUC__
#define TARGET_ARM_CRYPTO __attribute__((target("+crypto")))
#else
#define TARGET_ARM_CRYPTO
#endif

static const uint32_t k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

TARGET_ARM_CRYPTO
void sha256_arm_crypto(uint32_t *digest, const void *data, uint32_t num_blks)
{
    const uint8_t *dataptr = (const uint8_t *)data;

    uint32x4_t state0 = vld1q_u32(&digest[0]);
    uint32x4_t state1 = vld1q_u32(&digest[4]);

    while (num_blks--)
    {
        uint32x4_t abcd_save = state0;
        uint32x4_t efgh_save = state1;
        uint32x4_t msg0 = vld1q_u32((const uint32_t *)(dataptr + 0));
        uint32x4_t msg1 = vld1q_u32((const uint32_t *)(dataptr + 16));
        uint32x4_t msg2 = vld1q_u32((const uint32_t *)(dataptr + 32));
        uint32x4_t msg3 = vld1q_u32((const uint32_t *)(dataptr + 48));
        uint32x4_t tmp0, tmp1, tmp2;

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
        msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
        msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
        msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));
#endif

        tmp0 = vaddq_u32(msg0, vld1q_u32(&k256[0x00]));

        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, vld1q_u32(&k256[0x04]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, vld1q_u32(&k256[0x08]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, vld1q_u32(&k256[0x0c]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, vld1q_u32(&k256[0x10]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, vld1q_u32(&k256[0x14]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, vld1q_u32(&k256[0x18]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, vld1q_u32(&k256[0x1c]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, vld1q_u32(&k256[0x20]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, vld1q_u32(&k256[0x24]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, vld1q_u32(&k256[0x28]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, vld1q_u32(&k256[0x2c]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, vld1q_u32(&k256[0x30]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, vld1q_u32(&k256[0x34]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);

        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, vld1q_u32(&k256[0x38]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);

        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, vld1q_u32(&k256[0x3c]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);

        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);

        state0 = vaddq_u32(state0, abcd_save);
        state1 = vaddq_u32(state1, efgh_save);

        dataptr += 64;
    }

    vst1q_u32(&digest[0], state0);
    vst1q_u32(&digest[4], state1);
}

TARGET_ARM_CRYPTO
static void test_sha256_implementation(void)
{
    extern void sha256(const unsigned char *message, unsigned int len, unsigned char *digest);

    applog(LOG_WARNING, "=== Testing SHA256 ARM Crypto implementation ===");

    uint32_t digest[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    uint8_t block[64] = {0};
    memcpy(block, "abc", 3);
    block[3] = 0x80;
    block[62] = 0;
    block[63] = 24;

    sha256_arm_crypto(digest, block, 1);

    for (int i = 0; i < 8; i++)
    {
        digest[i] = __builtin_bswap32(digest[i]);
    }

    uint8_t generic_hash[32];
    sha256((uint8_t *)"abc", 3, generic_hash);

    applog(LOG_WARNING, "Test 1: SHA256('abc') - Known test vector");
    applog(LOG_WARNING, "Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    applog(LOG_WARNING, "Generic:  %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
           generic_hash[0], generic_hash[1], generic_hash[2], generic_hash[3],
           generic_hash[4], generic_hash[5], generic_hash[6], generic_hash[7],
           generic_hash[8], generic_hash[9], generic_hash[10], generic_hash[11],
           generic_hash[12], generic_hash[13], generic_hash[14], generic_hash[15],
           generic_hash[16], generic_hash[17], generic_hash[18], generic_hash[19],
           generic_hash[20], generic_hash[21], generic_hash[22], generic_hash[23],
           generic_hash[24], generic_hash[25], generic_hash[26], generic_hash[27],
           generic_hash[28], generic_hash[29], generic_hash[30], generic_hash[31]);

    applog(LOG_WARNING, "ARM Crypto:    %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
           ((uint8_t *)digest)[0], ((uint8_t *)digest)[1], ((uint8_t *)digest)[2], ((uint8_t *)digest)[3],
           ((uint8_t *)digest)[4], ((uint8_t *)digest)[5], ((uint8_t *)digest)[6], ((uint8_t *)digest)[7],
           ((uint8_t *)digest)[8], ((uint8_t *)digest)[9], ((uint8_t *)digest)[10], ((uint8_t *)digest)[11],
           ((uint8_t *)digest)[12], ((uint8_t *)digest)[13], ((uint8_t *)digest)[14], ((uint8_t *)digest)[15],
           ((uint8_t *)digest)[16], ((uint8_t *)digest)[17], ((uint8_t *)digest)[18], ((uint8_t *)digest)[19],
           ((uint8_t *)digest)[20], ((uint8_t *)digest)[21], ((uint8_t *)digest)[22], ((uint8_t *)digest)[23],
           ((uint8_t *)digest)[24], ((uint8_t *)digest)[25], ((uint8_t *)digest)[26], ((uint8_t *)digest)[27],
           ((uint8_t *)digest)[28], ((uint8_t *)digest)[29], ((uint8_t *)digest)[30], ((uint8_t *)digest)[31]);

    if (memcmp(generic_hash, digest, 32) == 0)
    {
        applog(LOG_WARNING, "✓ SHA256 test vector matches!");
    }
    else
    {
        applog(LOG_WARNING, "✗ SHA256 test vector MISMATCH!");
        applog(LOG_WARNING, "State words: %08x %08x %08x %08x %08x %08x %08x %08x",
               digest[0], digest[1], digest[2], digest[3],
               digest[4], digest[5], digest[6], digest[7]);
    }

    applog(LOG_WARNING, "=== SHA256 ARM Crypto test complete ===");
}

TARGET_ARM_CRYPTO
static void sha256_double_arm_crypto_full(uint8_t hash[32], const uint8_t data[80])
{
    uint32_t state[8] __attribute__((aligned(16)));
    uint8_t block[64] __attribute__((aligned(16)));

    memcpy(state, sha256_init_state, 32);

    swap32yes(block, data, 16);
    sha256_arm_crypto(state, block, 1);

    swap32yes(block, data + 64, 4);
    memset(block + 16, 0, 48);
    block[16] = 0x80;
    block[62] = 0x02;
    block[63] = 0x80;

    sha256_arm_crypto(state, block, 1);

    uint8_t hash1[32] __attribute__((aligned(16)));
    for (int i = 0; i < 8; i++)
    {
        ((uint32_t *)hash1)[i] = __builtin_bswap32(state[i]);
    }

    memcpy(state, sha256_init_state, 32);

    memcpy(block, hash1, 32);
    memset(block + 32, 0, 32);
    block[32] = 0x80;
    block[62] = 0x01;
    block[63] = 0x00;

    sha256_arm_crypto(state, block, 1);

    for (int i = 0; i < 8; i++)
    {
        state[i] = __builtin_bswap32(state[i]);
    }

    memcpy(hash, state, 32);
}

TARGET_ARM_CRYPTO
static void sha256_double_arm_crypto_swapped(uint8_t hash[32], const uint8_t data_swapped[80])
{
    uint32_t state[8] __attribute__((aligned(16)));
    uint8_t block[64] __attribute__((aligned(16)));

    memcpy(state, sha256_init_state, 32);

    memcpy(block, data_swapped, 64);
    sha256_arm_crypto(state, block, 1);

    memcpy(block, data_swapped + 64, 16);
    memset(block + 16, 0, 48);
    block[16] = 0x80;
    block[62] = 0x02;
    block[63] = 0x80;

    sha256_arm_crypto(state, block, 1);

    uint8_t hash1[32] __attribute__((aligned(16)));
    for (int i = 0; i < 8; i++)
    {
        ((uint32_t *)hash1)[i] = __builtin_bswap32(state[i]);
    }

    memcpy(state, sha256_init_state, 32);

    memcpy(block, hash1, 32);
    memset(block + 32, 0, 32);
    block[32] = 0x80;
    block[62] = 0x01;
    block[63] = 0x00;

    sha256_arm_crypto(state, block, 1);

    for (int i = 0; i < 8; i++)
    {
        state[i] = __builtin_bswap32(state[i]);
    }

    memcpy(hash, state, 32);
}

TARGET_ARM_CRYPTO
static void sha256_double_arm_crypto_midstate(uint8_t hash[32], const uint8_t midstate[32], const uint8_t data_tail[16])
{
    uint32_t state[8] __attribute__((aligned(16)));
    uint8_t block[64] __attribute__((aligned(16)));

    memcpy(state, midstate, 32);

    memcpy(block, data_tail, 16);
    memset(block + 16, 0, 48);
    block[16] = 0x80;
    block[62] = 0x02;
    block[63] = 0x80;

    sha256_arm_crypto(state, block, 1);

    uint8_t hash1[32] __attribute__((aligned(16)));
    for (int i = 0; i < 8; i++)
    {
        ((uint32_t *)hash1)[i] = __builtin_bswap32(state[i]);
    }

    memcpy(state, sha256_init_state, 32);

    memcpy(block, hash1, 32);
    memset(block + 32, 0, 32);
    block[32] = 0x80;
    block[62] = 0x01;
    block[63] = 0x00;

    sha256_arm_crypto(state, block, 1);

    for (int i = 0; i < 8; i++)
    {
        state[i] = __builtin_bswap32(state[i]);
    }

    memcpy(hash, state, 32);
}

TARGET_ARM_CRYPTO
bool scanhash_arm_crypto(struct thr_info *const thr, struct work *const work,
                         uint32_t max_nonce, uint32_t *last_nonce, uint32_t n)
{
    uint8_t *const hash = work->hash;
    uint8_t *data = work->data;
    const uint8_t *const target = work->target;
    uint32_t *const out_nonce = (uint32_t *)&data[0x4c];

    const uint32_t hash7_targ = le32toh(((const uint32_t *)target)[7]);
    uint32_t *const hash7_tmp = &((uint32_t *)hash)[7];

    uint8_t data_tail_swapped[16] __attribute__((aligned(16)));
    swap32yes(data_tail_swapped, data + 64, 4);
    uint32_t *nonce_swapped = (uint32_t *)&data_tail_swapped[12];

    while (true)
    {
        *out_nonce = n;
        *nonce_swapped = htobe32(n);

        sha256_double_arm_crypto_midstate(hash, work->midstate, data_tail_swapped);

        if (unlikely(le32toh(*hash7_tmp) <= hash7_targ))
        {
            *last_nonce = n;
            return true;
        }

        n++;

        if (unlikely(n >= max_nonce || thr->work_restart))
        {
            *last_nonce = n;
            return false;
        }
    }
}

#if defined(__aarch64__) || defined(__arm__)
bool arm_crypto_available(void)
{
#if defined(__aarch64__)
#if defined(__linux__)
    unsigned long hwcaps = getauxval(AT_HWCAP);
#ifdef HWCAP_SHA2
    bool available = (hwcaps & HWCAP_SHA2) != 0;
#else
    bool available = false;
#endif
    if (available)
    {
        test_sha256_implementation();
    }
    return available;
#elif defined(__APPLE__)
    int enabled = 0;
    size_t size = sizeof(enabled);
    if (sysctlbyname("hw.optional.armv8_sha", &enabled, &size, NULL, 0) == 0 && enabled)
    {
        test_sha256_implementation();
        return true;
    }
    return false;
#else
    return false;
#endif
#elif defined(__arm__)
#if defined(__linux__)
    unsigned long hwcaps = getauxval(AT_HWCAP2);
#ifdef HWCAP2_SHA2
    bool available = (hwcaps & HWCAP2_SHA2) != 0;
#else
    bool available = false;
#endif
    if (available)
    {
        test_sha256_implementation();
    }
    return available;
#else
    return false;
#endif
#else
    return false;
#endif
}
#else
bool arm_crypto_available(void)
{
    return false;
}
#endif

#endif /* WANT_ARM64_CRYPTO */
