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

#ifdef __GNUC__
#define TARGET_ARM_CRYPTO __attribute__((target("+crypto")))
#else
#define TARGET_ARM_CRYPTO
#endif

static const uint32_t K256[] __attribute__((aligned(16))) = {
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
static void sha256_transform_arm_crypto(uint32_t state[8], const uint8_t block[64])
{
    uint32x4_t STATE0, STATE1;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t TMP0, TMP1, TMP2;
    uint32x4_t ABEF_SAVE, CDGH_SAVE;

    STATE0 = vld1q_u32(&state[0]);
    STATE1 = vld1q_u32(&state[4]);

    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    MSG0 = vld1q_u32((const uint32_t *)(block + 0));
    MSG1 = vld1q_u32((const uint32_t *)(block + 16));
    MSG2 = vld1q_u32((const uint32_t *)(block + 32));
    MSG3 = vld1q_u32((const uint32_t *)(block + 48));

    MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
    MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
    MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
    MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));

    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[0]));
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[4]));
    TMP2 = vaddq_u32(MSG2, vld1q_u32(&K256[8]));

    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP0);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP0);
    MSG0 = vsha256su0q_u32(MSG0, MSG1);

    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP1);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP1);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
    MSG1 = vsha256su0q_u32(MSG1, MSG2);

    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP2);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP2);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
    MSG2 = vsha256su0q_u32(MSG2, MSG3);

    TMP0 = vaddq_u32(MSG3, vld1q_u32(&K256[12]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP0);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
    MSG3 = vsha256su0q_u32(MSG3, MSG0);

    TMP1 = vaddq_u32(MSG0, vld1q_u32(&K256[16]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP1);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
    MSG0 = vsha256su0q_u32(MSG0, MSG1);

    TMP2 = vaddq_u32(MSG1, vld1q_u32(&K256[20]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP2);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP2);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
    MSG1 = vsha256su0q_u32(MSG1, MSG2);

    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[24]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP0);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP0);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
    MSG2 = vsha256su0q_u32(MSG2, MSG3);

    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[28]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP1);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP1);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
    MSG3 = vsha256su0q_u32(MSG3, MSG0);

    TMP2 = vaddq_u32(MSG0, vld1q_u32(&K256[32]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP2);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP2);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
    MSG0 = vsha256su0q_u32(MSG0, MSG1);

    TMP0 = vaddq_u32(MSG1, vld1q_u32(&K256[36]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP0);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
    MSG1 = vsha256su0q_u32(MSG1, MSG2);

    TMP1 = vaddq_u32(MSG2, vld1q_u32(&K256[40]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP1);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
    MSG2 = vsha256su0q_u32(MSG2, MSG3);

    TMP2 = vaddq_u32(MSG3, vld1q_u32(&K256[44]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP2);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP2);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
    MSG3 = vsha256su0q_u32(MSG3, MSG0);

    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[48]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP0);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP0);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[52]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP1);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP1);

    TMP2 = vaddq_u32(MSG2, vld1q_u32(&K256[56]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP2);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP2);

    TMP0 = vaddq_u32(MSG3, vld1q_u32(&K256[60]));
    STATE1 = vsha256hq_u32(STATE1, STATE0, TMP0);
    STATE0 = vsha256h2q_u32(STATE0, STATE1, TMP0);

    STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
    STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}

TARGET_ARM_CRYPTO
static void sha256_double_arm_crypto(uint8_t hash[32], const uint8_t data[80], const uint8_t midstate[32])
{
    uint32_t state[8] __attribute__((aligned(16)));
    uint8_t block[64] __attribute__((aligned(16)));

    memcpy(state, midstate, 32);
    memcpy(block, data + 64, 16);
    memset(block + 16, 0, 48);
    block[16] = 0x80;
    block[62] = 0x02;
    block[63] = 0x80;

    sha256_transform_arm_crypto(state, block);

    uint8_t hash1[32] __attribute__((aligned(16)));
    memcpy(hash1, state, 32);

    static const uint32_t sha256_init[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(state, sha256_init, 32);

    memcpy(block, hash1, 32);
    memset(block + 32, 0, 32);
    block[32] = 0x80;
    block[62] = 0x01;
    block[63] = 0x00;

    sha256_transform_arm_crypto(state, block);
    memcpy(hash, state, 32);
}

TARGET_ARM_CRYPTO
bool scanhash_arm_crypto(struct thr_info *const thr, struct work *const work,
                         uint32_t max_nonce, uint32_t *last_nonce, uint32_t nonce)
{
    const uint8_t *const pmidstate = work->midstate;
    uint8_t *pdata = work->data;
    uint8_t *const phash = work->hash;
    uint32_t *hash32 = (uint32_t *)phash;
    uint32_t *nonce_p = (uint32_t *)(pdata + 76);

    uint8_t data_aligned[80] __attribute__((aligned(16)));
    uint8_t midstate_aligned[32] __attribute__((aligned(16)));
    uint8_t hash_buffer[32] __attribute__((aligned(16)));

    memcpy(data_aligned, pdata, 80);
    memcpy(midstate_aligned, pmidstate, 32);

    const uint8_t *midstate_le = midstate_aligned;
    uint8_t *data_le = data_aligned;

    LOCAL_swap32le(unsigned char, midstate_le, 32 / 4)
        LOCAL_swap32le(unsigned char, data_le, 80 / 4)

            uint32_t *nonce_le = (uint32_t *)(data_le + 76);
    uint32_t *hash32_buf = (uint32_t *)hash_buffer;

    /* Process in batches to reduce overhead and maintain performance at low difficulty */
    const uint32_t batch_size = 256;

    while (true)
    {
        uint32_t batch_end = nonce + batch_size;
        if (batch_end > max_nonce)
            batch_end = max_nonce;

        /* Process batch of nonces with minimal overhead */
        for (uint32_t n = nonce; n < batch_end; n++)
        {
            *nonce_le = n;

            sha256_double_arm_crypto(hash_buffer, data_le, midstate_le);

            if (unlikely(hash32_buf[7] == 0))
            {
                /* Found a potential solution, verify and return */
                memcpy(phash, hash_buffer, 32);
                *nonce_p = htole32(n);
                *last_nonce = n;
                return true;
            }

            /* Check work restart periodically (every 64 nonces) within batch */
            if (unlikely((n & 0x3f) == 0 && thr->work_restart))
            {
                *nonce_p = htole32(n);
                *last_nonce = n;
                return false;
            }
        }

        nonce = batch_end;

        if ((nonce >= max_nonce) || thr->work_restart)
        {
            *nonce_p = htole32(nonce);
            *last_nonce = nonce;
            return false;
        }
    }
}

#if defined(__linux__) && defined(__aarch64__)
#include <sys/auxv.h>
#include <asm/hwcap.h>

TARGET_ARM_CRYPTO
bool arm_crypto_available(void)
{
    unsigned long hwcaps = getauxval(AT_HWCAP);
    return (hwcaps & HWCAP_SHA2) != 0;
}
#else
bool arm_crypto_available(void)
{
    return false;
}
#endif

#else /* !WANT_ARM64_CRYPTO */

bool arm_crypto_available(void)
{
    return false;
}

bool scanhash_arm_crypto(struct thr_info *const thr, struct work *const work,
                         uint32_t max_nonce, uint32_t *last_nonce, uint32_t nonce)
{
    return false;
}

#endif /* WANT_ARM64_CRYPTO */
