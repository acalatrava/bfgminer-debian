/*
 * Copyright 2025 Optimized for modern hardware
 * Intel SHA Extensions (SHA-NI) implementation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 */

#include "config.h"
#include "driver-cpu.h"

#ifdef WANT_X8664_SHANI

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <immintrin.h>

#ifdef __GNUC__
#define TARGET_SHANI __attribute__((target("sha,sse4.1")))
#else
#define TARGET_SHANI
#endif

static inline TARGET_SHANI __m128i sha256_update(__m128i msg, __m128i state0, __m128i state1)
{
    __m128i msg_save = msg;
    msg = _mm_sha256msg1_epu32(msg, state0);
    msg = _mm_sha256msg2_epu32(msg, state1);
    return _mm_add_epi32(msg_save, msg);
}

TARGET_SHANI
static void sha256_transform_shani(uint32_t state[8], const uint8_t block[64])
{
    __m128i STATE0, STATE1;
    __m128i MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;

    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    TMP = _mm_loadu_si128((const __m128i *)&state[0]);
    STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);

    TMP = _mm_shuffle_epi32(TMP, 0xB1);
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);

    MSG0 = _mm_loadu_si128((const __m128i *)(block + 0));
    MSG1 = _mm_loadu_si128((const __m128i *)(block + 16));
    MSG2 = _mm_loadu_si128((const __m128i *)(block + 32));
    MSG3 = _mm_loadu_si128((const __m128i *)(block + 48));

    MSG0 = _mm_shuffle_epi8(MSG0, MASK);
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    MSG2 = _mm_shuffle_epi8(MSG2, MASK);
    MSG3 = _mm_shuffle_epi8(MSG3, MASK);

    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    MSG = _mm_add_epi32(MSG0, _mm_set_epi32(0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    MSG = _mm_add_epi32(MSG1, _mm_set_epi32(0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    MSG = _mm_add_epi32(MSG2, _mm_set_epi32(0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    MSG = _mm_add_epi32(MSG3, _mm_set_epi32(0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    MSG = _mm_add_epi32(MSG0, _mm_set_epi32(0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    MSG = _mm_add_epi32(MSG1, _mm_set_epi32(0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    MSG = _mm_add_epi32(MSG2, _mm_set_epi32(0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    MSG = _mm_add_epi32(MSG3, _mm_set_epi32(0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    MSG = _mm_add_epi32(MSG0, _mm_set_epi32(0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    MSG = _mm_add_epi32(MSG1, _mm_set_epi32(0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    MSG = _mm_add_epi32(MSG2, _mm_set_epi32(0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    MSG = _mm_add_epi32(MSG3, _mm_set_epi32(0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    MSG = _mm_add_epi32(MSG0, _mm_set_epi32(0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    MSG = _mm_add_epi32(MSG1, _mm_set_epi32(0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    MSG = _mm_add_epi32(MSG2, _mm_set_epi32(0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    MSG = _mm_add_epi32(MSG3, _mm_set_epi32(0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);

    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);
}

TARGET_SHANI
static void sha256_double_shani(uint8_t hash[32], const uint8_t data[80], const uint8_t midstate[32])
{
    uint32_t state[8] __attribute__((aligned(16)));
    uint8_t block[64] __attribute__((aligned(16)));

    memcpy(state, midstate, 32);
    memcpy(block, data + 64, 16);
    memset(block + 16, 0, 48);
    block[16] = 0x80;
    block[62] = 0x02;
    block[63] = 0x80;

    sha256_transform_shani(state, block);

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

    sha256_transform_shani(state, block);
    memcpy(hash, state, 32);
}

TARGET_SHANI
bool scanhash_shani(struct thr_info *const thr, struct work *const work,
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

            sha256_double_shani(hash_buffer, data_le, midstate_le);

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

bool sha_ni_available(void)
{
#if defined(__GNUC__) || defined(__clang__)
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;

/* Check if CPUID is supported */
#if defined(__x86_64__)
    /* CPUID is always available on x86_64 */
    eax = 7;
    ecx = 0;
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "0"(eax), "2"(ecx));
    /* SHA extensions are bit 29 of EBX */
    return (ebx & (1 << 29)) != 0;
#else
    /* On i386, we need to check if CPUID is available first */
    unsigned int flag;
    __asm__ __volatile__(
        "pushfl\n\t"
        "pushfl\n\t"
        "popl %%eax\n\t"
        "movl %%eax, %%ecx\n\t"
        "xorl $0x200000, %%eax\n\t"
        "pushl %%eax\n\t"
        "popfl\n\t"
        "pushfl\n\t"
        "popl %%eax\n\t"
        "popfl\n\t"
        "xorl %%ecx, %%eax\n\t"
        : "=a"(flag)
        :
        : "ecx");

    if (!(flag & 0x200000))
        return false; /* CPUID not supported */

    eax = 7;
    ecx = 0;
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "0"(eax), "2"(ecx));
    /* SHA extensions are bit 29 of EBX */
    return (ebx & (1 << 29)) != 0;
#endif
#else
    return false;
#endif
#else
    return false;
#endif
}

#else /* !WANT_X8664_SHANI */

bool sha_ni_available(void)
{
    return false;
}

bool scanhash_shani(struct thr_info *const thr, struct work *const work,
                    uint32_t max_nonce, uint32_t *last_nonce, uint32_t nonce)
{
    return false;
}

#endif /* WANT_X8664_SHANI */
