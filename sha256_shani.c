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

TARGET_SHANI
void sha256_ni(uint32_t *digest, const void *data, uint32_t num_blks)
{
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    const __m128i *dataptr = (const __m128i *)data;

    __m128i STATE0, STATE1, MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;

    TMP = _mm_loadu_si128((const __m128i *)&digest[0]);
    STATE1 = _mm_loadu_si128((const __m128i *)&digest[4]);

    TMP = _mm_shuffle_epi32(TMP, 0xB1);          // CDAB
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    // EFGH
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    // ABEF
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); // CDGH

    while (num_blks > 0)
    {
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        MSG0 = _mm_loadu_si128(dataptr + 0);
        MSG1 = _mm_loadu_si128(dataptr + 1);
        MSG2 = _mm_loadu_si128(dataptr + 2);
        MSG3 = _mm_loadu_si128(dataptr + 3);

        MSG0 = _mm_shuffle_epi8(MSG0, MASK);
        MSG1 = _mm_shuffle_epi8(MSG1, MASK);
        MSG2 = _mm_shuffle_epi8(MSG2, MASK);
        MSG3 = _mm_shuffle_epi8(MSG3, MASK);

        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

        dataptr += 4;
        num_blks--;
    }

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);       // FEBA
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    // DCHG
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); // DCBA
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    // HGFE

    _mm_storeu_si128((__m128i *)&digest[0], STATE0);
    _mm_storeu_si128((__m128i *)&digest[4], STATE1);
}

TARGET_SHANI
static void test_sha256_implementation(void)
{
    extern void sha256(const unsigned char *message, unsigned int len, unsigned char *digest);

    applog(LOG_WARNING, "=== Testing SHA256 SHANI implementation ===");

    uint32_t digest[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    uint8_t block[64] = {0};
    memcpy(block, "abc", 3);
    block[3] = 0x80;
    block[62] = 0;
    block[63] = 24;

    sha256_ni(digest, block, 1);

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

    applog(LOG_WARNING, "SHANI:    %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
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

    applog(LOG_WARNING, "=== SHA256 SHANI test complete ===");
}

TARGET_SHANI
static void sha256_double_shani_full(uint8_t hash[32], const uint8_t data[80])
{
    uint32_t state[8] __attribute__((aligned(16)));
    uint8_t block[64] __attribute__((aligned(16)));

    memcpy(state, sha256_init_state, 32);

    swap32yes(block, data, 16);
    sha256_ni(state, block, 1);

    swap32yes(block, data + 64, 4);
    memset(block + 16, 0, 48);
    block[16] = 0x80;
    block[62] = 0x02;
    block[63] = 0x80;

    sha256_ni(state, block, 1);

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

    sha256_ni(state, block, 1);

    for (int i = 0; i < 8; i++)
    {
        state[i] = __builtin_bswap32(state[i]);
    }

    memcpy(hash, state, 32);
}

TARGET_SHANI
static void sha256_double_shani_swapped(uint8_t hash[32], const uint8_t data_swapped[80])
{
    uint32_t state[8] __attribute__((aligned(16)));
    uint8_t block[64] __attribute__((aligned(16)));

    memcpy(state, sha256_init_state, 32);

    memcpy(block, data_swapped, 64);
    sha256_ni(state, block, 1);

    memcpy(block, data_swapped + 64, 16);
    memset(block + 16, 0, 48);
    block[16] = 0x80;
    block[62] = 0x02;
    block[63] = 0x80;

    sha256_ni(state, block, 1);

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

    sha256_ni(state, block, 1);

    for (int i = 0; i < 8; i++)
    {
        state[i] = __builtin_bswap32(state[i]);
    }

    memcpy(hash, state, 32);
}

TARGET_SHANI
static void sha256_double_shani_midstate(uint8_t hash[32], const uint8_t midstate[32], const uint8_t data_tail[16])
{
    uint32_t state[8] __attribute__((aligned(16)));
    uint8_t block[64] __attribute__((aligned(16)));

    memcpy(state, midstate, 32);

    memcpy(block, data_tail, 16);
    memset(block + 16, 0, 48);
    block[16] = 0x80;
    block[62] = 0x02;
    block[63] = 0x80;

    sha256_ni(state, block, 1);

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

    sha256_ni(state, block, 1);

    for (int i = 0; i < 8; i++)
    {
        state[i] = __builtin_bswap32(state[i]);
    }

    memcpy(hash, state, 32);
}

TARGET_SHANI
bool scanhash_shani(struct thr_info *const thr, struct work *const work,
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

        sha256_double_shani_midstate(hash, work->midstate, data_tail_swapped);

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

bool sha_ni_available(void)
{
#if defined(__GNUC__) || defined(__clang__)
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;

#if defined(__x86_64__)
    eax = 7;
    ecx = 0;
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "0"(eax), "2"(ecx));
    bool available = (ebx & (1 << 29)) != 0;
    if (available)
    {
        test_sha256_implementation();
    }
    return available;
#else
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
        return false;

    eax = 7;
    ecx = 0;
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "0"(eax), "2"(ecx));
    bool available = (ebx & (1 << 29)) != 0;
    if (available)
    {
        test_sha256_implementation();
    }
    return available;
#endif
#else
    return false;
#endif
#else
    return false;
#endif
}

#else

bool sha_ni_available(void)
{
    return false;
}

bool scanhash_shani(struct thr_info *const thr, struct work *const work,
                    uint32_t max_nonce, uint32_t *last_nonce, uint32_t nonce)
{
    return false;
}

#endif
