/* NEON ChaCha20: four blocks at a time.
 *
 * mbedTLS ships only a scalar block function. ChaCha20 is a natural fit for
 * 4-wide SIMD -- lane b of every state vector holds block b's copy of that
 * word, so one pass of quarter rounds advances four blocks at once. The state
 * is transposed back at the end so each block's 16 words land contiguously.
 *
 * Included from chacha20.c; guarded by WARPQ_CHACHA20_NEON. */

#include <arm_neon.h>

/* A rotate is shift-left then shift-right-and-insert, two instructions rather
 * than the three an or-of-shifts needs. The 16-bit rotate is just a halfword
 * swap, and the 8-bit rotate a byte rotate, so both collapse to one. */
#define ROTL_NEON(v, n) vsriq_n_u32(vshlq_n_u32((v), (n)), (v), 32 - (n))
#define ROTL16_NEON(v) \
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)))

#define ROTL8_NEON(v)                                                        \
    vreinterpretq_u32_u8(vqtbl1q_or_shift(vreinterpretq_u8_u32(v)))

#define QR_NEON(a, b, c, d)                        \
    do {                                           \
        a = vaddq_u32(a, b);                       \
        d = veorq_u32(d, a); d = ROTL16_NEON(d);   \
        c = vaddq_u32(c, d);                       \
        b = veorq_u32(b, c); b = ROTL_NEON(b, 12); \
        a = vaddq_u32(a, b);                       \
        d = veorq_u32(d, a); d = ROTL8_NEON(d);    \
        c = vaddq_u32(c, d);                       \
        b = veorq_u32(b, c); b = ROTL_NEON(b, 7);  \
    } while (0)

/* ARMv7 NEON has no 128-bit table lookup, so the byte rotate is done with two
 * 64-bit lookups over the halves. */
static inline uint8x16_t vqtbl1q_or_shift(uint8x16_t v)
{
    static const uint8_t idx[8] = { 3, 0, 1, 2, 7, 4, 5, 6 };
    uint8x8_t t = vld1_u8(idx);

    return vcombine_u8(vtbl1_u8(vget_low_u8(v), t),
                       vtbl1_u8(vget_high_u8(v), t));
}

/* Rows become lanes: after this, lane b of the group holds block b's words. */
static inline void warpq_transpose4(uint32x4_t *a, uint32x4_t *b,
                                    uint32x4_t *c, uint32x4_t *d)
{
    uint32x4x2_t t0 = vtrnq_u32(*a, *b);
    uint32x4x2_t t1 = vtrnq_u32(*c, *d);

    *a = vcombine_u32(vget_low_u32(t0.val[0]), vget_low_u32(t1.val[0]));
    *b = vcombine_u32(vget_low_u32(t0.val[1]), vget_low_u32(t1.val[1]));
    *c = vcombine_u32(vget_high_u32(t0.val[0]), vget_high_u32(t1.val[0]));
    *d = vcombine_u32(vget_high_u32(t0.val[1]), vget_high_u32(t1.val[1]));
}

/* Produce four keystream blocks for counters base..base+3 and XOR them into
 * output. Caller guarantees 256 bytes of input and output. */
static void warpq_chacha20_4block_xor(const uint32_t initial_state[16],
                                      const unsigned char *input,
                                      unsigned char *output)
{
    uint32x4_t v[16], o[16];
    uint32_t ctr = initial_state[12];
    const uint32_t ctrs[4] = { ctr, ctr + 1, ctr + 2, ctr + 3 };
    int i, r, b;

    for (i = 0; i < 16; i++) {
        v[i] = (i == 12) ? vld1q_u32(ctrs) : vdupq_n_u32(initial_state[i]);
        o[i] = v[i];
    }

    for (r = 0; r < 10; r++) {
        QR_NEON(v[0], v[4], v[8],  v[12]);
        QR_NEON(v[1], v[5], v[9],  v[13]);
        QR_NEON(v[2], v[6], v[10], v[14]);
        QR_NEON(v[3], v[7], v[11], v[15]);

        QR_NEON(v[0], v[5], v[10], v[15]);
        QR_NEON(v[1], v[6], v[11], v[12]);
        QR_NEON(v[2], v[7], v[8],  v[13]);
        QR_NEON(v[3], v[4], v[9],  v[14]);
    }

    for (i = 0; i < 16; i++) {
        v[i] = vaddq_u32(v[i], o[i]);
    }

    for (i = 0; i < 16; i += 4) {
        warpq_transpose4(&v[i], &v[i + 1], &v[i + 2], &v[i + 3]);
    }

    /* After transposing each group of four, v[g*4 + b] holds block b's words
     * g*4 .. g*4+3, so block b is the four vectors at stride 4. */
    for (b = 0; b < 4; b++) {
        unsigned char *out = output + b * 64;
        const unsigned char *in = input + b * 64;
        int g;

        for (g = 0; g < 4; g++) {
            uint8x16_t ks = vreinterpretq_u8_u32(v[g * 4 + b]);
            uint8x16_t dat = vld1q_u8(in + g * 16);

            vst1q_u8(out + g * 16, veorq_u8(dat, ks));
        }
    }
}
