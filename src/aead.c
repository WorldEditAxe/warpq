#include "aead.h"

#include <string.h>

#ifndef __SIZEOF_INT128__
#include <mbedtls/poly1305.h>
#endif

/* Little-endian loads and stores, spelled out byte by byte so they are right
 * on the big-endian MIPS targets too; compilers turn them into single loads
 * where the CPU is little-endian. */
static uint32_t ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

#ifdef __SIZEOF_INT128__
static uint64_t ld64(const uint8_t *p)
{
	return (uint64_t)ld32(p) | ((uint64_t)ld32(p + 4) << 32);
}
#endif

static void st32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void st64(uint8_t *p, uint64_t v)
{
	st32(p, (uint32_t)v);
	st32(p + 4, (uint32_t)(v >> 32));
}

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;

	while (n--)
		*v++ = 0;
}

/* ---- ChaCha20 ------------------------------------------------------------
 *
 * The quarter round is written once and used for plain words and for SIMD
 * vectors alike: with GCC/clang vector types, +, ^ and the shifts work lane
 * by lane, and the compiler turns the shift-or pair into the CPU's rotate
 * (vrlw on AltiVec, shl+sri or rev32 on NEON, vprold where AVX-512 has it). */

#define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define ROTL8(v) ROTL(v, 8)

#define QR_(a, b, c, d, rotl8)                          \
	a += b; d ^= a; d = ROTL(d, 16);                \
	c += d; b ^= c; b = ROTL(b, 12);                \
	a += b; d ^= a; d = rotl8(d);                   \
	c += d; b ^= c; b = ROTL(b, 7);
#define QR(a, b, c, d) QR_(a, b, c, d, ROTL8)

#define DOUBLE_ROUND(x)                                 \
	QR(x[0], x[4], x[8],  x[12])                    \
	QR(x[1], x[5], x[9],  x[13])                    \
	QR(x[2], x[6], x[10], x[14])                    \
	QR(x[3], x[7], x[11], x[15])                    \
	QR(x[0], x[5], x[10], x[15])                    \
	QR(x[1], x[6], x[11], x[12])                    \
	QR(x[2], x[7], x[8],  x[13])                    \
	QR(x[3], x[4], x[9],  x[14])

/* state: 4 constant words, 8 key words, the block counter, 3 nonce words */
static void chacha_setup(uint32_t s[16], const uint8_t key[32],
			 const uint8_t nonce[12])
{
	int i;

	s[0] = 0x61707865;
	s[1] = 0x3320646e;
	s[2] = 0x79622d32;
	s[3] = 0x6b206574;
	for (i = 0; i < 8; i++)
		s[4 + i] = ld32(key + 4 * i);
	s[12] = 0;
	for (i = 0; i < 3; i++)
		s[13 + i] = ld32(nonce + 4 * i);
}

/* One block XORed over 64 bytes of input a word at a time. */
static void chacha_block_xor(const uint32_t s[16], uint32_t ctr,
			     const uint8_t *in, uint8_t *out)
{
	uint32_t x[16];
	int i;

	memcpy(x, s, sizeof(x));
	x[12] = ctr;
	for (i = 0; i < 10; i++) {
		DOUBLE_ROUND(x)
	}
	for (i = 0; i < 16; i++)
		st32(out + 4 * i, ld32(in + 4 * i) ^ (x[i] + (i == 12 ? ctr : s[i])));
	wipe(x, sizeof(x));
}

static void chacha_block(const uint32_t s[16], uint32_t ctr, uint8_t out[64])
{
	uint32_t x[16];
	int i;

	memcpy(x, s, sizeof(x));
	x[12] = ctr;
	for (i = 0; i < 10; i++) {
		DOUBLE_ROUND(x)
	}
	for (i = 0; i < 16; i++)
		st32(out + 4 * i, x[i] + (i == 12 ? ctr : s[i]));
	wipe(x, sizeof(x));
}

/* A wide path XORs as many whole groups of its blocks as len holds and
 * returns how many bytes that was. */
typedef size_t (*chacha_wide_fn)(const uint32_t s[16], uint32_t ctr,
				 const uint8_t *in, uint8_t *out, size_t len);

#if defined(__GNUC__) && (defined(__SSE2__) || defined(__ARM_NEON) || \
	defined(__ALTIVEC__) || defined(__loongarch_sx) || defined(__mips_msa))
#define HAVE_VEC4 1
#endif
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#define HAVE_AVX2 1
#endif

#if defined(HAVE_VEC4) || defined(HAVE_AVX2)
#ifdef __clang__
#define SHUF4(a, b, i, j, k, l) __builtin_shufflevector(a, b, i, j, k, l)
#define SHUF8(a, b, i, j, k, l, m, n, o, p) \
	__builtin_shufflevector(a, b, i, j, k, l, m, n, o, p)
#else
#define SHUF4(a, b, i, j, k, l) __builtin_shuffle(a, b, (v4u){ i, j, k, l })
#define SHUF8(a, b, i, j, k, l, m, n, o, p) \
	__builtin_shuffle(a, b, (v8u){ i, j, k, l, m, n, o, p })
#endif
#endif

#ifdef HAVE_VEC4
typedef uint32_t v4u __attribute__((vector_size(16)));

/* Four blocks at once: lane b of x[i] is word i of block b, so one pass of
 * quarter rounds advances all four. */
static void vec4_init(v4u x[16], const uint32_t s[16], uint32_t ctr)
{
	int i;

	for (i = 0; i < 16; i++) {
		v4u t = { s[i], s[i], s[i], s[i] };

		x[i] = t;
	}
	{
		v4u c = { ctr, ctr + 1, ctr + 2, ctr + 3 };

		x[12] = c;
	}
}

/* Add the input back in, then a 4x4 transpose per group of four words puts
 * each block's keystream back in order for XORing over 256 bytes. */
static inline void vec4_xor(v4u x[16], const v4u o[16],
			    const uint8_t *in, uint8_t *out)
{
	int i, b;

	for (i = 0; i < 16; i += 4) {
		v4u a = x[i] + o[i], bb = x[i + 1] + o[i + 1];
		v4u c = x[i + 2] + o[i + 2], d = x[i + 3] + o[i + 3];
		v4u t0 = SHUF4(a, bb, 0, 4, 1, 5);
		v4u t1 = SHUF4(a, bb, 2, 6, 3, 7);
		v4u t2 = SHUF4(c, d, 0, 4, 1, 5);
		v4u t3 = SHUF4(c, d, 2, 6, 3, 7);

		/* x[i + b] is now block b's words i .. i+3 */
		x[i] = SHUF4(t0, t2, 0, 1, 4, 5);
		x[i + 1] = SHUF4(t0, t2, 2, 3, 6, 7);
		x[i + 2] = SHUF4(t1, t3, 0, 1, 4, 5);
		x[i + 3] = SHUF4(t1, t3, 2, 3, 6, 7);
	}
	for (b = 0; b < 4; b++) {
		for (i = 0; i < 4; i++) {
			size_t at = (size_t)b * 64 + (size_t)i * 16;
			v4u d;

			memcpy(&d, in + at, 16);
			d ^= x[i * 4 + b];
			memcpy(out + at, &d, 16);
		}
	}
}

static size_t chacha_vec4(const uint32_t s[16], uint32_t ctr,
			  const uint8_t *in, uint8_t *out, size_t len)
{
	size_t done = 0;

	while (len - done >= 256) {
		v4u x[16], o[16];
		int i, r;

		vec4_init(x, s, ctr);
		for (i = 0; i < 16; i++)
			o[i] = x[i];
		for (r = 0; r < 10; r++) {
			DOUBLE_ROUND(x)
		}
		vec4_xor(x, o, in + done, out + done);
		ctr += 4;
		done += 256;
	}
	return done;
}

#ifdef __aarch64__
typedef uint8_t v16b __attribute__((vector_size(16)));

/* The 8-bit rotate is a byte shuffle: one tbl instead of a shift pair. */
#define ROTL8_TBL(v) ((v4u)SHUF16((v16b)(v), (v16b)(v), \
	3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14))
#ifdef __clang__
#define SHUF16(a, b, ...) __builtin_shufflevector(a, b, __VA_ARGS__)
#else
#define SHUF16(a, b, ...) __builtin_shuffle(a, b, (v16b){ __VA_ARGS__ })
#endif
#define QR2(i, j, k, l)                                         \
	QR_(x[i], x[j], x[k], x[l], ROTL8_TBL)                  \
	QR_(y[i], y[j], y[k], y[l], ROTL8_TBL)

/* Two groups of four, interleaved. Each quarter round is a chain of a
 * dozen dependent instructions, and with one group there are only four
 * chains to overlap -- not enough to cover the add latency on any modern
 * core. AArch64's 32 vector registers hold both groups (with a few spills),
 * which runs about 1.7x faster than one group. */
static size_t chacha_vec4x2(const uint32_t s[16], uint32_t ctr,
			    const uint8_t *in, uint8_t *out, size_t len)
{
	size_t done = 0;

	while (len - done >= 512) {
		v4u x[16], y[16], o[16], p[16];
		int i, r;

		vec4_init(x, s, ctr);
		vec4_init(y, s, ctr + 4);
		for (i = 0; i < 16; i++) {
			o[i] = x[i];
			p[i] = y[i];
		}
		for (r = 0; r < 10; r++) {
			QR2(0, 4, 8, 12) QR2(1, 5, 9, 13)
			QR2(2, 6, 10, 14) QR2(3, 7, 11, 15)
			QR2(0, 5, 10, 15) QR2(1, 6, 11, 12)
			QR2(2, 7, 8, 13) QR2(3, 4, 9, 14)
		}
		vec4_xor(x, o, in + done, out + done);
		vec4_xor(y, p, in + done + 256, out + done + 256);
		ctr += 8;
		done += 512;
	}
	return done;
}
#endif
#endif

#ifdef HAVE_AVX2
typedef uint32_t v8u __attribute__((vector_size(32)));

/* The same eight blocks wide, for x86 CPUs with AVX2 (picked at run time:
 * the release builds target baseline x86-64, which stops at SSE2). The
 * transpose works within each 128-bit half, leaving block b in the low half
 * and block b+4 in the high half; the halves are paired up on the way out. */
__attribute__((target("avx2")))
static size_t chacha_avx2(const uint32_t s[16], uint32_t ctr,
			  const uint8_t *in, uint8_t *out, size_t len)
{
	size_t done = 0;

	while (len - done >= 512) {
		v8u x[16], o[16];
		int i, r, b;

		for (i = 0; i < 16; i++) {
			v8u t = { s[i], s[i], s[i], s[i], s[i], s[i], s[i], s[i] };

			x[i] = t;
		}
		{
			v8u c = { ctr, ctr + 1, ctr + 2, ctr + 3,
				  ctr + 4, ctr + 5, ctr + 6, ctr + 7 };

			x[12] = c;
		}
		for (i = 0; i < 16; i++)
			o[i] = x[i];
		for (r = 0; r < 10; r++) {
			DOUBLE_ROUND(x)
		}
		for (i = 0; i < 16; i += 4) {
			v8u a = x[i] + o[i], bb = x[i + 1] + o[i + 1];
			v8u c = x[i + 2] + o[i + 2], d = x[i + 3] + o[i + 3];
			v8u t0 = SHUF8(a, bb, 0, 8, 1, 9, 4, 12, 5, 13);
			v8u t1 = SHUF8(a, bb, 2, 10, 3, 11, 6, 14, 7, 15);
			v8u t2 = SHUF8(c, d, 0, 8, 1, 9, 4, 12, 5, 13);
			v8u t3 = SHUF8(c, d, 2, 10, 3, 11, 6, 14, 7, 15);

			x[i] = SHUF8(t0, t2, 0, 1, 8, 9, 4, 5, 12, 13);
			x[i + 1] = SHUF8(t0, t2, 2, 3, 10, 11, 6, 7, 14, 15);
			x[i + 2] = SHUF8(t1, t3, 0, 1, 8, 9, 4, 5, 12, 13);
			x[i + 3] = SHUF8(t1, t3, 2, 3, 10, 11, 6, 7, 14, 15);
		}
		for (b = 0; b < 4; b++) {
			v8u ks[4];
			int h;

			/* words 0-7 and 8-15 of block b, then of block b+4 */
			ks[0] = SHUF8(x[b], x[4 + b], 0, 1, 2, 3, 8, 9, 10, 11);
			ks[1] = SHUF8(x[8 + b], x[12 + b], 0, 1, 2, 3, 8, 9, 10, 11);
			ks[2] = SHUF8(x[b], x[4 + b], 4, 5, 6, 7, 12, 13, 14, 15);
			ks[3] = SHUF8(x[8 + b], x[12 + b], 4, 5, 6, 7, 12, 13, 14, 15);
			for (h = 0; h < 4; h++) {
				size_t at = done + (size_t)(b + (h >> 1) * 4) * 64 +
					    (size_t)(h & 1) * 32;
				v8u d;

				memcpy(&d, in + at, 32);
				d ^= ks[h];
				memcpy(out + at, &d, 32);
			}
		}
		ctr += 8;
		done += 512;
	}
	return done;
}

static int cpu_has_avx2(void)
{
	unsigned a, b, c, d, lo, hi;

	__asm__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0), "c"(0));
	if (a < 7)
		return 0;
	__asm__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
	/* OSXSAVE and AVX, and the OS saving the YMM registers */
	if ((c & (3u << 27)) != (3u << 27))
		return 0;
	__asm__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	if ((lo & 6) != 6)
		return 0;
	__asm__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(7), "c"(0));
	return (b >> 5) & 1;
}
#endif

static chacha_wide_fn chacha_wide;     /* 8 blocks per pass, if any */
static chacha_wide_fn chacha_narrow;   /* 4 blocks per pass, if any */
static const char *chacha_name = "scalar";

void aead_init(void)
{
#ifdef HAVE_VEC4
	chacha_narrow = chacha_vec4;
#ifdef __aarch64__
	chacha_wide = chacha_vec4x2;
#endif
#if defined(__ARM_NEON)
	chacha_name = "NEON";
#elif defined(__SSE2__)
	chacha_name = "SSE2";
#elif defined(__ALTIVEC__)
	chacha_name = "AltiVec";
#elif defined(__loongarch_sx)
	chacha_name = "LSX";
#else
	chacha_name = "MSA";
#endif
#endif
#ifdef HAVE_AVX2
	if (cpu_has_avx2()) {
		chacha_wide = chacha_avx2;
		chacha_name = "AVX2";
	}
#endif
}

const char *aead_impl(void)
{
	return chacha_name;
}

static void chacha_xor(const uint32_t s[16], uint32_t ctr,
		       const uint8_t *in, uint8_t *out, size_t len)
{
	uint8_t ks[64];
	size_t i, n;

	if (chacha_wide) {
		n = chacha_wide(s, ctr, in, out, len);
		ctr += (uint32_t)(n / 64);
		in += n;
		out += n;
		len -= n;
	}
	if (chacha_narrow) {
		n = chacha_narrow(s, ctr, in, out, len);
		ctr += (uint32_t)(n / 64);
		in += n;
		out += n;
		len -= n;
	}
	for (; len >= 64; in += 64, out += 64, len -= 64)
		chacha_block_xor(s, ctr++, in, out);
	if (len) {
		chacha_block(s, ctr, ks);
		for (i = 0; i < len; i++)
			out[i] = in[i] ^ ks[i];
		wipe(ks, sizeof(ks));
	}
}

/* ---- Poly1305 ------------------------------------------------------------
 *
 * Every block the AEAD feeds in is a full 16 bytes (short ones are padded
 * with zeros), so the 2^128 bit is always set. */

#ifdef __SIZEOF_INT128__
/* 64-bit CPUs: h in base 2^64 (two words and a few bits), r in two words.
 * One block is four 64x64->128 multiplies, against sixteen 32x32->64 for
 * the base-2^32 code mbedTLS uses everywhere. */
typedef unsigned __int128 u128;

struct poly1305 {
	uint64_t r0, r1, h0, h1, h2, pad0, pad1;
};

static void poly_init(struct poly1305 *p, const uint8_t key[32])
{
	p->r0 = ld64(key) & 0x0ffffffc0fffffffULL;
	p->r1 = ld64(key + 8) & 0x0ffffffc0ffffffcULL;
	p->h0 = p->h1 = p->h2 = 0;
	p->pad0 = ld64(key + 16);
	p->pad1 = ld64(key + 24);
}

static void poly_blocks(struct poly1305 *p, const uint8_t *m, size_t blocks)
{
	const uint64_t r0 = p->r0, r1 = p->r1;
	/* r1's low two bits are clamped to zero, so r1 * 5/4 is exact: it
	 * folds the 2^130 = 5 (mod p) reduction into the multiply */
	const uint64_t s1 = r1 + (r1 >> 2);
	uint64_t h0 = p->h0, h1 = p->h1, h2 = p->h2, c;
	u128 d0, d1;

	while (blocks--) {
		d0 = (u128)h0 + ld64(m);
		h0 = (uint64_t)d0;
		d1 = (u128)h1 + (uint64_t)(d0 >> 64) + ld64(m + 8);
		h1 = (uint64_t)d1;
		h2 += (uint64_t)(d1 >> 64) + 1;

		d0 = (u128)h0 * r0 + (u128)h1 * s1;
		d1 = (u128)h0 * r1 + (u128)h1 * r0 + (u128)(h2 * s1);
		h2 *= r0;

		h0 = (uint64_t)d0;
		d1 += (uint64_t)(d0 >> 64);
		h1 = (uint64_t)d1;
		h2 += (uint64_t)(d1 >> 64);

		/* fold everything above 2^130 back in, times 5 */
		c = (h2 >> 2) + (h2 & ~(uint64_t)3);
		h2 &= 3;
		d0 = (u128)h0 + c;
		h0 = (uint64_t)d0;
		d1 = (u128)h1 + (uint64_t)(d0 >> 64);
		h1 = (uint64_t)d1;
		h2 += (uint64_t)(d1 >> 64);
		m += 16;
	}
	p->h0 = h0;
	p->h1 = h1;
	p->h2 = h2;
}

static void poly_finish(struct poly1305 *p, uint8_t tag[16])
{
	uint64_t g0, g1, g2, mask, h0 = p->h0, h1 = p->h1;
	u128 t;

	/* h + 5 - 2^130 doesn't go negative exactly when h >= p */
	t = (u128)h0 + 5;
	g0 = (uint64_t)t;
	t = (u128)h1 + (uint64_t)(t >> 64);
	g1 = (uint64_t)t;
	g2 = p->h2 + (uint64_t)(t >> 64);
	mask = 0 - (g2 >> 2);
	h0 = (h0 & ~mask) | (g0 & mask);
	h1 = (h1 & ~mask) | (g1 & mask);

	t = (u128)h0 + p->pad0;
	st64(tag, (uint64_t)t);
	st64(tag + 8, h1 + p->pad1 + (uint64_t)(t >> 64));
}
#else
/* 32-bit CPUs: mbedTLS's own base-2^32 Poly1305, which is already the
 * right shape for a 32x32->64 multiplier (rewrites here came out slower). */
struct poly1305 {
	mbedtls_poly1305_context ctx;
};

static void poly_init(struct poly1305 *p, const uint8_t key[32])
{
	mbedtls_poly1305_init(&p->ctx);
	mbedtls_poly1305_starts(&p->ctx, key);
}

static void poly_blocks(struct poly1305 *p, const uint8_t *m, size_t blocks)
{
	mbedtls_poly1305_update(&p->ctx, m, 16 * blocks);
}

static void poly_finish(struct poly1305 *p, uint8_t tag[16])
{
	mbedtls_poly1305_finish(&p->ctx, tag);
	mbedtls_poly1305_free(&p->ctx);
}
#endif

/* data, then zeros up to a multiple of 16 */
static void poly_padded(struct poly1305 *p, const uint8_t *data, size_t len)
{
	uint8_t last[16] = { 0 };

	poly_blocks(p, data, len / 16);
	if (len % 16) {
		memcpy(last, data + len - len % 16, len % 16);
		poly_blocks(p, last, 1);
	}
}

/* RFC 8439 section 2.8: the one-time Poly1305 key is block 0's first half,
 * the text is encrypted from block 1, and the MAC covers aad, ciphertext and
 * both lengths. */
static void aead_mac(const uint32_t s[16], const uint8_t *aad, size_t aad_len,
		     const uint8_t *ct, size_t len, uint8_t tag[16])
{
	struct poly1305 p;
	uint8_t block0[64], lens[16];

	chacha_block(s, 0, block0);
	poly_init(&p, block0);
	poly_padded(&p, aad, aad_len);
	poly_padded(&p, ct, len);
	st64(lens, (uint64_t)aad_len);
	st64(lens + 8, (uint64_t)len);
	poly_blocks(&p, lens, 1);
	poly_finish(&p, tag);
	wipe(block0, sizeof(block0));
	wipe(&p, sizeof(p));
}

void aead_seal(const uint8_t key[AEAD_KEY_LEN], const uint8_t nonce[AEAD_NONCE_LEN],
	       const uint8_t *aad, size_t aad_len,
	       const uint8_t *in, size_t len, uint8_t *out,
	       uint8_t tag[AEAD_TAG_LEN])
{
	uint32_t s[16];

	chacha_setup(s, key, nonce);
	chacha_xor(s, 1, in, out, len);
	aead_mac(s, aad, aad_len, out, len, tag);
	wipe(s, sizeof(s));
}

int aead_open(const uint8_t key[AEAD_KEY_LEN], const uint8_t nonce[AEAD_NONCE_LEN],
	      const uint8_t *aad, size_t aad_len,
	      const uint8_t *in, size_t len, uint8_t *out,
	      const uint8_t tag[AEAD_TAG_LEN])
{
	uint32_t s[16];
	uint8_t want[16], diff = 0;
	int i;

	chacha_setup(s, key, nonce);
	aead_mac(s, aad, aad_len, in, len, want);
	for (i = 0; i < 16; i++)
		diff |= (uint8_t)(want[i] ^ tag[i]);
	if (!diff)
		chacha_xor(s, 1, in, out, len);
	wipe(s, sizeof(s));
	wipe(want, sizeof(want));
	return diff ? -1 : 0;
}
