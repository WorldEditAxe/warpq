#ifndef WARPQ_AEAD_H
#define WARPQ_AEAD_H

#include <stddef.h>
#include <stdint.h>

/* ChaCha20-Poly1305 (RFC 8439) for the tunnel's own TLS record layer -- see
 * tls_offload(). mbedTLS's version is portable C that does one 64-byte block
 * at a time and a 32-bit Poly1305; this one does four or eight ChaCha20
 * blocks per pass in SIMD registers (NEON, SSE2, AVX2, AltiVec) and runs
 * Poly1305 on 64x64-bit multiplies where the CPU has them. */

#define AEAD_KEY_LEN 32
#define AEAD_NONCE_LEN 12
#define AEAD_TAG_LEN 16

/* Pick the code paths this CPU can run. Call once, before any threads. */
void aead_init(void);

/* Which ChaCha20 code aead_init() picked, for the logs. */
const char *aead_impl(void);

/* in and out may be the same buffer. */
void aead_seal(const uint8_t key[AEAD_KEY_LEN], const uint8_t nonce[AEAD_NONCE_LEN],
	       const uint8_t *aad, size_t aad_len,
	       const uint8_t *in, size_t len, uint8_t *out,
	       uint8_t tag[AEAD_TAG_LEN]);

/* Returns 0, or -1 if the tag does not match (out is then left alone). */
int aead_open(const uint8_t key[AEAD_KEY_LEN], const uint8_t nonce[AEAD_NONCE_LEN],
	      const uint8_t *aad, size_t aad_len,
	      const uint8_t *in, size_t len, uint8_t *out,
	      const uint8_t tag[AEAD_TAG_LEN]);

#endif
