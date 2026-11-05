/* __sync atomics for ARMv5, on the kernel's kuser helpers.
 *
 * ARMv5 has no ldrex/strex, so the compiler turns every atomic into a call
 * to __sync_*. GCC's libgcc supplies those through the cmpxchg helpers the
 * kernel maps at the top of every process (Documentation/arm/kernel_user_
 * helpers.rst); zig's compiler-rt does not, so the link fails. These are the
 * same loops libgcc uses, for the sizes warpq and zig's libc ask for.
 *
 * Linked into the armv5 build only (see build-release.sh). musl itself
 * already relies on these helpers on pre-v6 cores, so this adds no new
 * kernel requirement beyond CONFIG_KUSER_HELPERS, which ARMv5 kernels keep. */

#include <stdint.h>

typedef int (*kuser_cmpxchg_t)(int oldval, int newval, volatile int *ptr);
typedef int (*kuser_cmpxchg64_t)(const int64_t *oldval, const int64_t *newval,
                                 volatile int64_t *ptr);

/* Both return 0 when *ptr held oldval and now holds newval. */
#define kuser_cmpxchg   (*(kuser_cmpxchg_t)0xffff0fc0)
#define kuser_cmpxchg64 (*(kuser_cmpxchg64_t)0xffff0f60)

/* clang refuses a plain definition of a __sync builtin, so each is defined
 * under another name and given the builtin's symbol with an asm label. */
#define SYNC(ret, name, args) ret warpq_##name args __asm__(#name); ret warpq_##name args

SYNC(uint32_t, __sync_fetch_and_add_4, (volatile uint32_t *p, uint32_t v))
{
	uint32_t old;

	do
		old = *p;
	while (kuser_cmpxchg((int)old, (int)(old + v), (volatile int *)p));
	return old;
}

SYNC(uint32_t, __sync_fetch_and_sub_4, (volatile uint32_t *p, uint32_t v))
{
	uint32_t old;

	do
		old = *p;
	while (kuser_cmpxchg((int)old, (int)(old - v), (volatile int *)p));
	return old;
}

SYNC(uint32_t, __sync_val_compare_and_swap_4,
     (volatile uint32_t *p, uint32_t expect, uint32_t desired))
{
	uint32_t old;

	for (;;) {
		old = *p;
		if (old != expect)
			return old;
		if (!kuser_cmpxchg((int)old, (int)desired, (volatile int *)p))
			return old;
	}
}

SYNC(uint64_t, __sync_fetch_and_add_8, (volatile uint64_t *p, uint64_t v))
{
	int64_t old, new;

	do {
		old = (int64_t)*p;
		new = old + (int64_t)v;
	} while (kuser_cmpxchg64(&old, &new, (volatile int64_t *)p));
	return (uint64_t)old;
}

/* Byte operations go through a cmpxchg on the aligned word holding the byte.
 * Little-endian only, which is what arm-linux-musleabi is. */
#define BYTE_WORD(p)  ((volatile uint32_t *)((uintptr_t)(p) & ~(uintptr_t)3))
#define BYTE_SHIFT(p) (((uintptr_t)(p) & 3) * 8)

SYNC(uint8_t, __sync_val_compare_and_swap_1,
     (volatile uint8_t *p, uint8_t expect, uint8_t desired))
{
	volatile uint32_t *w = BYTE_WORD(p);
	unsigned sh = BYTE_SHIFT(p);
	uint32_t old, new;
	uint8_t cur;

	for (;;) {
		old = *w;
		cur = (uint8_t)(old >> sh);
		if (cur != expect)
			return cur;
		new = (old & ~((uint32_t)0xff << sh)) | ((uint32_t)desired << sh);
		if (!kuser_cmpxchg((int)old, (int)new, (volatile int *)w))
			return cur;
	}
}

SYNC(uint8_t, __sync_lock_test_and_set_1, (volatile uint8_t *p, uint8_t v))
{
	volatile uint32_t *w = BYTE_WORD(p);
	unsigned sh = BYTE_SHIFT(p);
	uint32_t old, new;

	do {
		old = *w;
		new = (old & ~((uint32_t)0xff << sh)) | ((uint32_t)v << sh);
	} while (kuser_cmpxchg((int)old, (int)new, (volatile int *)w));
	return (uint8_t)(old >> sh);
}
