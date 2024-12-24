#ifndef __HASH_H__
#define __HASH_H__

/* An arbitrary initial parameter */
#define JHASH_INITVAL 0xdeadbeef

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c) \
    {                          \
        c ^= b;                \
        c -= rol32(b, 14);     \
        a ^= c;                \
        a -= rol32(c, 11);     \
        b ^= a;                \
        b -= rol32(a, 25);     \
        c ^= b;                \
        c -= rol32(b, 16);     \
        a ^= c;                \
        a -= rol32(c, 4);      \
        b ^= a;                \
        b -= rol32(a, 14);     \
        c ^= b;                \
        c -= rol32(b, 24);     \
    }
/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval)
{
    a += initval;
    b += initval;
    c += initval;

    __jhash_final(a, b, c);

    return c;
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
    return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

/* This really should be called fold32_ptr; it does no hashing to speak of. */
static inline u32 hash32_ptr(const void *ptr)
{
    unsigned long val = (unsigned long)ptr;

#if BITS_PER_LONG == 64
    val ^= (val >> 32);
#endif
    return (u32)val;
}

#endif