#ifndef __JHASH_H__
#define __JHASH_H__

/* An arbitrary initial parameter */
#define JHASH_INITVAL 0xdeadbeef

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static __always_inline u32 rol32(u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

#define __jhash_mix(a, b, c) \
    {                        \
        a -= c;              \
        a ^= rol32(c, 4);    \
        c += b;              \
        b -= a;              \
        b ^= rol32(a, 6);    \
        a += c;              \
        c -= b;              \
        c ^= rol32(b, 8);    \
        b += a;              \
        a -= c;              \
        a ^= rol32(c, 16);   \
        c += b;              \
        b -= a;              \
        b ^= rol32(a, 19);   \
        a += c;              \
        c -= b;              \
        c ^= rol32(b, 4);    \
        b += a;              \
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
static __always_inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval)
{
    a += initval;
    b += initval;
    c += initval;

    __jhash_final(a, b, c);

    return c;
}

static __always_inline u32 jhash_3words(u32 a, u32 b, __u32 c,
                                        u32 initval)
{
    return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static __always_inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
    return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static __always_inline u32 jhash_1word(u32 a, u32 initval)
{
    return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#endif