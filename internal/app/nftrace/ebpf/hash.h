#ifndef __HASH_H__
#define __HASH_H__

#include "jhash.h"
#include "common.h"

#define HASH_INIT4_SEED 0xcafe
#define HASH_INIT6_SEED 0xeb9f
#define HASH_MAP_HSARD_SEED 0xabcd

/* This really should be called fold32_ptr; it does no hashing to speak of. */
static __always_inline u32 hash32_ptr(const void *ptr)
{
    unsigned long val = (unsigned long)ptr;

#if BITS_PER_LONG == 64
    val ^= (val >> 32);
#endif
    return (u32)val;
}

static __always_inline u32 get_trace_id(struct sk_buff *skb)
{
    /* using skb address as ID results in a limited number of
     * values (and quick reuse).
     *
     * So we attempt to use as many skb members that will not
     * change while skb is with netfilter.
     */
    return jhash_2words(hash32_ptr(skb), BPF_CORE_READ(skb, hash), BPF_CORE_READ(skb, skb_iif));
}

static __always_inline u32 hash_from_tuple_v4(const struct ip4_tuple *tuple)
{
    return jhash_3words(tuple->src_ip,
                        ((u32)tuple->dst_port << 16) | tuple->src_port,
                        tuple->ip_proto, HASH_INIT4_SEED);
}

static __always_inline u32 hash_from_tuple_v6(const struct ip6_tuple *tuple)
{
    u32 a, b, c;

    a = tuple->src_ip6.in6_u.u6_addr32[0];
    b = tuple->src_ip6.in6_u.u6_addr32[1];
    c = tuple->src_ip6.in6_u.u6_addr32[2];
    __jhash_mix(a, b, c);
    a += tuple->src_ip6.in6_u.u6_addr32[3];
    b += ((u32)tuple->dst_port << 16) | tuple->src_port;
    c += tuple->ip_proto;
    __jhash_mix(a, b, c);
    a += HASH_INIT6_SEED;
    __jhash_final(a, b, c);
    return c;
}

#endif