// go:build ignore

#include "vmlinux.h"
// #include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
// #include <linux/netfilter.h>

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

static inline u32 trace_fill_id(struct sk_buff *skb)
{
    int skb_iif;
    __u32 skb_hash;
    skb_iif = BPF_CORE_READ(skb, skb_iif);
    skb_hash = BPF_CORE_READ(skb, hash);
    /* using skb address as ID results in a limited number of
     * values (and quick reuse).
     *
     * So we attempt to use as many skb members that will not
     * change while skb is with netfilter.
     */
    return jhash_2words(hash32_ptr(skb), skb_hash, skb_iif);
}

struct nft_rule
{
    struct list_head list;
    u64 handle : 42,
        genmask : 2,
        dlen : 12,
        udata : 1;
    // union
    // {
    //     struct
    //     {
    //         u64 handle : 42,
    //             genmask : 2,
    //             dlen : 12,
    //             udata : 1;
    //     };
    //     u64 bit_fields;
    // };
    // u64 bit_fields;
    unsigned char data[];
};

struct nft_table
{
    struct list_head list;
    struct rhltable chains_ht;
    struct list_head chains;
    struct list_head sets;
    struct list_head objects;
    struct list_head flowtables;
    u64 hgenerator;
    u64 handle;
    u32 use;
    u16 family : 6,
        flags : 8,
        genmask : 2;
    u32 nlpid;
    char *name;
    u16 udlen;
    u8 *udata;
};

struct nft_chain
{
    struct nft_rule *rules_gen_0;
    struct nft_rule *rules_gen_1;
    struct list_head rules;
    struct list_head list;
    struct rhlist_head rhlhead;
    struct nft_table *table;
    u64 handle;
    u32 use;
    u8 flags : 5,
        bound : 1,
        genmask : 2;
    char *name;
    u16 udlen;
    u8 *udata;

    /* Only used during control plane commit phase: */
    struct nft_rule **rules_next;
};

struct nft_verdict
{
    u32 code;
    struct nft_chain *chain;
};

struct nft_pktinfo
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    bool tprot_set;
    u8 tprot;
    u16 fragoff;
    unsigned int thoff;
};

enum nft_chain_types
{
    NFT_CHAIN_T_DEFAULT = 0,
    NFT_CHAIN_T_ROUTE,
    NFT_CHAIN_T_NAT,
    NFT_CHAIN_T_MAX
};

#define NFT_MAX_HOOKS (NF_INET_INGRESS + 1)

struct nft_chain_type
{
    const char *name;
    enum nft_chain_types type;
    int family;
    struct module *owner;
    unsigned int hook_mask;
    nf_hookfn *hooks[NFT_MAX_HOOKS];
    int (*ops_register)(struct net *net, const struct nf_hook_ops *ops);
    void (*ops_unregister)(struct net *net, const struct nf_hook_ops *ops);
};

struct nft_base_chain
{
    struct nf_hook_ops ops;
    struct list_head hook_list;
    const struct nft_chain_type *type;
    u8 policy;
    u8 flags;
    struct nft_stats *stats;
    struct nft_chain chain;
    struct flow_block flow_block;
};

struct nft_traceinfo
{
    const struct nft_pktinfo *pkt;
    const struct nft_base_chain *basechain;
    const struct nft_chain *chain;
    const struct nft_rule *rule;
    const struct nft_verdict *verdict;
    enum nft_trace_types type;
    bool packet_dumped;
    bool trace;
} __attribute__((preserve_access_index));

struct trace_info
{
    u32 id;
    enum nft_trace_types type;
    int family;
    u8 table_name[64];
    u64 table_handle;
    u8 chain_name[64];
    u64 chain_handle;
    u64 rule_handle;
    u8 nfproto;
    u32 verdict;
    u8 policy;
    u32 mark;
    u32 iif;
    u16 iif_type;
    u8 iif_name[16];
    u32 oif;
    u16 oif_type;
    u8 oif_name[16];
};

const struct trace_info *unused __attribute__((unused));

char __license[] SEC("license") = "Dual MIT/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/nft_trace_notify")
int BPF_KPROBE(kprobe_nft_trace_notify, struct nft_traceinfo *info)
{
    struct trace_info *trace;
    struct nft_rule rule_data;

    trace = bpf_ringbuf_reserve(&events, sizeof(struct trace_info), 0);
    if (!trace)
    {
        return 0;
    }

    trace->id = trace_fill_id(BPF_CORE_READ(info, pkt, skb));
    trace->type = BPF_CORE_READ(info, type);
    trace->family = BPF_CORE_READ(info, basechain, type, family);
    bpf_probe_read_kernel_str(trace->table_name, sizeof(trace->table_name), BPF_CORE_READ(info, chain, table, name));
    trace->table_handle = BPF_CORE_READ(info, chain, table, handle);
    bpf_probe_read_kernel_str(trace->chain_name, sizeof(trace->chain_name), BPF_CORE_READ(info, chain, name));
    trace->chain_handle = BPF_CORE_READ(info, chain, handle);
    bpf_probe_read_kernel(&rule_data, sizeof(rule_data), BPF_CORE_READ(info, rule));
    trace->rule_handle = rule_data.handle;
    trace->nfproto = BPF_CORE_READ(info, pkt, state, pf);
    trace->verdict = BPF_CORE_READ(info, verdict, code);
    trace->policy = BPF_CORE_READ(info, basechain, policy);
    trace->mark = BPF_CORE_READ(info, pkt, skb, mark);
    trace->iif = BPF_CORE_READ(info, pkt, state, in, ifindex);
    trace->iif_type = BPF_CORE_READ(info, pkt, state, in, type);
    bpf_probe_read_kernel_str(trace->iif_name, sizeof(trace->iif_name), BPF_CORE_READ(info, pkt, state, in, name));
    trace->oif = BPF_CORE_READ(info, pkt, state, out, ifindex);
    trace->oif_type = BPF_CORE_READ(info, pkt, state, out, type);
    bpf_probe_read_kernel_str(trace->oif_name, sizeof(trace->oif_name), BPF_CORE_READ(info, pkt, state, out, name));

    bpf_ringbuf_submit(trace, 0);

    return 0;
}