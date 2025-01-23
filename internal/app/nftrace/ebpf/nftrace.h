#ifndef __NFTRACE_H__
#define __NFTRACE_H__

#include "spinlock.h"

// #define LINUX_VERSION_CODE KERNEL_VERSION(6, 11, 0)

struct nft_rule
{
    //    struct list_head list;
    u64 handle : 42,
        genmask : 2,
        dlen : 12,
        udata : 1;
    //    unsigned char data[];
} __attribute__((preserve_access_index));

struct nft_rule_dp
{
    u64 is_last : 1,
        dlen : 12,
        handle : 42; /* for tracing */
} __attribute__((preserve_access_index));

struct nft_table
{
    // struct list_head list;
    // struct rhltable chains_ht;
    // struct list_head chains;
    // struct list_head sets;
    // struct list_head objects;
    // struct list_head flowtables;
    // u64 hgenerator;
    u64 handle;
    //    u32 use;
    u16 family : 6,
        flags : 8,
        genmask : 2;
    u32 nlpid;
    char *name;
    //     u16 udlen;
    //     u8 *udata;
    // #if LINUX_VERSION_CODE > KERNEL_VERSION(6, 3, 13)
    //     u8 validate_state;
    // #endif
} __attribute__((preserve_access_index));

struct nft_chain
{
    // struct nft_rule *rules_gen_0;
    // struct nft_rule *rules_gen_1;
    // struct list_head rules;
    // struct list_head list;
    // struct rhlist_head rhlhead;
    struct nft_table *table;
    u64 handle;
    // u32 use;
    // u8 flags : 5,
    //     bound : 1,
    //     genmask : 2;
    char *name;
    // u16 udlen;
    // u8 *udata;

    // /* Only used during control plane commit phase: */
    // struct nft_rule **rules_next;
} __attribute__((preserve_access_index));

struct nft_verdict
{
    u32 code;
    struct nft_chain *chain;
} __attribute__((preserve_access_index));

struct nft_pktinfo
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;

} __attribute__((preserve_access_index));

enum nft_chain_types
{
    NFT_CHAIN_T_DEFAULT = 0,
    NFT_CHAIN_T_ROUTE,
    NFT_CHAIN_T_NAT,
    NFT_CHAIN_T_MAX
};

// #define NFT_MAX_HOOKS (NF_INET_INGRESS + 1)

struct nft_chain_type
{
    const char *name;
    enum nft_chain_types type;
    int family;
    // struct module *owner;
    // unsigned int hook_mask;
    // nf_hookfn *hooks[NFT_MAX_HOOKS];
    // int (*ops_register)(struct net *net, const struct nf_hook_ops *ops);
    // void (*ops_unregister)(struct net *net, const struct nf_hook_ops *ops);
} __attribute__((preserve_access_index));

struct nft_base_chain
{
    //    struct nf_hook_ops ops;
    //    struct list_head hook_list;
    const struct nft_chain_type *type;
    u8 policy;
    //    u8 flags;
    //    struct nft_stats *stats;
    struct nft_chain chain;
    //    struct flow_block flow_block;
} __attribute__((preserve_access_index));

struct nft_traceinfo
{
    // #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
    const struct nft_pktinfo *pkt;
    const struct nft_base_chain *basechain;
    const struct nft_chain *chain;
    const struct nft_rule *rule;
    const struct nft_verdict *verdict;
    enum nft_trace_types type;
    //   bool packet_dumped;
    //    bool trace;
    // #else
    // #if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    //     bool trace;
    //     bool nf_trace;
    //     bool packet_dumped;
    //     enum nft_trace_types type : 8;
    //     u32 skbid;
    //     const struct nft_pktinfo *pkt;
    //     const struct nft_base_chain *basechain;
    //     const struct nft_chain *chain;
    //     const struct nft_rule_dp *rule;
    //     const struct nft_verdict *verdict;
    // #else
    //     bool trace;
    //     bool nf_trace;
    //     bool packet_dumped;
    //     enum nft_trace_types type : 8;
    //     u32 skbid;
    //     const struct nft_base_chain *basechain;
    // #endif
    // #endif
} __attribute__((preserve_access_index));

struct trace_info
{
    u32 id;
    u32 trace_hash;
    u8 table_name[64];
    u64 table_handle;
    u8 chain_name[64];
    u64 chain_handle;
    u64 rule_handle;
    u8 jump_target[64];
    u64 time;
    u64 counter;
    u32 verdict;
    u8 type;
    u8 family;
    u8 nfproto;
    u8 policy;
    u32 mark;
    u32 iif;
    u32 oif;
    u16 iif_type;
    u16 oif_type;
    u8 iif_name[16];
    u8 oif_name[16];
    u16 src_port;
    u16 dst_port;
    u32 src_ip;
    u32 dst_ip;
    struct in6_addr src_ip6;
    struct in6_addr dst_ip6;
    u16 len;
    u8 src_mac[6];
    u8 dst_mac[6];
    u8 ip_proto; // 120 bytes
};

const struct trace_info *unused __attribute__((unused));

#endif