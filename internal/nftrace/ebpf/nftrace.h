#ifndef __NFTRACE_H__
#define __NFTRACE_H__

// #define LINUX_VERSION_CODE KERNEL_VERSION(6, 11, 0)

#define NFT_RULE_FIELDS      \
    struct list_head list;   \
    union                    \
    {                        \
        u64 flags;           \
        struct               \
        {                    \
            u64 handle : 42; \
            u64 genmask : 2; \
            u64 dlen : 12;   \
            u64 udata : 1;   \
        };                   \
    };                       \
    unsigned char data[]

#define NFT_RULE_DP_FIELDS \
    u64 is_last : 1,       \
        dlen : 12,         \
        handle : 42

#define NFT_RULE_DP_LAST_FIELDS(_variant_) \
    struct nft_rule_dp##_variant_ end;     \
    struct nft_rule_blob *blob;            \
    const struct nft_chain##_variant_ *chain

#define NFT_TABLE_FIELDS         \
    struct list_head list;       \
    struct rhltable chains_ht;   \
    struct list_head chains;     \
    struct list_head sets;       \
    struct list_head objects;    \
    struct list_head flowtables; \
    u64 hgenerator;              \
    u64 handle;                  \
    u32 use;                     \
    u16 family : 6,              \
        flags : 8,               \
        genmask : 2;             \
    char *name;                  \
    u16 udlen;                   \
    u8 *udata

#define NFT_CHAIN_FIELDS(_variant_)          \
    struct nft_rule##_variant_ *rules_gen_0; \
    struct nft_rule##_variant_ *rules_gen_1; \
    struct list_head rules;                  \
    struct list_head list;                   \
    struct rhlist_head rhlhead;              \
    struct nft_table##_variant_ *table;      \
    u64 handle;                              \
    u32 use;                                 \
    u8 flags : 5,                            \
        bound : 1,                           \
        genmask : 2;                         \
    char *name;                              \
    u16 udlen;                               \
    u8 *udata;                               \
    struct nft_rule##_variant_ **rules_next

#define NFT_VERDICT_FIELDS(_variant_) \
    u32 code;                         \
    struct nft_chain##_variant_ *chain

#define XT_ACTION_PARAM_FIELDS          \
    union                               \
    {                                   \
        const struct xt_match *match;   \
        const struct xt_target *target; \
    };                                  \
    union                               \
    {                                   \
        const void *matchinfo;          \
        const void *targinfo;           \
    };                                  \
    const struct nf_hook_state *state;  \
    int fragoff;                        \
    unsigned int thoff;                 \
    bool hotdrop

#define NFT_PKTINFO_FIELDS(_variant_)         \
    struct sk_buff *skb;                      \
    bool tprot_set;                           \
    u8 tprot;                                 \
    union                                     \
    {                                         \
        struct xt_action_param##_variant_ xt; \
        const struct nf_hook_state *state;    \
    }

#define NFT_CHAIN_TYPE_FIELDS                                             \
    const char *name;                                                     \
    enum nft_chain_types type;                                            \
    int family;                                                           \
    struct module *owner;                                                 \
    unsigned int hook_mask;                                               \
    nf_hookfn *hooks[NFT_MAX_HOOKS];                                      \
    int (*ops_register)(struct net * net, const struct nf_hook_ops *ops); \
    void (*ops_unregister)(struct net * net, const struct nf_hook_ops *ops)

#define NFT_BASE_CHAIN_FIELDS(_variant_)          \
    struct nf_hook_ops ops;                       \
    struct list_head hook_list;                   \
    const struct nft_chain_type##_variant_ *type; \
    u8 policy;                                    \
    u8 flags;                                     \
    struct nft_stats *stats;                      \
    struct nft_chain##_variant_ chain

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
#define NFT_TRACEINFO_FIELDS(_variant_)                \
    const struct nft_pktinfo##_variant_ *pkt;          \
    const struct nft_base_chain##_variant_ *basechain; \
    const struct nft_chain##_variant_ *chain;          \
    const struct nft_rule##_variant_ *rule;            \
    const struct nft_verdict##_variant_ *verdict;      \
    enum nft_trace_types type;                         \
    bool packet_dumped;                                \
    bool trace
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
#define NFT_TRACEINFO_FIELDS(_variant_)                \
    bool trace;                                        \
    bool nf_trace;                                     \
    bool packet_dumped;                                \
    enum nft_trace_types type : 8;                     \
    u32 skbid;                                         \
    const struct nft_pktinfo##_variant_ *pkt;          \
    const struct nft_base_chain##_variant_ *basechain; \
    const struct nft_chain##_variant_ *chain;          \
    const struct nft_rule_dp##_variant_ *rule;         \
    const struct nft_verdict##_variant_ *verdict
#else
#define NFT_TRACEINFO_FIELDS(_variant_) \
    bool trace;                         \
    bool nf_trace;                      \
    bool packet_dumped;                 \
    enum nft_trace_types type : 8;      \
    u32 skbid;                          \
    const struct nft_base_chain##_variant_ *basechain
#endif
#endif

enum nft_chain_types
{
    NFT_CHAIN_T_DEFAULT = 0,
    NFT_CHAIN_T_ROUTE,
    NFT_CHAIN_T_NAT,
    NFT_CHAIN_T_MAX
};

#define NFT_MAX_HOOKS (NF_INET_INGRESS + 1)

#define CORE_ATTRS __attribute__((preserve_access_index))

#define DECLARE(_name_, _field_, _attr_) \
    _name_ { _field_; }                  \
    _attr_

#define NFT_RULE_VARIANT(_variant_) struct nft_rule##_variant_
#define NFT_RULE_NOCORE_TYPE NFT_RULE_VARIANT(_nocore)
#define NFT_RULE_TYPE NFT_RULE_VARIANT()

#define NFT_RULE_DP_VARIANT(_variant_) struct nft_rule_dp##_variant_
#define NFT_RULE_DP_NOCORE_TYPE NFT_RULE_DP_VARIANT(_nocore)
#define NFT_RULE_DP_TYPE NFT_RULE_DP_VARIANT()

#define NFT_RULE_DP_LAST_VARIANT(_variant_) struct nft_rule_dp_last##_variant_
#define NFT_RULE_DP_LAST_TYPE NFT_RULE_DP_LAST_VARIANT()
#define NFT_RULE_DP_LAST_NOCORE_TYPE NFT_RULE_DP_LAST_VARIANT(_nocore)

#define NFT_TABLE_VARIANT(_variant_) struct nft_table##_variant_
#define NFT_TABLE_NOCORE_TYPE NFT_TABLE_VARIANT(_nocore)
#define NFT_TABLE_TYPE NFT_TABLE_VARIANT()

#define NFT_CHAIN_VARIANT(_variant_) struct nft_chain##_variant_
#define NFT_CHAIN_NOCORE_TYPE NFT_CHAIN_VARIANT(_nocore)
#define NFT_CHAIN_TYPE NFT_CHAIN_VARIANT()

#define NFT_VERDICT_VARIANT(_variant_) struct nft_verdict##_variant_
#define NFT_VERDICT_NOCORE_TYPE NFT_VERDICT_VARIANT(_nocore)
#define NFT_VERDICT_TYPE NFT_VERDICT_VARIANT()

#define XT_ACTION_PARAM_VARIANT(_variant_) struct xt_action_param##_variant_
#define XT_ACTION_PARAM_NOCORE_TYPE XT_ACTION_PARAM_VARIANT(_nocore)
#define XT_ACTION_PARAM_TYPE XT_ACTION_PARAM_VARIANT()

#define NFT_PKTINFO_VARIANT(_variant_) struct nft_pktinfo##_variant_
#define NFT_PKTINFO_NOCORE_TYPE NFT_PKTINFO_VARIANT(_nocore)
#define NFT_PKTINFO_TYPE NFT_PKTINFO_VARIANT()

#define NFT_CHAIN_TYPE_VARIANT(_variant_) struct nft_chain_type##_variant_
#define NFT_CHAIN_TYPE_NOCORE_TYPE NFT_CHAIN_TYPE_VARIANT(_nocore)
#define NFT_CHAIN_TYPE_TYPE NFT_CHAIN_TYPE_VARIANT()

#define NFT_BASE_CHAIN_VARIANT(_variant_) struct nft_base_chain##_variant_
#define NFT_BASE_CHAIN_NOCORE_TYPE NFT_BASE_CHAIN_VARIANT(_nocore)
#define NFT_BASE_CHAIN_TYPE NFT_BASE_CHAIN_VARIANT()

#define NFT_TRACEINFO_VARIANT(_variant_) struct nft_traceinfo##_variant_
#define NFT_TRACEINFO_NOCORE_TYPE NFT_TRACEINFO_VARIANT(_nocore)
#define NFT_TRACEINFO_TYPE NFT_TRACEINFO_VARIANT()

#define DECLARE_NFT_RULE_NOCORE DECLARE(NFT_RULE_NOCORE_TYPE, NFT_RULE_FIELDS, )
#define DECLARE_NFT_RULE DECLARE(NFT_RULE_TYPE, NFT_RULE_FIELDS, CORE_ATTRS)

#define DECLARE_NFT_RULE_DP_NOCORE DECLARE(NFT_RULE_DP_NOCORE_TYPE, NFT_RULE_DP_FIELDS, )
#define DECLARE_NFT_RULE_DP DECLARE(NFT_RULE_DP_TYPE, NFT_RULE_DP_FIELDS, CORE_ATTRS)

#define DECLARE_NFT_RULE_DP_LAST_NOCORE DECLARE(NFT_RULE_DP_LAST_NOCORE_TYPE, NFT_RULE_DP_LAST_FIELDS(_nocore), )
#define DECLARE_NFT_RULE_DP_LAST DECLARE(NFT_RULE_DP_LAST_TYPE, NFT_RULE_DP_LAST_FIELDS(), CORE_ATTRS)

#define DECLARE_NFT_TABLE_NOCORE DECLARE(NFT_TABLE_NOCORE_TYPE, NFT_TABLE_FIELDS, )
#define DECLARE_NFT_TABLE DECLARE(NFT_TABLE_TYPE, NFT_TABLE_FIELDS, CORE_ATTRS)

#define DECLARE_NFT_CHAIN_NOCORE DECLARE(NFT_CHAIN_NOCORE_TYPE, NFT_CHAIN_FIELDS(_nocore), )
#define DECLARE_NFT_CHAIN DECLARE(NFT_CHAIN_TYPE, NFT_CHAIN_FIELDS(), CORE_ATTRS)

#define DECLARE_NFT_VERDICT_NOCORE DECLARE(NFT_VERDICT_NOCORE_TYPE, NFT_VERDICT_FIELDS(_nocore), )
#define DECLARE_NFT_VERDICT DECLARE(NFT_VERDICT_TYPE, NFT_VERDICT_FIELDS(), CORE_ATTRS)

#define DECLARE_XT_ACTION_PARAM_NOCORE DECLARE(XT_ACTION_PARAM_NOCORE_TYPE, XT_ACTION_PARAM_FIELDS, )
#define DECLARE_XT_ACTION_PARAM DECLARE(XT_ACTION_PARAM_TYPE, XT_ACTION_PARAM_FIELDS, CORE_ATTRS)

#define DECLARE_NFT_PKTINFO_NOCORE DECLARE(NFT_PKTINFO_NOCORE_TYPE, NFT_PKTINFO_FIELDS(_nocore), )
#define DECLARE_NFT_PKTINFO DECLARE(NFT_PKTINFO_TYPE, NFT_PKTINFO_FIELDS(), CORE_ATTRS)

#define DECLARE_NFT_CHAIN_TYPE_NOCORE DECLARE(NFT_CHAIN_TYPE_NOCORE_TYPE, NFT_CHAIN_TYPE_FIELDS, )
#define DECLARE_NFT_CHAIN_TYPE DECLARE(NFT_CHAIN_TYPE_TYPE, NFT_CHAIN_TYPE_FIELDS, CORE_ATTRS)

#define DECLARE_NFT_BASE_CHAIN_NOCORE DECLARE(NFT_BASE_CHAIN_NOCORE_TYPE, NFT_BASE_CHAIN_FIELDS(_nocore), )
#define DECLARE_NFT_BASE_CHAIN DECLARE(NFT_BASE_CHAIN_TYPE, NFT_BASE_CHAIN_FIELDS(), CORE_ATTRS)

#define DECLARE_NFT_TRACEINFO_NOCORE DECLARE(NFT_TRACEINFO_NOCORE_TYPE, NFT_TRACEINFO_FIELDS(_nocore), )
#define DECLARE_NFT_TRACEINFO DECLARE(NFT_TRACEINFO_TYPE, NFT_TRACEINFO_FIELDS(), CORE_ATTRS)

DECLARE_NFT_RULE_NOCORE;
DECLARE_NFT_RULE;

DECLARE_NFT_RULE_DP_NOCORE;
DECLARE_NFT_RULE_DP;

DECLARE_NFT_RULE_DP_LAST_NOCORE;
DECLARE_NFT_RULE_DP_LAST;

DECLARE_NFT_TABLE_NOCORE;
DECLARE_NFT_TABLE;

DECLARE_NFT_CHAIN_NOCORE;
DECLARE_NFT_CHAIN;

DECLARE_NFT_VERDICT_NOCORE;
DECLARE_NFT_VERDICT;

DECLARE_XT_ACTION_PARAM_NOCORE;
DECLARE_XT_ACTION_PARAM;

DECLARE_NFT_PKTINFO_NOCORE;
DECLARE_NFT_PKTINFO;

DECLARE_NFT_CHAIN_TYPE_NOCORE;
DECLARE_NFT_CHAIN_TYPE;

DECLARE_NFT_BASE_CHAIN_NOCORE;
DECLARE_NFT_BASE_CHAIN;

DECLARE_NFT_TRACEINFO_NOCORE;
DECLARE_NFT_TRACEINFO;

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