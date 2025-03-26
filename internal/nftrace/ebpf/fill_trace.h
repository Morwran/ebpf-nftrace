#ifndef __FILL_TRACE_H__
#define __FILL_TRACE_H__

#include "hash.h"
#include "nftrace.h"

#define IS_NFT_CORE_ENABLED bpf_core_type_exists(struct nft_traceinfo)

#define BPF_READ_NFT(src, a, ...)                               \
    ({                                                          \
        ___type((src), a, ##__VA_ARGS__) __r;                   \
        if (!IS_NFT_CORE_ENABLED)                               \
        {                                                       \
            BPF_PROBE_READ_INTO(&__r, (src), a, ##__VA_ARGS__); \
        }                                                       \
        else                                                    \
        {                                                       \
            BPF_CORE_READ_INTO(&__r, (src), a, ##__VA_ARGS__);  \
        }                                                       \
        __r;                                                    \
    })

static __always_inline int skb_mac_header_was_set(const struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, mac_header) != (typeof(BPF_CORE_READ(skb, mac_header)))~0U;
}

static __always_inline unsigned char *skb_mac_header(const struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, mac_header);
}

static __always_inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header);
}

static __always_inline void fill_trace_pkt_info(
    struct trace_info *trace,
    const struct sk_buff *skb)
{
    void *head = BPF_CORE_READ(skb, head);
    void *end = head + BPF_CORE_READ(skb, end);
    if (!head || !end || head >= end)
        return;

    if (skb_mac_header_was_set(skb))
    {
        struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);
        if ((void *)eth + sizeof(*eth) > end)
            return;
        bpf_probe_read_kernel(trace->src_mac, sizeof(trace->src_mac), BPF_CORE_READ(eth, h_source));
        bpf_probe_read_kernel(trace->dst_mac, sizeof(trace->dst_mac), BPF_CORE_READ(eth, h_dest));
    }

    if (trace->family == NFPROTO_IPV4)
    {
        struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
        if ((void *)iph + sizeof(*iph) > end)
            return;

        trace->ip_proto = BPF_CORE_READ(iph, protocol);
        trace->src_ip = bpf_ntohl(BPF_CORE_READ(iph, saddr));
        trace->dst_ip = bpf_ntohl(BPF_CORE_READ(iph, daddr));
        trace->len = bpf_ntohs(BPF_CORE_READ(iph, tot_len));

        if (trace->ip_proto == IPPROTO_TCP)
        {
            struct tcphdr *tcph = (void *)((void *)iph + (BPF_CORE_READ_BITFIELD_PROBED(iph, ihl) * 4));
            if ((void *)tcph + sizeof(*tcph) > end)
                return;

            trace->src_port = bpf_ntohs(BPF_CORE_READ(tcph, source));
            trace->dst_port = bpf_ntohs(BPF_CORE_READ(tcph, dest));
        }
        else if (trace->ip_proto == IPPROTO_UDP)
        {
            struct udphdr *udph = (void *)((void *)iph + (BPF_CORE_READ_BITFIELD_PROBED(iph, ihl) * 4));
            if ((void *)udph + sizeof(*udph) > end)
                return;

            trace->src_port = bpf_ntohs(BPF_CORE_READ(udph, source));
            trace->dst_port = bpf_ntohs(BPF_CORE_READ(udph, dest));
        }
    }
    else if (trace->family == NFPROTO_IPV6)
    {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)skb_network_header(skb);
        if ((void *)ip6h + sizeof(*ip6h) > end)
            return;

        trace->ip_proto = BPF_CORE_READ(ip6h, nexthdr);
        trace->src_ip6 = BPF_CORE_READ(ip6h, saddr);
        trace->dst_ip6 = BPF_CORE_READ(ip6h, daddr);
        trace->len = bpf_ntohs(BPF_CORE_READ(ip6h, payload_len));

        if (trace->ip_proto == IPPROTO_TCP)
        {
            struct tcphdr *tcph = (void *)((void *)ip6h + sizeof(*ip6h));
            if ((void *)tcph + sizeof(*tcph) > end)
                return;

            trace->src_port = bpf_ntohs(BPF_CORE_READ(tcph, source));
            trace->dst_port = bpf_ntohs(BPF_CORE_READ(tcph, dest));
        }
        else if (trace->ip_proto == IPPROTO_UDP)
        {
            struct udphdr *udph = (void *)((void *)ip6h + sizeof(*ip6h));
            if ((void *)udph + sizeof(*udph) > end)
                return;

            trace->src_port = bpf_ntohs(BPF_CORE_READ(udph, source));
            trace->dst_port = bpf_ntohs(BPF_CORE_READ(udph, dest));
        }
    }
}

#define __fill_dev_info(trace, pkt)                                                                                      \
    ({                                                                                                                   \
        if (bpf_core_field_exists(((struct nft_pktinfo *)0)->state))                                                     \
        {                                                                                                                \
            trace->iif = BPF_CORE_READ(pkt, state, in, ifindex);                                                         \
            trace->iif_type = BPF_CORE_READ(pkt, state, in, type);                                                       \
            trace->oif = BPF_CORE_READ(pkt, state, out, ifindex);                                                        \
            trace->oif_type = BPF_CORE_READ(pkt, state, out, type);                                                      \
            bpf_probe_read_kernel_str(trace->iif_name, sizeof(trace->iif_name), BPF_CORE_READ(pkt, state, in, name));    \
            bpf_probe_read_kernel_str(trace->oif_name, sizeof(trace->oif_name), BPF_CORE_READ(pkt, state, out, name));   \
        }                                                                                                                \
        else                                                                                                             \
        {                                                                                                                \
            trace->iif = BPF_READ_NFT(pkt, xt.state, in, ifindex);                                                       \
            trace->iif_type = BPF_READ_NFT(pkt, xt.state, in, type);                                                     \
            trace->oif = BPF_READ_NFT(pkt, xt.state, out, ifindex);                                                      \
            trace->oif_type = BPF_READ_NFT(pkt, xt.state, out, type);                                                    \
            bpf_probe_read_kernel_str(trace->iif_name, sizeof(trace->iif_name), BPF_READ_NFT(pkt, xt.state, in, name));  \
            bpf_probe_read_kernel_str(trace->oif_name, sizeof(trace->oif_name), BPF_READ_NFT(pkt, xt.state, out, name)); \
        }                                                                                                                \
    })

static __always_inline u64 get_rule_handle(const void *rule_ptr)
{
    if (!rule_ptr)
        return 0;

    if (!IS_NFT_CORE_ENABLED)
    {
        u64 bit_mask = BPF_PROBE_READ((const NFT_RULE_NOCORE_TYPE *)rule_ptr, flags);
        return bit_mask & ((1ULL << 42) - 1);
    }

    if (bpf_core_type_exists(struct nft_rule_dp))
    {
        return BPF_CORE_READ_BITFIELD_PROBED(
            (const NFT_RULE_DP_TYPE *)rule_ptr, handle);
    }
    else if (bpf_core_type_exists(struct nft_rule))
    {
        return BPF_CORE_READ_BITFIELD_PROBED(
            (const NFT_RULE_TYPE *)rule_ptr, handle);
    }

    return 0;
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

static __always_inline enum nft_trace_types get_trace_type(void *info)
{
    if (!IS_NFT_CORE_ENABLED)
    {
        return BPF_PROBE_READ((NFT_TRACEINFO_NOCORE_TYPE *)info, type);
    }

    return BPF_CORE_READ_BITFIELD_PROBED((NFT_TRACEINFO_TYPE *)info, type);
}

static __always_inline const NFT_RULE_DP_TYPE *nft_rule_next(const NFT_RULE_DP_TYPE *rule)
{
    return (void *)rule + sizeof(*rule) + BPF_CORE_READ_BITFIELD_PROBED(rule, dlen);
}

static __always_inline void fill_chain_info(struct trace_info *trace, void *info, const void *rule)
{
    if (!IS_NFT_CORE_ENABLED)
    {
        bpf_probe_read_kernel_str(trace->chain_name, sizeof(trace->chain_name), BPF_PROBE_READ((NFT_TRACEINFO_NOCORE_TYPE *)info, chain, name));
        trace->chain_handle = BPF_READ_NFT((NFT_TRACEINFO_NOCORE_TYPE *)info, chain, handle);
        return;
    }
    if (bpf_core_field_exists(((struct nft_traceinfo *)0)->chain))
    {
        bpf_probe_read_kernel_str(trace->chain_name, sizeof(trace->chain_name), BPF_CORE_READ((NFT_TRACEINFO_TYPE *)info, chain, name));
        trace->chain_handle = BPF_CORE_READ((NFT_TRACEINFO_TYPE *)info, chain, handle);
        return;
    }
    if (!bpf_core_type_exists(struct nft_rule_dp))
    {
        return;
    }
    if (!rule)
    {
        bpf_probe_read_kernel_str(trace->chain_name, sizeof(trace->chain_name), BPF_CORE_READ((NFT_TRACEINFO_TYPE *)info, basechain, chain.name));
        trace->chain_handle = BPF_CORE_READ((NFT_TRACEINFO_TYPE *)info, basechain, chain.handle);
        return;
    }
    const NFT_RULE_DP_TYPE *rl = (const NFT_RULE_DP_TYPE *)rule;
#pragma unroll
    for (int i = 0; i < 500; i++)
    {
        if (BPF_CORE_READ_BITFIELD_PROBED(rl, is_last))
        {
            break;
        }
        rl = nft_rule_next(rl);
    }
    if (!BPF_CORE_READ_BITFIELD_PROBED(rl, is_last))
    {
        return;
    }
    const NFT_RULE_DP_LAST_TYPE *last = (const NFT_RULE_DP_LAST_TYPE *)rl;
    bpf_probe_read_kernel_str(trace->chain_name, sizeof(trace->chain_name), BPF_CORE_READ(last, chain, name));
    trace->chain_handle = BPF_CORE_READ(last, chain, handle);
}

static __always_inline u8 get_nfproto(const void *pkt)
{
    if (!IS_NFT_CORE_ENABLED)
    {
        return BPF_PROBE_READ((const NFT_PKTINFO_NOCORE_TYPE *)pkt, xt.state, pf);
    }
    if (bpf_core_field_exists(((struct nft_pktinfo *)0)->state))
    {
        return BPF_CORE_READ((const NFT_PKTINFO_TYPE *)pkt, state, pf);
    }
    return BPF_CORE_READ((const NFT_PKTINFO_TYPE *)pkt, xt.state, pf);
}

#define __fill_verdict_info(trace, verdict)                                                                                \
    ({                                                                                                                     \
        trace->verdict = BPF_READ_NFT(verdict, code);                                                                      \
        if (trace->type == NFT_TRACETYPE_RULE &&                                                                           \
            (trace->verdict == NFT_JUMP || trace->verdict == NFT_GOTO))                                                    \
        {                                                                                                                  \
            bpf_probe_read_kernel_str(trace->jump_target, sizeof(trace->jump_target), BPF_READ_NFT(verdict, chain, name)); \
        }                                                                                                                  \
    })

#define FILL_TRACE(trace, ctx)                                             \
    ({                                                                     \
        struct trace_info *__trace = (struct trace_info *)(trace);         \
        if (!IS_NFT_CORE_ENABLED)                                          \
        {                                                                  \
            NFT_TRACEINFO_NOCORE_TYPE *info = (void *)PT_REGS_PARM1(ctx);  \
            typeof(info->pkt) pkt = BPF_PROBE_READ(info, pkt);             \
            typeof(info->verdict) verdict = BPF_PROBE_READ(info, verdict); \
            typeof(info->rule) rule = BPF_PROBE_READ(info, rule);          \
            __fill_trace(__trace, pkt, verdict, rule, info);               \
        }                                                                  \
        else if (bpf_core_field_exists(((struct nft_traceinfo *)0)->pkt))  \
        {                                                                  \
            NFT_TRACEINFO_TYPE *info = (void *)PT_REGS_PARM1(ctx);         \
            typeof(info->pkt) pkt = BPF_CORE_READ(info, pkt);              \
            typeof(info->verdict) verdict = BPF_CORE_READ(info, verdict);  \
            typeof(info->rule) rule = BPF_CORE_READ(info, rule);           \
            __fill_trace(__trace, pkt, verdict, rule, info);               \
        }                                                                  \
        else                                                               \
        {                                                                  \
            NFT_PKTINFO_TYPE *pkt = (void *)PT_REGS_PARM1(ctx);            \
            NFT_VERDICT_TYPE *verdict = (void *)PT_REGS_PARM2(ctx);        \
            NFT_RULE_DP_TYPE *rule = (void *)PT_REGS_PARM3(ctx);           \
            NFT_TRACEINFO_TYPE *info = (void *)PT_REGS_PARM4(ctx);         \
            __fill_trace(__trace, pkt, verdict, rule, info);               \
        }                                                                  \
    })

#define __fill_trace(trace, pkt, verdict, rule, info)                                                                              \
    ({                                                                                                                             \
        struct sk_buff *skb = (struct sk_buff *)BPF_READ_NFT(pkt, skb);                                                            \
        trace->id = get_trace_id(skb);                                                                                             \
        trace->type = get_trace_type(info);                                                                                        \
        trace->family = BPF_READ_NFT(info, basechain, type, family);                                                               \
        bpf_probe_read_kernel_str(trace->table_name, sizeof(trace->table_name), BPF_READ_NFT(info, basechain, chain.table, name)); \
        trace->table_handle = BPF_READ_NFT(info, basechain, chain.table, handle);                                                  \
        fill_chain_info(trace, info, rule);                                                                                        \
        trace->rule_handle = get_rule_handle(rule);                                                                                \
        trace->nfproto = get_nfproto(pkt);                                                                                         \
        trace->verdict = BPF_READ_NFT(verdict, code);                                                                              \
        __fill_verdict_info(trace, verdict);                                                                                       \
        trace->policy = BPF_READ_NFT(info, basechain, policy);                                                                     \
        trace->mark = BPF_READ_NFT(pkt, skb, mark);                                                                                \
        __fill_dev_info(trace, pkt);                                                                                               \
        fill_trace_pkt_info(trace, skb);                                                                                           \
        trace->trace_hash = get_trace_hash(trace, skb);                                                                            \
        __sync_fetch_and_add(&trace->counter, 1);                                                                                  \
    })

#endif