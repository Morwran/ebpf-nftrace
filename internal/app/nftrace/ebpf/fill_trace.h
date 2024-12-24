#ifndef __FILL_TRACE_H__
#define __FILL_TRACE_H__

#include "hash.h"
#include "nftrace.h"

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

static inline void fill_trace(
    struct trace_info *trace,
    const struct nft_pktinfo *pkt,
    const struct nft_verdict *verdict,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    const struct nft_rule *rule,
#else
    const struct nft_rule_dp *rule,
#endif
    struct nft_traceinfo *info)
{
    trace->id = trace_fill_id(BPF_CORE_READ(pkt, skb));
    trace->type = BPF_CORE_READ_BITFIELD_PROBED(info, type);
    trace->family = BPF_CORE_READ(info, basechain, type, family);
    bpf_probe_read_kernel_str(trace->table_name, sizeof(trace->table_name), BPF_CORE_READ(info, basechain, chain.table, name));
    trace->table_handle = BPF_CORE_READ(info, basechain, chain.table, handle);
    bpf_probe_read_kernel_str(trace->chain_name, sizeof(trace->chain_name), BPF_CORE_READ(info, basechain, chain.name));
    trace->chain_handle = BPF_CORE_READ(info, basechain, chain.handle);
    trace->rule_handle = BPF_CORE_READ_BITFIELD_PROBED(rule, handle);
    trace->nfproto = BPF_CORE_READ(pkt, state, pf);
    trace->verdict = BPF_CORE_READ(verdict, code);
    bpf_probe_read_kernel_str(trace->jump_target, sizeof(trace->jump_target), BPF_CORE_READ(verdict, chain, name));
    trace->policy = BPF_CORE_READ(info, basechain, policy);
    trace->mark = BPF_CORE_READ(pkt, skb, mark);
    trace->iif = BPF_CORE_READ(pkt, state, in, ifindex);
    trace->iif_type = BPF_CORE_READ(pkt, state, in, type);
    bpf_probe_read_kernel_str(trace->iif_name, sizeof(trace->iif_name), BPF_CORE_READ(pkt, state, in, name));
    trace->oif = BPF_CORE_READ(pkt, state, out, ifindex);
    trace->oif_type = BPF_CORE_READ(pkt, state, out, type);
    bpf_probe_read_kernel_str(trace->oif_name, sizeof(trace->oif_name), BPF_CORE_READ(pkt, state, out, name));
}

#endif