#ifndef __FILL_TRACE_H__
#define __FILL_TRACE_H__

#include "hash.h"
#include "nftrace.h"

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
        const struct ip4_tuple tuple = {
            .src_port = trace->src_port,
            .dst_port = trace->dst_port,
            .src_ip = trace->src_ip,
            .dst_ip = trace->dst_ip,
            .ip_proto = trace->family,
        };
        // bpf_printk("tuple_hash: %x, trace_id: %x, skb_hash: %x", hash_from_tuple_v4(&tuple), get_trace_id(skb), BPF_CORE_READ(skb, hash));
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

static __always_inline enum nft_trace_types get_trace_type(struct nft_traceinfo *info)
{
    return BPF_CORE_READ_BITFIELD_PROBED(info, type);
}

static __always_inline void fill_trace(
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
    trace->id = BPF_CORE_READ(pkt, skb, hash); // get_trace_id(BPF_CORE_READ(pkt, skb));
    trace->type = get_trace_type(info);
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
    fill_trace_pkt_info(trace, BPF_CORE_READ(pkt, skb));
    __sync_fetch_and_add(&trace->counter, 1);
}

#endif