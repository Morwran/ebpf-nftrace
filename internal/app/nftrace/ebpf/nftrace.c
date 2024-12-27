// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <linux/netfilter/nf_tables.h>

#include "fill_trace.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 30);
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} sample_rate SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} trace_count SEC(".maps");

SEC("kprobe/nft_trace_notify")
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
int BPF_KPROBE(kprobe_nft_trace_notify, struct nft_traceinfo *info)
#else
int BPF_KPROBE(kprobe_nft_trace_notify, const struct nft_pktinfo *pkt,
               const struct nft_verdict *verdict,
               const struct nft_rule_dp *rule,
               struct nft_traceinfo *info)
#endif
{

    u32 sample_rate_key = 0, trace_count_key = 0;
    u64 *sample_rate_val, *trace_count_val, initval = 1;

    struct trace_info *trace;

    sample_rate_val = bpf_map_lookup_elem(&sample_rate, &sample_rate_key);

    if (sample_rate_val)
    {
        u64 safe_sample_rate_val = __sync_fetch_and_add(sample_rate_val, 0);
        if (safe_sample_rate_val > 0)
        {
            trace_count_val = bpf_map_lookup_elem(&trace_count, &trace_count_key);
            if (!trace_count_val)
            {
                bpf_map_update_elem(&trace_count, &trace_count_key, &initval, BPF_ANY);
                return 0;
            }

            if (__sync_fetch_and_add(trace_count_val, 1) % safe_sample_rate_val)
            {
                return 0;
            }
        }
    }

    trace = bpf_ringbuf_reserve(&events, sizeof(struct trace_info), 0);
    if (!trace)
    {
        return 0;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    fill_trace(trace, BPF_CORE_READ(info, pkt), BPF_CORE_READ(info, verdict), BPF_CORE_READ(info, rule), info);
#else
    fill_trace(trace, pkt, verdict, rule, info);
#endif
    if (trace->type == NFT_TRACETYPE_RULE)
    {
        bpf_ringbuf_submit(trace, 0);
    }

    return 0;
}