// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <linux/netfilter/nf_tables.h>

#include "hash.h"
#include "fill_trace.h"
#include "spinlock.h"
#include "counters.h"
#include "que.h"
#include "double_buffering.h"

const struct trace_info *unused __attribute__((unused));

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_KEYS 1000

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
} time_interval SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 200000);
    __type(key, u32);
    __type(value, struct trace_info);
} traces_per_cpu SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 128); // number of CPUs
} trace_events SEC(".maps");

SEC("perf_event")
int send_agregated_trace(struct bpf_perf_event_data *ctx)
{
    struct que_data trace_que_data;
    struct trace_info *value;

    int i = 0;
    u32 cpu_id = bpf_get_smp_processor_id();
    void *active_que = bpf_map_lookup_elem(&per_cpu_que, &cpu_id);
    if (!active_que)
    {
        bpf_printk("perf_event not found que for cpu=%d", cpu_id);

        RD_WAIT_COUNT();
        return 0;
    }
    // bpf_printk("perf_event cpu=%d, period=%d", cpu_id, ctx->sample_period);

#pragma unroll
    for (; i < MAX_KEYS; i++)
    {
        if (bpf_map_pop_elem(active_que, &trace_que_data) != 0)
        {
            break;
        }
        value = bpf_map_lookup_elem(&traces_per_cpu, &trace_que_data.hash);
        if (!value)
        {
            continue;
        }
        bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, value, sizeof(*value));
        bpf_map_delete_elem(&traces_per_cpu, &trace_que_data.hash);
    }

    return 0;
}

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
    u32 sample_rate_key = 0, time_interval_key = 0;
    u64 *sample_rate_val;

    struct trace_info trace = {};

    if (get_trace_type(info) != NFT_TRACETYPE_RULE)
    {
        return 0;
    }

    u32 pkt_cnt = PKT_COUNTER_INC();

    sample_rate_val = bpf_map_lookup_elem(&sample_rate, &sample_rate_key);

    if (sample_rate_val)
    {
        u64 safe_sample_rate_val = __sync_fetch_and_add(sample_rate_val, 0);
        if (safe_sample_rate_val > 0)
        {
            if (pkt_cnt % safe_sample_rate_val)
            {
                return 0;
            }
        }
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
    fill_trace(&trace, BPF_CORE_READ(info, pkt), BPF_CORE_READ(info, verdict), BPF_CORE_READ(info, rule), info);
#else
    fill_trace(&trace, pkt, verdict, rule, info);
#endif

    if (!is_time_interval_set(bpf_map_lookup_elem(&time_interval, &time_interval_key)))
    {
        bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &trace, sizeof(trace));
        return 0;
    }
    u32 cpu_id = bpf_get_smp_processor_id();

    struct trace_info *old_trace = (struct trace_info *)bpf_map_lookup_elem(&traces_per_cpu, &trace.id);
    if (!old_trace)
    {
        struct que_data trace_que_data = {
            .hash = trace.id,
        };
        trace.time = bpf_ktime_get_ns();

        void *active_que = bpf_map_lookup_elem(&per_cpu_que, &cpu_id);
        if (!active_que)
        {
            bpf_printk("kprobe not found que for cpu=%d", cpu_id);
            bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &trace, sizeof(trace));

            WR_WAIT_COUNT();
            return 0;
        }
        if (bpf_map_update_elem(&traces_per_cpu, &trace.id, &trace, BPF_ANY) != 0)
        {
            bpf_printk("kprobe failed to upd trace for cpu=%d", cpu_id);
            bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &trace, sizeof(trace));

            WR_WAIT_COUNT();
            return 0;
        }
        if (bpf_map_push_elem(active_que, &trace, BPF_ANY) != 0)
        {
            bpf_printk("kprobe failed to push trace into que for cpu=%d", cpu_id);
            bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &trace, sizeof(trace));

            WR_WAIT_COUNT();
        }

        return 0;
    }
    __sync_fetch_and_add(&old_trace->counter, 1);

    return 0;
}