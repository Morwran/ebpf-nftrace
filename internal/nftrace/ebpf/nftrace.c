// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <linux/netfilter/nf_tables.h>

#include "hash.h"
#include "fill_trace.h"
#include "counters.h"
#include "que.h"
#include "input_params.h"

const struct trace_info *unused __attribute__((unused));

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_KEYS 1000

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200000);
    __type(key, u32);
    __type(value, struct trace_info);
    //__uint(map_flags, BPF_F_NO_PREALLOC);
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
            bpf_printk("perf_event not found trace for cpu=%d and hash=%x", cpu_id, trace_que_data.hash);
            continue;
        }
        RD_TRACE_ADD_COUNT(value->counter);
        bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, value, sizeof(*value));
        bpf_map_delete_elem(&traces_per_cpu, &trace_que_data.hash);
    }

    return 0;
}

SEC("kprobe/nft_trace_notify")
int kprobe_nft_trace_notify(struct pt_regs *ctx)
{
    u32 sample_cnt = 0;

    struct trace_info trace = {};

    FILL_TRACE(&trace, ctx);

    u64 sample_rate_val = get_sample_rate();

    bool is_rule = (trace.type == NFT_TRACETYPE_RULE);

    if ((is_sampling_enabled() || is_aggregation_enabled()) && !is_rule)
    {
        return 0;
    }

    if (is_rule)
    {
        sample_cnt = TRACE_COUNT();
    }

    if (is_sampling_enabled() && (sample_cnt % sample_rate_val != 0))
    {
        return 0;
    }

    if (!is_aggregation_enabled())
    {
        bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &trace, sizeof(trace));
        return 0;
    }

    u32 cpu_id = bpf_get_smp_processor_id();
    u32 per_cpu_trace_hash = jhash_1word(trace.trace_hash, cpu_id);

    struct trace_info *old_trace = (struct trace_info *)bpf_map_lookup_elem(&traces_per_cpu, &per_cpu_trace_hash);
    if (!old_trace)
    {
        struct que_data trace_que_data = {
            .hash = per_cpu_trace_hash,
        };
        trace.time = bpf_ktime_get_ns();

        void *active_que = bpf_map_lookup_elem(&per_cpu_que, &cpu_id);
        if (!active_que)
        {
            bpf_printk("kprobe not found que for cpu=%d", cpu_id);
            bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &trace, sizeof(trace));
            WR_TRACE_ADD_COUNT(1);
            WR_WAIT_COUNT();
            return 0;
        }
        if (bpf_map_update_elem(&traces_per_cpu, &per_cpu_trace_hash, &trace, BPF_NOEXIST) != 0)
        {
            bpf_printk("kprobe failed to upd trace for cpu=%d", cpu_id);
            bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &trace, sizeof(trace));
            WR_TRACE_ADD_COUNT(1);
            WR_WAIT_COUNT();
            return 0;
        }
        if (bpf_map_push_elem(active_que, &trace_que_data, BPF_ANY) != 0)
        {
            bpf_printk("kprobe failed to push trace into que for cpu=%d", cpu_id);
            bpf_perf_event_output(ctx, &trace_events, BPF_F_CURRENT_CPU, &trace, sizeof(trace));
            WR_TRACE_ADD_COUNT(1);
            WR_WAIT_COUNT();
            return 0;
        }
        WR_TRACE_ADD_COUNT(1);
        return 0;
    }
    WR_TRACE_ADD_COUNT(1);
    __sync_fetch_and_add(&old_trace->counter, 1);

    return 0;
}