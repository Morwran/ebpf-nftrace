#ifndef __COUNTERS_H__
#define __COUNTERS_H__

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} pkt_counter SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} wr_wait_counter SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} rd_wait_counter SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} wr_trace_counter SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} rd_trace_counter SEC(".maps");

static __always_inline u64 upd_counter_in_map(void *map, u64 add_val)
{
    u32 key = 0;
    u64 *val, init_val = 1;

    val = bpf_map_lookup_elem(map, &key);
    if (val)
    {
        return __sync_fetch_and_add(val, add_val);
    }

    bpf_map_update_elem(map, &key, &init_val, BPF_NOEXIST);

    return init_val;
}

#define PKT_COUNTER_INC() upd_counter_in_map(&pkt_counter, 1)

#define WR_WAIT_COUNT() upd_counter_in_map(&wr_wait_counter, 1)

#define RD_WAIT_COUNT() upd_counter_in_map(&rd_wait_counter, 1)

#define WR_TRACE_ADD_COUNT(__val__) upd_counter_in_map(&wr_trace_counter, __val__)

#define RD_TRACE_ADD_COUNT(__val__) upd_counter_in_map(&rd_trace_counter, __val__)

#endif