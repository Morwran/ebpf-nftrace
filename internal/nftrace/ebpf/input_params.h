#ifndef __INPUT_PARAMS_H__
#define __INPUT_PARAMS_H__

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
} use_aggregation SEC(".maps");

static __always_inline bool is_aggregation_enabled()
{
    u32 key = 0;
    u64 *val = bpf_map_lookup_elem(&use_aggregation, &key);
    return val && *val > 0;
}

static __always_inline u64 get_sample_rate()
{
    u32 key = 0;
    u64 *val = bpf_map_lookup_elem(&sample_rate, &key);
    if (!val)
    {
        return 0;
    }
    return *val;
}

static __always_inline bool is_sampling_enabled()
{
    return get_sample_rate() > 0;
}

#endif