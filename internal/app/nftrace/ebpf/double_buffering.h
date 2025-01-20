#ifndef __DOUBLE_BUFFERING_H__
#define __DOUBLE_BUFFERING_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// struct
// {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, u32);
//     __type(value, u64);
// } select_map SEC(".maps");

// struct
// {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 100000);
//     __type(key, u32);
//     __type(value, struct trace_info);
// } trace_holder SEC(".maps");

// struct
// {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 100000);
//     __type(key, u32);
//     __type(value, struct trace_info);
// } trace_holder2 SEC(".maps");

// static __always_inline u8 get_active_map_num()
// {
//     u32 key = 0;
//     u64 *val, init_val = 0;

//     val = (u64 *)bpf_map_lookup_elem(&select_map, &key);
//     if (!val)
//     {
//         bpf_map_update_elem(&select_map, &key, &init_val, BPF_NOEXIST);
//         return init_val;
//     }

//     return __sync_fetch_and_add(val, 0) % 2;
// }

// static __always_inline int change_active_map_num()
// {
//     u32 key = 0;
//     u64 *val;

//     val = (u64 *)bpf_map_lookup_elem(&select_map, &key);
//     if (val)
//     {
//         return __sync_fetch_and_add(val, 1) % 2;
//     }

//     return -1;
// }

// static __always_inline u8 get_active_map(void **map)
// {
//     u8 map_id = get_active_map_num();
//     *map = &trace_holder;
//     if (map_id == 1)
//     {
//         *map = &trace_holder2;
//     }
//     return map_id;
// }

#endif