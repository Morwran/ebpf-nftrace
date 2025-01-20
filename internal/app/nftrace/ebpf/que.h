#ifndef __QUE_H__
#define __QUE_H__

#ifndef MAX_CPU
#define MAX_CPU 128UL
#endif

#ifndef QUE_SIZE
#define QUE_SIZE 100000UL
#endif

// static u64 wr_indexes SEC(".bss");
// static u64 rd_indexes SEC(".bss");
// static u64 wr_rd_index SEC(".bss");

struct que_data
{
    u32 hash;
    // u32 cpu_id;
    // u32 map_id;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 128);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    //__uint(map_flags, BPF_F_NO_PREALLOC);
} per_cpu_que SEC(".maps");

// struct
// {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, QUE_SIZE);
//     __type(key, u32);
//     __type(value, struct que_data);
// } que_ring SEC(".maps");

// static __always_inline u32 get_wr_index(u64 val)
// {
//     return val >> 32;
// }

// static __always_inline u32 get_rd_index(u64 val)
// {
//     return (u32)(val & 0xffffffff);
// }

// static __always_inline u64 make_indexes(u32 wr, u32 rd)
// {
//     return ((u64)wr << 32) | (u64)rd;
// }

// static __always_inline int enque(int retry, struct que_data *data)
// {

// #pragma unroll
//     for (int i = 0; i < MAX_CPU; i++)
//     {
//         if (i >= retry)
//         {
//             return -1;
//         }
//         u64 old_val = __sync_fetch_and_add(&wr_rd_index, 0);
//         u32 old_wr = get_wr_index(old_val);
//         u32 old_rd = get_rd_index(old_val);

//         if ((u32)(old_wr - old_rd) >= QUE_SIZE)
//         {
//             return -1;
//         }

//         u64 new_val = make_indexes(old_wr + 1, old_rd);
//         u64 res = __sync_val_compare_and_swap(&wr_rd_index, old_val, new_val);

//         if (res == old_val)
//         {
//             u32 ring_index = old_wr % QUE_SIZE;
//             return bpf_map_update_elem(&que_ring, &ring_index, data, BPF_ANY);
//         }
//     }

//     return -1;
// }

// static __always_inline void *que_top()
// {
//     u64 rd_wr_id = __sync_fetch_and_add(&wr_rd_index, 0);
//     u32 wr_id = get_wr_index(rd_wr_id) % QUE_SIZE;
//     u32 rd_id = get_rd_index(rd_wr_id) % QUE_SIZE;
//     if (wr_id == rd_id)
//     {
//         return NULL;
//     }
//     return bpf_map_lookup_elem(&que_ring, &rd_id);
// }

// static __always_inline void *deque(int retry)
// {
// #pragma unroll
//     for (int i = 0; i < MAX_CPU; i++)
//     {
//         if (i >= retry)
//         {
//             return NULL;
//         }

//         u64 old_val = __sync_fetch_and_add(&wr_rd_index, 0);
//         u32 old_wr = get_wr_index(old_val);
//         u32 old_rd = get_rd_index(old_val);

//         if (old_wr == old_rd)
//         {
//             return NULL;
//         }

//         u32 ring_index = old_rd % QUE_SIZE;
//         struct que_data *val = (struct que_data *)bpf_map_lookup_elem(&que_ring, &ring_index);
//         if (!val)
//         {
//             return NULL;
//         }

//         u64 new_val = make_indexes(old_wr, old_rd + 1);

//         u64 res = __sync_val_compare_and_swap(&wr_rd_index, old_val, new_val);

//         if (res == old_val)
//         {
//             return val;
//         }
//     }

//     return NULL;
// }

#endif