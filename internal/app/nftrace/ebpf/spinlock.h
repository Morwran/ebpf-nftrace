#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64); // Lock flag
} global_lock SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64); // Lock flag
} percpu_lock SEC(".maps");

static __always_inline int acquire_global_lock(int retry)
{
    u32 key = 0;
    u64 init_val = 0;
    u64 *lock_val = bpf_map_lookup_elem(&global_lock, &key);
    if (!lock_val)
    {
        bpf_map_update_elem(&global_lock, &key, &init_val, BPF_NOEXIST);
        lock_val = bpf_map_lookup_elem(&global_lock, &key);
        if (!lock_val)
        {
            return 0;
        }
    }

#pragma unroll
    for (int i = 0; i < 1000; i++)
    {
        if (i == retry)
        {
            break;
        }

        if (__sync_val_compare_and_swap(lock_val, 0, 1) == 0)
        {
            return 1;
        }
        asm volatile("" ::: "memory");
    }
    return 0;
}

static __always_inline void release_global_lock(void)
{
    u32 key = 0;
    u64 *lock_val = bpf_map_lookup_elem(&global_lock, &key);
    if (lock_val)
    {
        __sync_val_compare_and_swap(lock_val, 1, 0);
    }
}

static __always_inline int acquire_percpu_lock(int retry)
{
    u32 key = 0;
    u64 init_val = 0;
    u64 *lock_val = bpf_map_lookup_elem(&percpu_lock, &key);
    if (!lock_val)
    {
        bpf_map_update_elem(&percpu_lock, &key, &init_val, BPF_NOEXIST);
        lock_val = bpf_map_lookup_elem(&percpu_lock, &key);
        if (!lock_val)
        {
            return 0;
        }
    }

#pragma unroll
    for (int i = 0; i < 1000; i++)
    {
        if (i == retry)
        {
            break;
        }

        if (__sync_val_compare_and_swap(lock_val, 0, 1) == 0)
        {
            return 1;
        }
        asm volatile("" ::: "memory");
    }
    return 0;
}

static __always_inline void release_percpu_lock()
{
    u32 key = 0;
    u64 *lock_val = bpf_map_lookup_elem(&percpu_lock, &key);
    if (lock_val)
    {
        __sync_val_compare_and_swap(lock_val, 1, 0);
    }
}

#endif
