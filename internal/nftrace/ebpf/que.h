#ifndef __QUE_H__
#define __QUE_H__

#ifndef MAX_CPU
#define MAX_CPU 128UL
#endif

#ifndef QUE_SIZE
#define QUE_SIZE 100000UL
#endif

struct que_data
{
    u32 hash;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 128);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    //__uint(map_flags, BPF_F_NO_PREALLOC);
} per_cpu_que SEC(".maps");

#endif