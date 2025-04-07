#ifndef _MAP_DEFS_H_
#define _MAP_DEFS_H_

#include "bits_bpf.h"

extern int LINUX_KERNEL_VERSION __kconfig __weak;

#undef __inline
#define __inline inline __attribute__((__always_inline__))

// BPF结构类型
#define BPF_CY_MAP(NAME, TYPE, CAPACITY, KEY_TYPE, VALUE_TYPE) \
	struct {                                           \
		__uint(type, BPF_MAP_TYPE_##TYPE);             \
		__uint(max_entries, (CAPACITY));               \
		__type(key, KEY_TYPE);                         \
		__type(value, VALUE_TYPE);                     \
	} NAME SEC(".maps");

#define BPF_CY_RINGBUF(NAME, CAPACIT)               \
	struct {                                        \
		__uint(type, BPF_MAP_TYPE_RINGBUF);         \
		__uint(max_entries, (CAPACIT));             \
	} NAME SEC(".maps");

#define BPF_CY_ARRAY(NAME, CAPACITY, KEY_TYPE, VALUE_TYPE) \
	BPF_CY_MAP(NAME, ARRAY, CAPACITY, KEY_TYPE, VALUE_TYPE);

#define BPF_CY_HASH(NAME, CAPACITY, KEY_TYPE, VALUE_TYPE) \
	BPF_CY_MAP(NAME, HASH, CAPACITY, KEY_TYPE, VALUE_TYPE);


#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries, _pin, _map_flags) \
    struct {                                                                         \
        __uint(type, _type);                                                         \
        __uint(max_entries, _max_entries);                                           \
        __uint(pinning, _pin);                                                       \
        __type(key, _key_type);                                                      \
        __type(value, _value_type);                                                  \
        __uint(map_flags, _map_flags);                                               \
    } _name SEC(".maps");

#define BPF_RINGBUF_MAP(name, max_entries)  \
    BPF_MAP(name, BPF_MAP_TYPE_RINGBUF, 0, 0, max_entries, 0, 0)

#define BPF_PERF_EVENT_ARRAY_MAP_PINNED(name, value_type, max_entries) \
    BPF_MAP(name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, u32, value_type, max_entries, 1, 0)

#define BPF_PERF_EVENT_ARRAY_MAP(name, value_type, max_entries) \
    BPF_MAP(name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, u32, value_type, max_entries, 0, 0)

#define BPF_ARRAY_MAP(name, value_type, max_entries) \
    BPF_MAP(name, BPF_MAP_TYPE_ARRAY, u32, value_type, max_entries, 0, 0)

#define BPF_HASH_MAP_PINNED(name, key_type, value_type, max_entries) \
    BPF_MAP(name, BPF_MAP_TYPE_HASH, key_type, value_type, max_entries, 1, 0)

#define BPF_HASH_MAP(name, key_type, value_type, max_entries) \
    BPF_MAP(name, BPF_MAP_TYPE_HASH, key_type, value_type, max_entries, 0, 0)

#define BPF_PROG_ARRAY(name, max_entries) \
    BPF_MAP(name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, max_entries, 0, 0)

#define BPF_LRU_MAP(name, key_type, value_type, max_entries) \
    BPF_MAP(name, BPF_MAP_TYPE_LRU_HASH, key_type, value_type, max_entries, 0, 0)

#define BPF_LRU_MAP_PINNED(name, key_type, value_type, max_entries) \
    BPF_MAP(name, BPF_MAP_TYPE_LRU_HASH, key_type, value_type, max_entries, 1, 0)

#define BPF_LRU_MAP_FLAGS(name, key_type, value_type, max_entries, map_flags) \
    BPF_MAP(name, BPF_MAP_TYPE_LRU_HASH, key_type, value_type, max_entries, 0, map_flags)

#define BPF_PERCPU_HASH_MAP(name, key_type, value_type, max_entries) \
    BPF_MAP(name, BPF_MAP_TYPE_PERCPU_HASH, key_type, value_type, max_entries, 0, 0)

#define BPF_PERCPU_ARRAY_MAP(name, value_type, max_entries) \
    BPF_MAP(name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, value_type, max_entries, 0, 0)

    
#define lookup_or_zero_init_key(map, key, into)                                                                        \
u64 zero = 0;                                                                                                      \
                                                                                                                   \
into = bpf_map_lookup_elem(map, key);                                                                              \
if (!into) {                                                                                                       \
    bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);                                                             \
    into = bpf_map_lookup_elem(map, key);                                                                          \
    if (!into) {                                                                                                   \
        return 0;                                                                                                  \
    }                                                                                                              \
}

#define increment_variant(map, key, increment, variant)                                                                \
u64 *count;                                                                                                        \
lookup_or_zero_init_key(map, key, count);                                                                          \
variant;                                                                                                           \
return *count;

static inline int increment_map(void *map, void *key, u64 increment)
{
    increment_variant(map, key, increment, __sync_fetch_and_add(count, increment));
}

static inline int increment_map_nosync(void *map, void *key, u64 increment)
{
    increment_variant(map, key, increment, *count += increment);
}

// Arrays are always preallocated, so this only fails if the key is missing
#define read_array_ptr(map, key, into)                                                                                 \
into = bpf_map_lookup_elem(map, key);                                                                              \
if (!into) {                                                                                                       \
    return 0;                                                                                                      \
}

#define _increment_histogram(map, key, increment, max_bucket, increment_fn)                                            \
if (key.bucket > max_bucket) {                                                                                     \
    key.bucket = max_bucket;                                                                                       \
}                                                                                                                  \
                                                                                                                   \
increment_fn(map, &key, 1);                                                                                        \
                                                                                                                   \
if (increment > 0) {                                                                                               \
    key.bucket = max_bucket + 1;                                                                                   \
    increment_fn(map, &key, increment);                                                                            \
}

#define _increment_ex2_histogram(map, key, increment, max_bucket, increment_fn)                                        \
key.bucket = log2l(increment);                                                                                     \
                                                                                                                   \
if (key.bucket > max_bucket) {                                                                                     \
    key.bucket = max_bucket;                                                                                       \
}                                                                                                                  \
                                                                                                                   \
_increment_histogram(map, key, increment, max_bucket, increment_fn);

#define increment_exp2_histogram(map, key, increment, max_bucket)                                                      \
_increment_ex2_histogram(map, key, increment, max_bucket, increment_map)

#define increment_exp2_histogram_nosync(map, key, increment, max_bucket)                                               \
_increment_ex2_histogram(map, key, increment, max_bucket, increment_map_nosync)

#define _increment_exp2zero_histogram(map, key, increment, max_bucket, increment_fn)                                   \
if (increment == 0) {                                                                                              \
    key.bucket = 0;                                                                                                \
} else {                                                                                                           \
    key.bucket = log2l(increment) + 1;                                                                             \
}                                                                                                                  \
                                                                                                                   \
_increment_histogram(map, key, increment, max_bucket, increment_fn);

#define increment_exp2zero_histogram(map, key, increment, max_bucket)                                                  \
_increment_exp2zero_histogram(map, key, increment, max_bucket, increment_map)

#define increment_exp2zero_histogram_nosync(map, key, increment, max_bucket)                                           \
_increment_exp2zero_histogram(map, key, increment, max_bucket, increment_map_nosync)


#endif
