// SPDX-License-Identifier: GPL-2
//
// Copyright (C) 2021  William Findlay
//
// Jan. 19, 2021  William Findlay  Created this.

#ifndef HELPERS_H
#define HELPERS_H

// This must be first
#include "vmlinux.h"

// These must be below vmlinux.h
#include <bpf/bpf_helpers.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define __GFP_IO		0x40u
#define __GFP_FS		0x80u
#define ___GFP_DIRECT_RECLAIM	0x400u
#define ___GFP_KSWAPD_RECLAIM	0x800u
#define __GFP_RECLAIM (___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)

//#define __GFP_IO	((__force gfp_t)___GFP_IO)
//#define __GFP_FS	((__force gfp_t)___GFP_FS)
//#define __GFP_DIRECT_RECLAIM	((__force gfp_t)___GFP_DIRECT_RECLAIM) /* Caller can reclaim */
//#define __GFP_KSWAPD_RECLAIM	((__force gfp_t)___GFP_KSWAPD_RECLAIM) /* kswapd can wake */
//#define __GFP_RECLAIM ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))
//
//#ifndef GFP_KERNEL
//#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
//#endif
//

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)

#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))

static __always_inline u32 new_encode_dev(dev_t dev)
{
	unsigned major = MAJOR(dev);
	unsigned minor = MINOR(dev);
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}


#ifndef NULL
#define NULL 0
#endif

/* =========================================================================
 * General-Purpose Helpers
 * ========================================================================= */

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *val)
{
    void *res = bpf_map_lookup_elem(map, key);
    if (!res) {
        bpf_map_update_elem(map, key, val, BPF_NOEXIST);
    }
    return bpf_map_lookup_elem(map, key);
}

/* =========================================================================
 * Map Definition Helpers
 * ========================================================================= */

/* Declare a BPF ringbuf map @NAME with 2^(@PAGES) size */
#define BPF_RINGBUF(NAME, PAGES)                                               \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_RINGBUF);                                    \
        __uint(max_entries, ((1 << PAGES) * PAGE_SIZE));                       \
    } NAME SEC(".maps")

/* Declare a BPF perbuf map with name @NAME */
#define BPF_PERFBUF(NAME)                                                      \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);                           \
        __uint(key_size, sizeof(u32));                                         \
        __uint(value_size, sizeof(u32));                                       \
    } NAME SEC(".maps");

/* Declare a BPF hashmap @NAME with key type @KEY, value type @VALUE, and @SIZE
 * max entries. The map creation flags may be specified with @FLAGS. */
#define BPF_HASH(NAME, KEY, VALUE, SIZE, FLAGS)                                \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_HASH);                                       \
        __uint(max_entries, SIZE);                                             \
        __type(key, KEY);                                                      \
        __type(value, VALUE);                                                  \
        __uint(map_flags, FLAGS);                                              \
    } NAME SEC(".maps")

/* Declare an LRU BPF hashmap @NAME with key type @KEY, value type @VALUE, and
 * @SIZE max entries. The map creation flags may be specified with @FLAGS. */
#define BPF_LRU_HASH(NAME, KEY, VALUE, SIZE, FLAGS)                            \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_LRU_HASH);                                   \
        __uint(max_entries, SIZE);                                             \
        __type(key, KEY);                                                      \
        __type(value, VALUE);                                                  \
        __uint(map_flags, FLAGS);                                              \
    } NAME SEC(".maps")

/* Declare a per-cpu BPF hashmap @NAME with key type @KEY, value type @VALUE,
 * and
 * @SIZE max entries. The map creation flags may be specified with @FLAGS. */
#define BPF_PERCPU_HASH(NAME, KEY, VALUE, SIZE, FLAGS)                         \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_PERCPU_HASH);                                \
        __uint(max_entries, SIZE);                                             \
        __type(key, KEY);                                                      \
        __type(value, VALUE);                                                  \
        __uint(map_flags, FLAGS);                                              \
    } NAME SEC(".maps")

/* Declare a per-cpu LRU BPF hashmap @NAME with key type @KEY, value type
 * @VALUE, and @SIZE max entries. The map creation flags may be specified with
 * @FLAGS. */
#define BPF_LRU_PERCPU_HASH(NAME, KEY, VALUE, SIZE, FLAGS)                     \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);                            \
        __uint(max_entries, SIZE);                                             \
        __type(key, KEY);                                                      \
        __type(value, VALUE);                                                  \
        __uint(map_flags, FLAGS);                                              \
    } NAME SEC(".maps")

/* Declare a BPF array @NAME with value type @VALUE, and @SIZE max entries.
 * The map creation flags may be specified with @FLAGS. */
#define BPF_ARRAY(NAME, VALUE, SIZE, FLAGS)                                    \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_ARRAY);                                      \
        __uint(max_entries, SIZE);                                             \
        __type(key, unsigned int);                                             \
        __type(value, VALUE);                                                  \
        __uint(map_flags, FLAGS);                                              \
    } NAME SEC(".maps")

/* Declare a per-cpu BPF array @NAME with value type @VALUE, and @SIZE max
 * entries.  The map creation flags may be specified with @FLAGS. */
#define BPF_PERCPU_ARRAY(NAME, VALUE, SIZE, FLAGS)                             \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                               \
        __uint(max_entries, SIZE);                                             \
        __type(key, unsigned int);                                             \
        __type(value, VALUE);                                                  \
        __uint(map_flags, FLAGS);                                              \
    } NAME SEC(".maps")

/* Declare a BPF stack @NAME with value type @VALUE, and @SIZE max entries.
 * The map creation flags may be specified with @FLAGS. */
#define BPF_STACK(NAME, VALUE, SIZE, FLAGS)                                    \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_STACK);                                      \
        __uint(max_entries, SIZE);                                             \
        __uint(key_size, 0);                                                   \
        __uint(value_size, sizeof(VALUE));                                     \
        __uint(map_flags, FLAGS);                                              \
    } NAME SEC(".maps")

/* Declare a BPF queue @NAME with value type @VALUE, and @SIZE max entries.
 * The map creation flags may be specified with @FLAGS. */
#define BPF_QUEUE(NAME, VALUE, SIZE, FLAGS)                                    \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_QUEUE);                                      \
        __uint(max_entries, SIZE);                                             \
        __uint(key_size, 0);                                                   \
        __uint(value_size, sizeof(VALUE));                                     \
        __uint(map_flags, FLAGS);                                              \
    } NAME SEC(".maps")

/* Declare an inode storage map @NAME with value type @VALUE.
 * The map creation flags may be specified with @FLAGS. */
#define BPF_INODE_STORAGE(NAME, VALUE, FLAGS)                                  \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_INODE_STORAGE);                              \
        __uint(map_flags, (FLAGS | BPF_F_NO_PREALLOC));                        \
        __type(key, int);                                                      \
        __type(value, VALUE);                                                  \
    } NAME SEC(".maps")

#endif /* ifndef HELPERS_H */

