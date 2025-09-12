/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
 * Copyright (c) 2019, 2020, 2021 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DPIF_NETDEV_PRIVATE_DFC_H
#define DPIF_NETDEV_PRIVATE_DFC_H 1

#include "dpif.h"
#include "dpif-netdev-private-dpcls.h"
#include "dpif-netdev-private-flow.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* EMC cache and SMC cache compose the datapath flow cache (DFC)
 *
 * Exact match cache for frequently used flows
 *
 * The cache uses a 32-bit hash of the packet (which can be the RSS hash) to
 * search its entries for a miniflow that matches exactly the miniflow of the
 * packet. It stores the 'dpcls_rule' (rule) that matches the miniflow.
 *
 * A cache entry holds a reference to its 'dp_netdev_flow'.
 *
 * A miniflow with a given hash can be in one of EM_FLOW_HASH_SEGS different
 * entries. The 32-bit hash is split into EM_FLOW_HASH_SEGS values (each of
 * them is EM_FLOW_HASH_SHIFT bits wide and the remainder is thrown away). Each
 * value is the index of a cache entry where the miniflow could be.
 *
 *
 * Signature match cache (SMC)
 *
 * This cache stores a 16-bit signature for each flow without storing keys, and
 * stores the corresponding 16-bit flow_table index to the 'dp_netdev_flow'.
 * Each flow thus occupies 32bit which is much more memory efficient than EMC.
 * SMC uses a set-associative design that each bucket contains
 * SMC_ENTRY_PER_BUCKET number of entries.
 * Since 16-bit flow_table index is used, if there are more than 2^16
 * dp_netdev_flow, SMC will miss them that cannot be indexed by a 16-bit value.
 *
 *
 * Thread-safety
 * =============
 *
 * Each pmd_thread has its own private exact match cache.
 * If dp_netdev_input is not called from a pmd thread, a mutex is used.
 */

#define EM_FLOW_HASH_SHIFT 13
#define EM_FLOW_HASH_ENTRIES (1u << EM_FLOW_HASH_SHIFT) // 8K
#define EM_FLOW_HASH_MASK (EM_FLOW_HASH_ENTRIES - 1)
#define EM_FLOW_HASH_SEGS 2

/* SMC uses a set-associative design. A bucket contains a set of entries that
 * a flow item can occupy. For now, it uses one hash function rather than two
 * as for the EMC design. */
#define SMC_ENTRY_PER_BUCKET 4
#define SMC_ENTRIES (1u << 20)
#define SMC_BUCKET_CNT (SMC_ENTRIES / SMC_ENTRY_PER_BUCKET) // 1M / 4 = 256K
#define SMC_MASK (SMC_BUCKET_CNT - 1)

/* Default EMC insert probability is 1 / DEFAULT_EM_FLOW_INSERT_INV_PROB */
#define DEFAULT_EM_FLOW_INSERT_INV_PROB 100
#define DEFAULT_EM_FLOW_INSERT_MIN (UINT32_MAX /                     \
                                    DEFAULT_EM_FLOW_INSERT_INV_PROB)

/* Forward declaration for SMC function prototype that requires access to
 * 'struct dp_netdev_pmd_thread'. */
struct dp_netdev_pmd_thread;

/* Forward declaration for EMC and SMC batch insert function prototypes that
 * require access to 'struct dpcls_rule'. */
struct dpcls_rule;

struct emc_entry {
    struct dp_netdev_flow *flow; // 指向其关联的数据面的 flow
    struct netdev_flow_key key;   /* key.hash used for emc hash value. */
};

// emc flow 表
// entries 是一个 hash 表，采样 hash 移位来避免冲突
// ref: EMC_FOR_EACH_POS_WITH_HASH
struct emc_cache {
    struct emc_entry entries[EM_FLOW_HASH_ENTRIES]; // 每个 pmd 的 这个 cache 大小是固定的
    int sweep_idx;                /* For emc_cache_slow_sweep(). */
};

// 一个 bucket 存储哪些 netdev_flow_key.hash % SMC_BUCKET_CNT 相同的 flow
// 在 bucket 里的 SMC_ENTRY_PER_BUCKET 个 flow sig 都是不同的
// 每个 桶 4 个 entry
struct smc_bucket {
    uint16_t sig[SMC_ENTRY_PER_BUCKET]; // 这个是 key
    uint16_t flow_idx[SMC_ENTRY_PER_BUCKET]; // 这个是 value, 指向 dp_netdev_pmd_thread.flow_table 里的位置. flow_table 
};

/* Signature match cache, differentiate from EMC cache */
// emc 是精确匹配的，smc 则是按照报文 hash 值保存的一个桶。 
// 根据 netdev_flow_key.hash % SMC_BUCKET_CNT 作为 index 找到对应的 bucket, ref: smc_insert
// 然后将 flow 的 hash 的 [31:16]b 作为 sig 将其在 dp_netdev_pmd_thread.flow_table 中的位置保存到 flow_idx 中
struct smc_cache {
    struct smc_bucket buckets[SMC_BUCKET_CNT]; // 256K 个桶 ???
};

// emc 插入: emc_insert()
// emc 删除: emc_cache_slow_sweep()
//
// smc 插入: smc_insert
// smc 删除: 插入 的时候冲突了就被覆盖了 ???
struct dfc_cache {
    struct emc_cache emc_cache;
    // emc 和 megaflow 之间的一层 基于签名而不是 flow key 匹配的表
    struct smc_cache smc_cache;
};

/* Iterate in the exact match cache through every entry that might contain a
 * miniflow with hash 'HASH'. */
#define EMC_FOR_EACH_POS_WITH_HASH(EMC, CURRENT_ENTRY, HASH)                 \
    for (uint32_t i__ = 0, srch_hash__ = (HASH);                             \
         (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ & EM_FLOW_HASH_MASK], \
         i__ < EM_FLOW_HASH_SEGS;                                            \
         i__++, srch_hash__ >>= EM_FLOW_HASH_SHIFT) // 这里是避免冲突的操作

void dfc_cache_init(struct dfc_cache *flow_cache);

void dfc_cache_uninit(struct dfc_cache *flow_cache);

/* Check and clear dead flow references slowly (one entry at each
 * invocation).  */
void emc_cache_slow_sweep(struct emc_cache *flow_cache);

// 什么时候 ce->flow 会被置为 NULL 呢 ??? ref: emc_clear_entry()
// 什么时候 flow 会被置为 dead 呢 ??? dp_netdev_pmd_remove_flow
static inline bool
emc_entry_alive(struct emc_entry *ce)
{
    return ce->flow && !ce->flow->dead;
}

/* Used to compare 'netdev_flow_key' in the exact match cache to a miniflow.
 * The maps are compared bitwise, so both 'key->mf' and 'mf' must have been
 * generated by miniflow_extract. */
static inline bool
emc_flow_key_equal_mf(const struct netdev_flow_key *key,
                         const struct miniflow *mf)
{
    return !memcmp(&key->mf, mf, key->len);
}

// key 可以从 packet 里提取的
// cache 是 per-pmd 结构，从 pmd 里获取
// 如果命中了，直接返回数据面使用的 flow, dp_netdev_flow, 其中包含有 action
static inline struct dp_netdev_flow *
emc_lookup(struct emc_cache *cache, const struct netdev_flow_key *key)
{
    struct emc_entry *current_entry;

    EMC_FOR_EACH_POS_WITH_HASH (cache, current_entry, key->hash) {
        if (current_entry->key.hash == key->hash
            && emc_entry_alive(current_entry)
            && emc_flow_key_equal_mf(&current_entry->key, &key->mf)) {	// 遍历 entry，然后用 miniflow 匹配

            /* We found the entry with the 'key->mf' miniflow */
            return current_entry->flow;
        }
    }

    return NULL;
}

/* Insert a batch of keys/flows into the EMC and SMC caches. */
void
emc_probabilistic_insert_batch(struct dp_netdev_pmd_thread *pmd,
                               const struct netdev_flow_key *keys,
                               struct dpcls_rule **rules,
                               uint32_t emc_insert_mask);

void
smc_insert_batch(struct dp_netdev_pmd_thread *pmd,
                               const struct netdev_flow_key *keys,
                               struct dpcls_rule **rules,
                               uint32_t smc_insert_mask);

struct dp_netdev_flow *
smc_lookup_single(struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet *packet,
                  struct netdev_flow_key *key);

#ifdef  __cplusplus
}
#endif

#endif /* dpif-netdev-private-dfc.h */
