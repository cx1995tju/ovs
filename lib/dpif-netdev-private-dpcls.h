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

#ifndef DPIF_NETDEV_PRIVATE_DPCLS_H
#define DPIF_NETDEV_PRIVATE_DPCLS_H 1

#include "dpif.h"

#include <stdbool.h>
#include <stdint.h>

#include "cmap.h"
#include "openvswitch/thread.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Forward declaration for lookup_func typedef. */
struct dpcls_subtable;
struct dpcls_rule;
struct dpcls;

/* Must be public as it is instantiated in subtable struct below. */
// microflow 的 key
struct netdev_flow_key {
    uint32_t hash;       /* Hash function differs for different users. */
    uint32_t len;        /* Length of the following miniflow (incl. map). */
    struct miniflow mf;	// 节省 flow 的空间, 是 struct flow 的压缩
    uint64_t buf[FLOW_MAX_PACKET_U64S];
};

/* A rule to be inserted to the classifier. */
// - 表示的是一个 masked key, 即 subtable 中一个 entry 的 key
// - 一个 subtable 中所有的 key mask 都是一样的
// - 可以认为其是一条 megaflow
//
// 插入: dpcls_insert()
// 删除: dpcls_remove() / dpcls_destroy() revalidator线程负责的, %udpif_revalidator()
//
// Q: megaflow 删除的时候, 底层关联的 emc, smc 怎么处理?
//    * emc 引用 dp_netdev_flow (i.e. megaflow) 的时候有引用技术, megaflow 删除的时候, megaflow 不会释放会被标记为 dead, 后续回收 emc 的时候才释放
//    * smc 不需要回收, 仅仅是一个 megaflow 的 cache 层, megaflow 删除后, 后面就算找到别的 flow, 无非就是匹配不上罢了
 
struct dpcls_rule {
    struct cmap_node cmap_node;   /* Within struct dpcls_subtable 'rules'. */
    struct netdev_flow_key *mask; /* Subtable's mask. */ // 因为相同 mask 的 flow组织在同一个 subtable 里(dpcls_subtable), 所以 mask 是一个 per-subtable 的值, 通过指针指过去就好了
    struct netdev_flow_key flow;  /* Matching key. */
    /* 'flow' must be the last field, additional space is allocated here. */
};

/* Lookup function for a subtable in the dpcls. This function is called
 * by each subtable with an array of packets, and a bitmask of packets to
 * perform the lookup on. Using a function pointer gives flexibility to
 * optimize the lookup function based on subtable properties and the
 * CPU instruction set available at runtime.
 */
typedef
uint32_t (*dpcls_subtable_lookup_func)(struct dpcls_subtable *subtable,
                                       uint32_t keys_map,
                                       const struct netdev_flow_key *keys[],
                                       struct dpcls_rule **rules);

/* A set of rules that all have the same fields wildcarded. */
// 组织 megaflow(i.e. dpcls_rule) 的表, 即具有相同 mask 的 megaflow 组织在一起
struct dpcls_subtable {
    /* The fields are only used by writers. */
    struct cmap_node cmap_node OVS_GUARDED; /* Within dpcls 'subtables_map'. */

    /* These fields are accessed by readers. */
    struct cmap rules;           /* Contains "struct dpcls_rule"s. */
    uint32_t hit_cnt;            /* Number of match hits in subtable in current
                                    optimization interval. */

    /* Miniflow fingerprint that the subtable matches on. The miniflow "bits"
     * are used to select the actual dpcls lookup implementation at subtable
     * creation time.
     */
    uint8_t mf_bits_set_unit0;
    uint8_t mf_bits_set_unit1;

    /* The lookup function to use for this subtable. If there is a known
     * property of the subtable (eg: only 3 bits of miniflow metadata is
     * used for the lookup) then this can point at an optimized version of
     * the lookup function for this particular subtable. */
    dpcls_subtable_lookup_func lookup_func;

    /* Caches the masks to match a packet to, reducing runtime calculations. */
    uint64_t *mf_masks;

    struct netdev_flow_key mask; /* Wildcards for fields (const). */
    /* 'mask' must be the last field, additional space is allocated here. */
};

/* Iterate through netdev_flow_key TNL u64 values specified by 'FLOWMAP'. */
#define NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(VALUE, KEY, FLOWMAP)   \
    MINIFLOW_FOR_EACH_IN_FLOWMAP (VALUE, &(KEY)->mf, FLOWMAP)

/* Generates a mask for each bit set in the subtable's miniflow. */
void
dpcls_flow_key_gen_masks(const struct netdev_flow_key *tbl, uint64_t *mf_masks,
                         const uint32_t mf_bits_u0, const uint32_t mf_bits_u1);

/* Matches a dpcls rule against the incoming packet in 'target' */
bool dpcls_rule_matches_key(const struct dpcls_rule *rule,
                            const struct netdev_flow_key *target);

static inline uint32_t
dpif_netdev_packet_get_rss_hash_orig_pkt(struct dp_packet *packet,
                                const struct miniflow *mf)
{
    uint32_t hash;

    if (OVS_LIKELY(dp_packet_rss_valid(packet))) {
        hash = dp_packet_get_rss_hash(packet);
    } else {
        hash = miniflow_hash_5tuple(mf, 0);
        dp_packet_set_rss_hash(packet, hash);
    }

    return hash;
}

/* Allow other implementations to call dpcls_lookup() for subtable search. */
bool
dpcls_lookup(struct dpcls *cls, const struct netdev_flow_key *keys[],
             struct dpcls_rule **rules, const size_t cnt,
             int *num_lookups_p);

#ifdef  __cplusplus
}
#endif

#endif /* dpif-netdev-private-dpcls.h */
