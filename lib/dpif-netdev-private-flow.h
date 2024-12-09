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

#ifndef DPIF_NETDEV_PRIVATE_FLOW_H
#define DPIF_NETDEV_PRIVATE_FLOW_H 1

#include "dpif.h"
#include "dpif-netdev-private-dpcls.h"

#include <stdbool.h>
#include <stdint.h>

#include "cmap.h"
#include "openvswitch/thread.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Contained by struct dp_netdev_flow's 'stats' member.  */
struct dp_netdev_flow_stats {
    atomic_llong used;             /* Last used time, in monotonic msecs. */
    atomic_ullong packet_count;    /* Number of packets matched. */
    atomic_ullong byte_count;      /* Number of bytes matched. */
    atomic_uint16_t tcp_flags;     /* Bitwise-OR of seen tcp_flags values. */
};

/* Contained by struct dp_netdev_flow's 'last_attrs' member.  */
struct dp_netdev_flow_attrs {
    atomic_bool offloaded;         /* True if flow is offloaded to HW. */
    ATOMIC(const char *) dp_layer; /* DP layer the flow is handled in. */
};

/* A flow in 'dp_netdev_pmd_thread's 'flow_table'.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * its pmd thread's classifier.  The text below calls this classifier 'cls'.
 *
 * Motivation
 * ----------
 *
 * The thread safety rules described here for "struct dp_netdev_flow" are
 * motivated by two goals:
 *
 *    - Prevent threads that read members of "struct dp_netdev_flow" from
 *      reading bad data due to changes by some thread concurrently modifying
 *      those members.
 *
 *    - Prevent two threads making changes to members of a given "struct
 *      dp_netdev_flow" from interfering with each other.
 *
 *
 * Rules
 * -----
 *
 * A flow 'flow' may be accessed without a risk of being freed during an RCU
 * grace period.  Code that needs to hold onto a flow for a while
 * should try incrementing 'flow->ref_cnt' with dp_netdev_flow_ref().
 *
 * 'flow->ref_cnt' protects 'flow' from being freed.  It doesn't protect the
 * flow from being deleted from 'cls' and it doesn't protect members of 'flow'
 * from modification.
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 */
// 将报文提交给 openflow 层处理后, 利用得到的信息来构造这个结构, handle_packet_upcall()
// 创建: dp_netdev_flow_add()
/* Q:  一个 dp_netdev_flow 即通过 flow 表达了精确的 key, 又通过 cr 表示一个 megaflow, 那么 megaflow 不会 overlapping 么 ?
 * dp_netdev_flow 是一个 数据面使用的 flow, 但是其并不是 __一个精确的 flow__ , 虽然其开头有一个 const struct flow flow 结构, 但是这个结构里的 key 其实不太重要, 重要的是其中的 actions
 *
 * - emc 插入的时候, key 不是使用的这里的 flow 里的 key, 而是 从 pkt 里提取出来的key, 但是 value 会指向这个 dp_netdev_flow, 主要是为了其中的 actions 咯
 *
 *
 * 注: 可以不精确的将其看作 megaflow, 因为 megaflow 就是数据面最大的 flow 了, 而这个就是数据面用的最大的 flow
 * */
struct dp_netdev_flow {
    // miss 的时候将 pkt upcall 到 openflow 层, 这时候匹配的到 openflow 是通配的, 后续创建的 megaflow 也是通配的
    const struct flow flow;      /* Unmasked flow that created this entry. */ // flow key, 保存到dp_netdev_pmd_thread.flow_table
    /* Hash table index by unmasked flow. */
    const struct cmap_node node; /* In owning dp_netdev_pmd_thread's */
                                 /* 'flow_table'. */
    const struct cmap_node mark_node; /* In owning flow_mark's mark_to_flow */
    const ovs_u128 ufid;         /* Unique flow identifier. */ // 和 mega_ufid 类似, 算出的 一个 uuid 
    const ovs_u128 mega_ufid;    /* Unique mega flow identifier. */ // 其实没有办法 100% 确保, 不过是使用足够大的 uuid 罢了 ref: %dp_netdev_get_mega_ufid()
    const unsigned pmd_id;       /* The 'core_id' of pmd thread owning this */
                                 /* flow. */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt;

    bool dead;
    uint32_t mark;               /* Unique flow mark assigned to a flow */

    /* Statistics. */
    struct dp_netdev_flow_stats stats;

    /* Statistics and attributes received from the netdev offload provider. */
    atomic_int netdev_flow_get_result;
    struct dp_netdev_flow_stats last_stats;
    struct dp_netdev_flow_attrs last_attrs;

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions;

    /* While processing a group of input packets, the datapath uses the next
     * member to store a pointer to the output batch for the flow.  It is
     * reset after the batch has been sent out (See dp_netdev_queue_batches(),
     * packet_batch_per_flow_init() and packet_batch_per_flow_execute()). */
    struct packet_batch_per_flow *batch; // 处理报文的时候临时使用的, 即一次处理中, 相同 flow 的 pkt 都会缓存到这里

    /* Packet classification. */
    char *dp_extra_info;         /* String to return in a flow dump/get. */
    // 不同的
    struct dpcls_rule cr;        /* In owning dp_netdev's 'cls'. */	// megaflow, 创建 dp_netdev_flow 的时候是基于 openflow 的信息的, 那么当然可以有一个 mask 信息咯, 保存到: dp_netdev_pmd_thread.classifiers 里
    /* 'cr' must be the last member. */
};

static inline uint32_t
dp_netdev_flow_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

/* Given the number of bits set in miniflow's maps, returns the size of the
 * 'netdev_flow_key.mf' */
static inline size_t
netdev_flow_key_size(size_t flow_u64s)
{
    return sizeof(struct miniflow) + MINIFLOW_VALUES_SIZE(flow_u64s);
}

/* forward declaration required for EMC to unref flows */
void dp_netdev_flow_unref(struct dp_netdev_flow *);

/* A set of datapath actions within a "struct dp_netdev_flow".
 *
 *
 * Thread-safety
 * =============
 *
 * A struct dp_netdev_actions 'actions' is protected with RCU. */
struct dp_netdev_actions {
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    unsigned int size;          /* Size of 'actions', in bytes. */ // XXX: in bytes
    struct nlattr actions[];    /* Sequence of OVS_ACTION_ATTR_* attributes. */
};

#ifdef  __cplusplus
}
#endif

#endif /* dpif-netdev-private-flow.h */
