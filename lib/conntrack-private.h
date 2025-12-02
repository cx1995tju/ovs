/*
 * Copyright (c) 2015-2019 Nicira, Inc.
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

#ifndef CONNTRACK_PRIVATE_H
#define CONNTRACK_PRIVATE_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "cmap.h"
#include "conntrack.h"
#include "ct-dpif.h"
#include "ipf.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "unaligned.h"
#include "dp-packet.h"

struct ct_endpoint {
    union ct_addr addr;
    union {
        ovs_be16 port;
        struct {
            ovs_be16 icmp_id;
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};

/* Verify that there is no padding in struct ct_endpoint, to facilitate
 * hashing in ct_endpoint_hash_add(). */
BUILD_ASSERT_DECL(sizeof(struct ct_endpoint) == sizeof(union ct_addr) + 4);

/* Changes to this structure need to be reflected in conn_key_hash()
 * and conn_key_cmp(). */
// 关于 icmp 报文的 src 和 dst, ref: extract_l4_icmp
//
// 对于 icmp 报文, 这里的 src, dst 是从 icmp paylaod 的提取的
struct conn_key {
    struct ct_endpoint src;
    struct ct_endpoint dst;

    ovs_be16 dl_type;
    uint16_t zone;
    uint8_t nw_proto;
};

/* Verify that nw_proto stays uint8_t as it's used to index into l4_protos[] */
BUILD_ASSERT_DECL(MEMBER_SIZEOF(struct conn_key, nw_proto) == sizeof(uint8_t));

/* This is used for alg expectations; an expectation is a
 * context created in preparation for establishing a data
 * connection. The expectation is created by the control
 * connection. */
struct alg_exp_node {
    /* Node in alg_expectations. */
    struct hmap_node node;
    /* Node in alg_expectation_refs. */
    struct hindex_node node_ref;
    /* Key of data connection to be created. */
    struct conn_key key;
    /* Corresponding key of the control connection. */
    struct conn_key parent_key;
    /* The NAT replacement address to be used by the data connection. */
    union ct_addr alg_nat_repl_addr;
    /* The data connection inherits the parent control
     * connection label and mark. */
    ovs_u128 parent_label;
    uint32_t parent_mark;
    /* True if for NAT application, the alg replaces the dest address;
     * otherwise, the source address is replaced.  */
    bool nat_rpl_dst;
};

enum OVS_PACKED_ENUM ct_conn_type {
    CT_CONN_TYPE_DEFAULT,
    CT_CONN_TYPE_UN_NAT,  // 做 nat 的时创建的额外的 conn. ref: conn_not_found
};

// XXX: 核心的核心结构
// 关于 NAT 中 key 和 rev_key 的说明: ref: pat_packet(), nat_packet()
//
// 对于 SNAT:  A->C => B->C
// conn:
// - key: A->C
// - rev_key: C->B
//
// nat_conn:
// - key: C->B
// - rev_key: A->C
//
//
// 对于 DNAT: A->C => A->B
// conn:
// - key: A->C
// - rev_key: B->A
//
// nat_conn:
// - key: B->A
// - rev_key: A->C
struct conn {
    /* Immutable data. */
    struct conn_key key; // 5-tuple, ref: conn_not_found
    struct conn_key rev_key; // 做 lookup 的时候, 不仅仅用 key 来 look, 也用 rev_key 来 look_up
    struct conn_key parent_key; /* Only used for orig_tuple support. */ // 支持 ftp 这种功能
    struct ovs_list exp_node; // 用于连接 跟踪扩展的 list
    struct cmap_node cm_node; // 连接到 hash 表
    uint16_t nat_action; // %NAT_ACTION_DST_PORT   nat action
    char *alg; // fip, sip 应用层网关 (ALG)
    struct conn *nat_conn; /* The NAT 'conn' context, if there is one. */

    /* Mutable data. */
    struct ovs_mutex lock; /* Guards all mutable fields. */
    ovs_u128 label;
    long long expiration;
    uint32_t mark;
    int seq_skew; // tcp 序号偏移量, 用于 ftp, alg 场景. 某些操作导致序号比阿华了, 那么么就需要记录偏移量, 用于后续的 seq 校验

    /* Immutable data. */
    int32_t admit_zone; /* The zone for managing zone limit counts. */
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */

    /* Mutable data. */
    bool seq_skew_dir; /* TCP sequence skew direction due to NATTing of FTP
                        * control messages; true if reply direction. */
    bool cleaned; /* True if cleaned from expiry lists. */

    /* Immutable data. */
    bool alg_related; /* True if alg data connection. */
    enum ct_conn_type conn_type; // ref: CT_CONN_TYPE_UN_NAT

    uint32_t tp_id; /* Timeout policy ID. */
};

// ref: conn_update_state()
enum ct_update_res {
    CT_UPDATE_INVALID,
    CT_UPDATE_VALID,
    CT_UPDATE_NEW,
    CT_UPDATE_VALID_NEW,
};

/* Timeouts: all the possible timeout states passed to update_expiration()
 * are listed here. The name will be prefix by CT_TM_ and the value is in
 * milliseconds */
#define CT_TIMEOUTS \
    CT_TIMEOUT(TCP_FIRST_PACKET) \
    CT_TIMEOUT(TCP_OPENING) \
    CT_TIMEOUT(TCP_ESTABLISHED) \
    CT_TIMEOUT(TCP_CLOSING) \
    CT_TIMEOUT(TCP_FIN_WAIT) \
    CT_TIMEOUT(TCP_CLOSED) \
    CT_TIMEOUT(OTHER_FIRST) \
    CT_TIMEOUT(OTHER_MULTIPLE) \
    CT_TIMEOUT(OTHER_BIDIR) \
    CT_TIMEOUT(ICMP_FIRST) \
    CT_TIMEOUT(ICMP_REPLY)

#define NAT_ACTION_SNAT_ALL (NAT_ACTION_SRC | NAT_ACTION_SRC_PORT)
#define NAT_ACTION_DNAT_ALL (NAT_ACTION_DST | NAT_ACTION_DST_PORT)

enum ct_ephemeral_range {
    MIN_NAT_EPHEMERAL_PORT = 1024,
    MAX_NAT_EPHEMERAL_PORT = 65535
};

#define IN_RANGE(curr, min, max) \
    (curr >= min && curr <= max)

#define NEXT_PORT_IN_RANGE(curr, min, max) \
    (curr = (!IN_RANGE(curr, min, max) || curr == max) ? min : curr + 1)

/* If the current port is out of range increase the attempts by
 * one so that in the worst case scenario the current out of
 * range port plus all the in-range ports get tested.
 * Note that curr can be an out of range port only in case of
 * source port (SNAT with port range unspecified or DNAT),
 * furthermore the source port in the packet has to be less than
 * MIN_NAT_EPHEMERAL_PORT. */
#define N_PORT_ATTEMPTS(curr, min, max) \
    ((!IN_RANGE(curr, min, max)) ? (max - min) + 2 : (max - min) + 1)

/* Loose in-range check, the first curr port can be any port out of
 * the range. */
#define FOR_EACH_PORT_IN_RANGE__(curr, min, max, INAME) \
    for (uint16_t INAME = N_PORT_ATTEMPTS(curr, min, max); \
        INAME > 0; INAME--, NEXT_PORT_IN_RANGE(curr, min, max))

#define FOR_EACH_PORT_IN_RANGE(curr, min, max) \
    FOR_EACH_PORT_IN_RANGE__(curr, min, max, OVS_JOIN(idx, __COUNTER__))

enum ct_timeout {
#define CT_TIMEOUT(NAME) CT_TM_##NAME,
    CT_TIMEOUTS
#undef CT_TIMEOUT
    N_CT_TM
};

// per-datapath 的结构. ovs-dpdk 里所有 pmd 共享一个该结构
struct conntrack {
    struct ovs_mutex ct_lock; /* Protects 2 following fields. */
    struct cmap conns OVS_GUARDED;                     // 组织 ct 的 hash 表
    struct ovs_list exp_lists[N_CT_TM] OVS_GUARDED;
    struct hmap zone_limits OVS_GUARDED;
    struct hmap timeout_policies OVS_GUARDED;
    uint32_t hash_basis; /* Salt for hashing a connection key. */
    pthread_t clean_thread; /* Periodically cleans up connection tracker. */
    struct latch clean_thread_exit; /* To destroy the 'clean_thread'. */

    /* Counting connections. */
    atomic_count n_conn; /* Number of connections currently tracked. */
    atomic_uint n_conn_limit; /* Max connections tracked. */

    /* Expectations for application level gateways (created by control
     * connections to help create data connections, e.g. for FTP). */
    struct ovs_rwlock resources_lock; /* Protects fields below. */
    struct hmap alg_expectations OVS_GUARDED; /* Holds struct
                                               * alg_exp_nodes. */
    struct hindex alg_expectation_refs OVS_GUARDED; /* For lookup from
                                                     * control context.  */

    struct ipf *ipf; /* Fragmentation handling context. */
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */
    atomic_bool tcp_seq_chk; /* Check TCP sequence numbers. */
};

/* Lock acquisition order:
 *    1. 'ct_lock'
 *    2. 'conn->lock'
 *    3. 'resources_lock'
 */

extern struct ct_l4_proto ct_proto_tcp;
extern struct ct_l4_proto ct_proto_other;
extern struct ct_l4_proto ct_proto_icmp4;
extern struct ct_l4_proto ct_proto_icmp6;

// 核心结构, 各个 l4 实现 protocol specific 的逻辑
struct ct_l4_proto {
	// 创建新连接
    struct conn *(*new_conn)(struct conntrack *ct, struct dp_packet *pkt,
                             long long now, uint32_t tp_id);

    // 校验 pkt 用来创建 new conn 是否合法
    bool (*valid_new)(struct dp_packet *pkt);

    // 主题逻辑, pkt 都送到这里来更新状态
    enum ct_update_res (*conn_update)(struct conntrack *ct, struct conn *conn,
                                      struct dp_packet *pkt, bool reply,
                                      long long now);

    // dump 连接相关信息
    void (*conn_get_protoinfo)(const struct conn *,
                               struct ct_dpif_protoinfo *);
};

#endif /* conntrack-private.h */
