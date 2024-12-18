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

#ifndef DPIF_NETDEV_PRIVATE_THREAD_H
#define DPIF_NETDEV_PRIVATE_THREAD_H 1

#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-netdev-private-dfc.h"
#include "dpif-netdev-private-dpif.h"

#include <stdbool.h>
#include <stdint.h>

#include "cmap.h"

#include "dpif-netdev-private-dfc.h"
#include "dpif-netdev-private-dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-netdev-private-extract.h"
#include "openvswitch/thread.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* PMD Thread Structures */

/* A set of properties for the current processing loop that is not directly
 * associated with the pmd thread itself, but with the packets being
 * processed or the short-term system configuration (for example, time).
 * Contained by struct dp_netdev_pmd_thread's 'ctx' member. */
struct dp_netdev_pmd_thread_ctx {
    /* Latest measured time. See 'pmd_thread_ctx_time_update()'. */
    long long now;
    /* RX queue from which last packet was received. */
    struct dp_netdev_rxq *last_rxq;
    /* EMC insertion probability context for the current processing cycle. */
    uint32_t emc_insert_min; // ref: emc_probabilistic_insert()
    /* Enable the SMC cache from ovsdb config. */
    bool smc_enable_db;
};

/* PMD: Poll modes drivers.  PMD accesses devices via polling to eliminate
 * the performance overhead of interrupt processing.  Therefore netdev can
 * not implement rx-wait for these devices.  dpif-netdev needs to poll
 * these device to check for recv buffer.  pmd-thread does polling for
 * devices assigned to itself.
 *
 * DPDK used PMD for accessing NIC.
 *
 * Note, instance with cpu core id NON_PMD_CORE_ID will be reserved for
 * I/O of all non-pmd threads.  There will be no actual thread created
 * for the instance.
 *
 * 每个pmd都有自己的EMC
 * 每个端口有自己的dpcls
 * 每个bridge才有ofproto classifier
 *
 * Each struct has its own flow cache and classifier per managed ingress port.
 * For packets received on ingress port, a look up is done on corresponding PMD
 * thread's flow cache and in case of a miss, lookup is performed in the
 * corresponding classifier of port.  Packets are executed with the found
 * actions in either case.
 * */
//dp: datapath
//pmd_thread
//综上：这个结构表示一个dpdk类型的datapath的pmd thread
// 主线程会作为 nonpmd 也有一个这个结构: dp_netdev_set_nonpmd(), 而且主线程的static_tx_qid 是 0
struct dp_netdev_pmd_thread {
    struct dp_netdev *dp; //表示基于dpdk 的 datapath, 一个datapath可能有很多thread的, dpif_netdev.dp
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */
    struct cmap_node node;          /* In 'dp->poll_threads'. */ //链接到对应的datapath 结构的链表上

    /* Per thread exact-match cache.  Note, the instance for cpu core
     * NON_PMD_CORE_ID can be accessed by multiple threads, and thusly
     * need to be protected by 'non_pmd_mutex'.  Every other instance
     * will only be accessed by its own pmd thread. */
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) struct dfc_cache flow_cache; //保存emc, per-pmd 的

    /* Flow-Table and classifiers
     *
     * Writers of 'flow_table' must take the 'flow_mutex'.  Corresponding
     * changes to 'classifiers' must be made while still holding the
     * 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;
    // concurrent hash map
    struct cmap flow_table OVS_GUARDED; /* Flow table. */	// datapath 中所有的 flow 都在这里，是 per-pmd, 保存的是 dp_netdev_flow 结构

    /* One classifier per in_port polled by the pmd */
    // 每个 in_port 有一个 megaflow 的表
    struct cmap classifiers;	// per-in_port  struct dpcls 结构挂在这里, 而且会保证不会这里的 megaflow  overlapping, ref: comments on dpcls_lookup()
    /* Periodically sort subtable vectors according to hit frequencies */
    long long int next_optimization;
    /* End of the next time interval for which processing cycles
       are stored for each polled rxq. */
    long long int next_cycle_store;

    /* Last interval timestamp. */
    uint64_t intrvl_tsc_prev;
    /* Last interval cycles. */
    atomic_ullong intrvl_cycles;

    /* Write index for 'busy_cycles_intrvl'. */
    unsigned int intrvl_idx;
    /* Busy cycles in last PMD_INTERVAL_MAX intervals. */
    atomic_ullong *busy_cycles_intrvl;

    /* Current context of the PMD thread. */
    struct dp_netdev_pmd_thread_ctx ctx;

    /* Function pointer to call for dp_netdev_input() functionality. */
    ATOMIC(dp_netdev_input_func) netdev_input_func;

    /* Pointer for per-DPIF implementation scratch space. */
    void *netdev_input_func_userdata;

    /* Function pointer to call for miniflow_extract() functionality. */
    ATOMIC(miniflow_extract_func) miniflow_extract_opt;

    struct seq *reload_seq;
    uint64_t last_reload_seq;

    /* These are atomic variables used as a synchronization and configuration
     * points for thread reload/exit.
     *
     * 'reload' atomic is the main one and it's used as a memory
     * synchronization point for all other knobs and data.
     *
     * For a thread that requests PMD reload:
     *
     *   * All changes that should be visible to the PMD thread must be made
     *     before setting the 'reload'.  These changes could use any memory
     *     ordering model including 'relaxed'.
     *   * Setting the 'reload' atomic should occur in the same thread where
     *     all other PMD configuration options updated.
     *   * Setting the 'reload' atomic should be done with 'release' memory
     *     ordering model or stricter.  This will guarantee that all previous
     *     changes (including non-atomic and 'relaxed') will be visible to
     *     the PMD thread.
     *   * To check that reload is done, thread should poll the 'reload' atomic
     *     to become 'false'.  Polling should be done with 'acquire' memory
     *     ordering model or stricter.  This ensures that PMD thread completed
     *     the reload process.
     *
     * For the PMD thread:
     *
     *   * PMD thread should read 'reload' atomic with 'acquire' memory
     *     ordering model or stricter.  This will guarantee that all changes
     *     made before setting the 'reload' in the requesting thread will be
     *     visible to the PMD thread.
     *   * All other configuration data could be read with any memory
     *     ordering model (including non-atomic and 'relaxed') but *only after*
     *     reading the 'reload' atomic set to 'true'.
     *   * When the PMD reload done, PMD should (optionally) set all the below
     *     knobs except the 'reload' to their default ('false') values and
     *     (mandatory), as the last step, set the 'reload' to 'false' using
     *     'release' memory ordering model or stricter.  This will inform the
     *     requesting thread that PMD has completed a reload cycle.
     */
    atomic_bool reload;             /* Do we need to reload ports? */
    atomic_bool wait_for_reload;    /* Can we busy wait for the next reload? */
    atomic_bool reload_tx_qid;      /* Do we need to reload static_tx_qid? */
    atomic_bool exit;               /* For terminating the pmd thread. */

    pthread_t thread;
    unsigned core_id;               /* CPU core id of this pmd thread. */
    int numa_id;                    /* numa node id of this pmd thread. */
    bool isolated;

    /* Queue id used by this pmd thread to send packets on all netdevs if
     * XPS disabled for this netdev. All static_tx_qid's are unique and less
     * than 'cmap_count(dp->poll_threads)'. */
    // 如果 port 支持的 queue 数目小于 static_tx_qid 怎么办 ? 那就必须开启 struct tx_port.dynamic_txqs
    // nonpmd 主线程的 static_tx_qid 是 0, ref: dp_netdev_set_nonpmd()
    uint32_t static_tx_qid;

    /* Number of filled output batches. */
    int n_output_batches;

    struct ovs_mutex port_mutex;    /* Mutex for 'poll_list' and 'tx_ports'. */
    /* List of rx queues to poll. */
    struct hmap poll_list OVS_GUARDED; //需要polling 的rx queue, 这个结构 main thread 会访问的, 所以在数据面不会直接使用其中的信息, 而是会 copy 其中的信息到局部变量使用, ref: pmd_load_queues_and_ports()
    /* Map of 'tx_port's used for transmission.  Written by the main thread,
     * read by the pmd thread. */
    // 每个 pmd 都需要有能力将 pkt 发送给所有的 tx_ports, 所以会将 tx_port 挂载到这里
    // 只有使用 tx_port 的哪个 q, 分两种情况: ref: dp_netdev_pmd_flush_output_on_port
    // - 支持 dynamic_txqs 的话, 就使用 tx->tx_qid
    // - 不支持的话, 则使用 static_tx_qid, 这时候显然:
    //         - 所有 pmd 的 static_tx_qid 不能一样
    struct hmap tx_ports OVS_GUARDED; //需要transmit的tx port, 挂载的是 `struct tx_port` 结构, ref: dp_netdev_add_port_tx_to_pmd()

    struct ovs_mutex bond_mutex;    /* Protects updates of 'tx_bonds'. */
    /* Map of 'tx_bond's used for transmission.  Written by the main thread
     * and read by the pmd thread. */
    struct cmap tx_bonds;

    /* These are thread-local copies of 'tx_ports'.  One contains only tunnel
     * ports (that support push_tunnel/pop_tunnel), the other contains ports
     * with at least one txq (that support send).  A port can be in both.
     *
     * There are two separate maps to make sure that we don't try to execute
     * OUTPUT on a device which has 0 txqs or PUSH/POP on a non-tunnel device.
     *
     * The instances for cpu core NON_PMD_CORE_ID can be accessed by multiple
     * threads, and thusly need to be protected by 'non_pmd_mutex'.  Every
     * other instance will only be accessed by its own pmd thread. */
    struct hmap tnl_port_cache; // 为了性能问题(tx_ports 会被 main thread 访问的), 会将 tx_ports 中的信息 copy 到 tnl_port_cache / send_port_cache
    struct hmap send_port_cache;

    /* Keep track of detailed PMD performance statistics. */
    struct pmd_perf_stats perf_stats;

    /* Stats from previous iteration used by automatic pmd
     * load balance logic. */
    uint64_t prev_stats[PMD_N_STATS];
    atomic_count pmd_overloaded;

    /* Set to true if the pmd thread needs to be reloaded. */
    bool need_reload;

    /* Next time when PMD should try RCU quiescing. */
    long long next_rcu_quiesce;
};

#ifdef  __cplusplus
}
#endif

#endif /* dpif-netdev-private-thread.h */
