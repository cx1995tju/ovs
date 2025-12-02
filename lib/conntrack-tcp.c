/*-
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2008 Henning Brauer
 * Copyright (c) 2012 Gleb Smirnoff <glebius@FreeBSD.org>
 * Copyright (c) 2015, 2016 Nicira, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 *      $OpenBSD: pf.c,v 1.634 2009/02/27 12:37:45 henning Exp $
 */

#include <config.h>

#include "conntrack-private.h"
#include "conntrack-tp.h"
#include "coverage.h"
#include "ct-dpif.h"
#include "dp-packet.h"
#include "util.h"

COVERAGE_DEFINE(conntrack_tcp_seq_chk_bypass);
COVERAGE_DEFINE(conntrack_tcp_seq_chk_failed);
COVERAGE_DEFINE(conntrack_invalid_tcp_flags);

// ref: tcp_new_conn
struct tcp_peer {
    uint32_t               seqlo;          /* Max sequence number sent     */ // 从本端发送的 pkt:seq 里提取的
    uint32_t               seqhi;          /* Max the other end ACKd + win */ // 从 peer 的 pkt:ack 里提取的
    uint16_t               max_win;        /* largest window (pre scaling) */
    uint8_t                wscale;         /* window scaling factor        */
    enum ct_dpif_tcp_state state;
};

struct conn_tcp {
    struct conn up;
    struct tcp_peer peer[2]; /* 'conn' lock protected. */ // peer[0] -> peer[1] 是原始方向
};

enum {
    TCPOPT_EOL,
    TCPOPT_NOP,
    TCPOPT_WINDOW = 3,
};

/* TCP sequence numbers are 32 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers. */
#define SEQ_LT(a,b)     INT_MOD_LT(a, b)
#define SEQ_LEQ(a,b)    INT_MOD_LEQ(a, b)
#define SEQ_GT(a,b)     INT_MOD_GT(a, b)
#define SEQ_GEQ(a,b)    INT_MOD_GEQ(a, b)

#define SEQ_MIN(a, b)   INT_MOD_MIN(a, b)
#define SEQ_MAX(a, b)   INT_MOD_MAX(a, b)

static struct conn_tcp*
conn_tcp_cast(const struct conn* conn)
{
    return CONTAINER_OF(conn, struct conn_tcp, up);
}

/* pf does this in in pf_normalize_tcp(), and it is called only if scrub
 * is enabled.  We're not scrubbing, but this check seems reasonable.  */
static bool
tcp_invalid_flags(uint16_t flags)
{

    if (flags & TCP_SYN) {
        if (flags & TCP_RST || flags & TCP_FIN) {
            return true;
        }
    } else {
        /* Illegal packet */
        if (!(flags & (TCP_ACK|TCP_RST))) {
            return true;
        }
    }

    if (!(flags & TCP_ACK)) {
        /* These flags are only valid if ACK is set */
        if ((flags & TCP_FIN) || (flags & TCP_PSH) || (flags & TCP_URG)) {
            return true;
        }
    }

    return false;
}

#define TCP_MAX_WSCALE 14
#define CT_WSCALE_FLAG 0x80
// 建立 tcp ct conn 的时候的报文不是 syn 包, 那么就只能猜测双方的 wscale 了
#define CT_WSCALE_UNKNOWN 0x40
#define CT_WSCALE_MASK 0xf

static uint8_t
tcp_get_wscale(const struct tcp_header *tcp)
{
    int len = TCP_OFFSET(tcp->tcp_ctl) * 4 - sizeof *tcp;
    const uint8_t *opt = (const uint8_t *)(tcp + 1);
    uint8_t wscale = 0;
    uint8_t optlen;

    while (len >= 3) {
        switch (*opt) {
        case TCPOPT_EOL:
            return wscale;
        case TCPOPT_NOP:
            opt++;
            len--;
            break;
        case TCPOPT_WINDOW:
            wscale = MIN(opt[2], TCP_MAX_WSCALE);
            wscale |= CT_WSCALE_FLAG;
            /* fall through */
        default:
            optlen = opt[1];
            if (optlen < 2) {
                optlen = 2;
            }
            len -= optlen;
            opt += optlen;
        }
    }

    return wscale;
}

// 可以强行跳过 seq 检查的
// 默认情况下是做检查的
static bool
tcp_bypass_seq_chk(struct conntrack *ct)
{
    if (!conntrack_get_tcp_seq_chk(ct)) {
        COVERAGE_INC(conntrack_tcp_seq_chk_bypass);
        return true;
    }
    return false;
}

// 核心逻辑: 关注返回值
// INPUT:
// - @ct: global ct moudle root struct
// - @conn_: the conn struct for this tcp connection, Obtained from the generic CT layer
// - @pkt: 整理被处理的 pkt
// - @reply: 表示这个 pkt 的方向
// - @now: 用来判断 ct 是不是超时了
//
//
// 这个函数的核心逻辑就是检测一个 tcp  包是否合法:
// - 一些基础的检测: tcp_flags
// - 最重要的是 seq 范围和 ack 范围的检测
//
// ref:  real stateful TCP Packet Filtering in IP Filter.
//
// seq 和 ack 范围的检测就是使用的上述 paper 里的算法.
//
// 算法原理: 合法的 seq 号和 ack 号满足下述条件
//
// 对于一个 A->B 的 pkt [s, s+n)
// - s+n <= B:ack     + A:maxwin
// - s   >= A:pre:s+n - A:maxwin
//
// A->B 的 pkt ack号 的合法范围
// - ack <= B:s+n
// - ack >= B:s+n - MAXACKWINDOW(66000)
//
// 注: 考虑到 zero window probing 问题, maxwin 修正为 max(maxwin, 1)
//
// 算法实现, 为每端(self, peer)维护三个变量:
// - td_end(seqlo):     F 看到的 self 发送的最大的 s + n.          和 snd_nxt 的含义类似
// - td_maxend(seqhi):  F 看到的 peer 发送的最大的 ack + max(win). 即 CT 看到的窗口 left_boundary + max(win, 1)
// - td_maxwin:         F 看到的 self 发送的 maxwin
//
//
// 然后从 pkt 里提取出下述信息:
// - ack: ack 号
// - seq: seq 号, i.e. s
// - end: seq 号 + payload len. i.e. s+n
//
//
// 综上 合法的 pkt 需要 满足:
// - end <= self->seqhi
// - seq >= self.seqlo  - peer.max_win
// - ack <= peer->seqlo
// - ack >= peer->seqlo - MAXACKWINDOW
//
// 定义 ackskew = peer->seqlo - ack, 那么有
// - end          <= self->seqhi
// - seq          >= self.seqlo - peer.max_win
// - 0            <= ackskew
// - MAXACKWINDOW >= ackskew
//
// 另外需要针对分片报文的处理放宽条件:
//
// 定义 ackskew = peer->seqlo - ack, 那么有
// - end          <= self->seqhi
// - seq          >= self.seqlo - peer.max_win
// - -67035       <= ackskew
// - MAXACKWINDOW >= ackskew
//
// 关于 seqlo, seqhi, maxwin 的初始化与更新:
//
// *maxwin* 最好更新的, 只要观察 self->peer 包里的 window 信息就可以了. 唯一的
// 例外就是当我们错过了 syn 和 syn+acl 包里的 wscale 的时候, 我们就要放宽条件,
// 默认 wscale 是最大值.
//
// *seqlo* 自己发送的 pkt seq, 很好更新的.
//
// *seqhi* 如果看到了对方发送的包里带了 ack, 那么就用这个值了. 如果暂时还没有看
// 到对方的 ack 包. 那么就默认用 snd_nxt + 1. 尽量放宽限制.
//
// 
// 其他问题:
// - pure ack 的处理: 没有 data, 也就是 data 平凡的 valid. 
// - ack flag 没有设置: ack 号没有意义, 也就是 ack 号平凡的 valid
// - 创建 ct entry 的 pkt 不是 SYN 包
static enum ct_update_res
tcp_conn_update(struct conntrack *ct, struct conn *conn_,
                struct dp_packet *pkt, bool reply, long long now)
{
    struct conn_tcp *conn = conn_tcp_cast(conn_);
    struct tcp_header *tcp = dp_packet_l4(pkt);
    /* The peer that sent 'pkt' */
    struct tcp_peer *src = &conn->peer[reply ? 1 : 0];
    /* The peer that should receive 'pkt' */
    struct tcp_peer *dst = &conn->peer[reply ? 0 : 1];
    uint8_t sws = 0, dws = 0; // window scale
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    uint16_t win = ntohs(tcp->tcp_winsz);
    uint32_t ack, end, seq, orig_seq; // ack 号, end = seq + packet_len, seq 号
    uint32_t p_len = dp_packet_get_tcp_payload_length(pkt);

    if (tcp_invalid_flags(tcp_flags)) {
        COVERAGE_INC(conntrack_invalid_tcp_flags);
        return CT_UPDATE_INVALID;
    }

    /* pure SYN 包的处理 */
    if ((tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
        if (dst->state >= CT_DPIF_TCPS_FIN_WAIT_2
            && src->state >= CT_DPIF_TCPS_FIN_WAIT_2) { // TIMEWAIT or FIN_WAIT_2. 说明 dst 发出的 FIN 都被处理了. 即 src 之前已经相应了 FIN 了. 那么现在其发出了 syn 那么肯定是要创建新连接. 
            src->state = dst->state = CT_DPIF_TCPS_CLOSED;
            return CT_UPDATE_NEW; // 所以返回这个 flag, 让其重新走 conn_not_found 逻辑去创建新的 conn
        } else if (src->state <= CT_DPIF_TCPS_SYN_SENT) { // 这里应该是 syn 重传了, 然后在 conn_update_state 里会被标记为 ct_stat.new
            src->state = CT_DPIF_TCPS_SYN_SENT;
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_FIRST_PACKET, now);
            return CT_UPDATE_VALID_NEW;
        }
    }

    /* 提取 wscale 来校验后续的 seq */
    if (src->wscale & CT_WSCALE_FLAG
        && dst->wscale & CT_WSCALE_FLAG
        && !(tcp_flags & TCP_SYN)) { // 不是 syn 报文, 而且之前从 syn 报文提取出了 wscale

        sws = src->wscale & CT_WSCALE_MASK;
        dws = dst->wscale & CT_WSCALE_MASK;

    } else if (src->wscale & CT_WSCALE_UNKNOWN
               && dst->wscale & CT_WSCALE_UNKNOWN
               && !(tcp_flags & TCP_SYN)) {

        sws = TCP_MAX_WSCALE;
        dws = TCP_MAX_WSCALE;
    }

    /* XXX: 核心逻辑, seq 的校验
     * Sequence tracking algorithm from Guido van Rooij's paper:
     *   http://www.madison-gurkha.com/publications/tcp_filtering/
     *      tcp_filtering.ps
     */


    // 下面的核心就是获取 seqlo 和 seqhi
    orig_seq = seq = ntohl(get_16aligned_be32(&tcp->tcp_seq));
    bool check_ackskew = true;
    if (src->state < CT_DPIF_TCPS_SYN_SENT) { // CLOSED or LISTEN
        /* First packet from this end. Set its state */ // 因为只有一个方向的 pkt 是用来创建 conn 的, 它在 tcp_new_conn 里处理了
        ack = ntohl(get_16aligned_be32(&tcp->tcp_ack));

        end = seq + p_len;
        if (tcp_flags & TCP_SYN) { // wscale 的提取逻辑
            end++;
            if (dst->wscale & CT_WSCALE_FLAG) {
                src->wscale = tcp_get_wscale(tcp);
                if (src->wscale & CT_WSCALE_FLAG) {
                    /* Remove scale factor from initial window */
                    sws = src->wscale & CT_WSCALE_MASK;
                    win = DIV_ROUND_UP((uint32_t) win, 1 << sws);
                    dws = dst->wscale & CT_WSCALE_MASK;
                } else {
			// 只有一个 方向有 wscale 的时候, 将另一个方向的也抹平, why (???)
                    /* fixup other window */
                    dst->max_win <<= dst->wscale & CT_WSCALE_MASK;
                    /* in case of a retrans SYN|ACK */
                    dst->wscale = 0;
                }
            }
        }
        if (tcp_flags & TCP_FIN) {
            end++;
        }

	// XXX: 无法确保 tcp 连接的所有报文都经过了 ct 模块, 所以这里的状态切换
	// 和真实的 tcp 状态机是有一些区别的. 所以这里只要看到了某个方向的第一
	// 个 pkt, 就无条件切换到 SYN_SENT 状态, 而不在乎其是否是 SYN 报文
	//
	// 对于第一个包 来说, 当然是没有以前的 seqlo 的信息的, 所以用当前的 seq 来 pretend 之前的 seqlo 信息.
        src->seqlo = seq;
        src->state = CT_DPIF_TCPS_SYN_SENT;
        /*
         * May need to slide the window (seqhi may have been set by
         * the crappy stack check or if we picked up the connection
         * after establishment)
         */
	// 注意进入这里的前提是 src->state < SYN_SENT, 说明之前没有看到过这个方向的 pkt
	// 那么这里 seqhi 常态就是 1. rec: tcp_new_conn
        if (src->seqhi == 1 /* ref tcp_new_conn 里的 dst 的设置 */
                || SEQ_GEQ(end + MAX(1, dst->max_win << dws), src->seqhi)) {
            src->seqhi = end + MAX(1, dst->max_win << dws);
            /* We are either picking up a new connection or a connection which
             * was already in place.  We are more permissive in terms of
             * ackskew checking in these cases.
             */
            check_ackskew = false;
        }
        if (win > src->max_win) {
            src->max_win = win;
        }

    } else { // 这是常态路径, ack end 的更新都很简单的
        ack = ntohl(get_16aligned_be32(&tcp->tcp_ack));
        end = seq + p_len;
        if (tcp_flags & TCP_SYN) {
            end++;
        }
        if (tcp_flags & TCP_FIN) {
            end++;
        }
    }

    if ((tcp_flags & TCP_ACK) == 0) { // ack flag 没有设置, 也就是 ack 号没有意义. 那么这里为其设置一个特殊值, 让其平凡的通过后续 ack号检查
        /* Let it pass through the ack skew check */
        ack = dst->seqlo;
    } else if ((ack == 0
                && (tcp_flags & (TCP_ACK|TCP_RST)) == (TCP_ACK|TCP_RST))
               /* broken tcp stacks do not set ack */) {
	    // 有些协议栈比奇怪的, 比如在 SYN 超时后发送 FIN|ACK / RST|ACK 包, 但是 ACK 号是非法的
        /* Many stacks (ours included) will set the ACK number in an
         * FIN|ACK if the SYN times out -- no sequence to ACK. */
        ack = dst->seqlo;
    }

    if (seq == end) { // pure ack pkt, 没有 data , 也就是 data 平凡的 valid.所以这里设置 seq, end 值, 让其肯定通过后续 seq 的检查
        /* Ease sequencing restrictions on no data packets */
        seq = src->seqlo;
        end = seq;
    }

    int ackskew = check_ackskew ? dst->seqlo - ack : 0;
#define MAXACKWINDOW (0xffff + 1500)    /* 1500 is an arbitrary fudge factor */
    if ((SEQ_GEQ(src->seqhi, end)
        /* Last octet inside other's window space */
        && SEQ_GEQ(seq, src->seqlo - (dst->max_win << dws))
        /* Retrans: not more than one window back */
        && (ackskew >= -MAXACKWINDOW)
        /* Acking not more than one reassembled fragment backwards */
        && (ackskew <= (MAXACKWINDOW << sws))
        /* Acking not more than one window forward */
        && ((tcp_flags & TCP_RST) == 0 || orig_seq == src->seqlo
            || (orig_seq == src->seqlo + 1) || (orig_seq + 1 == src->seqlo)))	 // rst 包的特殊处理
        || tcp_bypass_seq_chk(ct)) {
        /* Require an exact/+1 sequence match on resets when possible */

	// 通过检查了,  更新各种信息了
        /* update max window */
        if (src->max_win < win) {
            src->max_win = win;
        }
        /* synchronize sequencing */
        if (SEQ_GT(end, src->seqlo)) {
            src->seqlo = end;
        }
        /* slide the window of what the other end can send */
        if (SEQ_GEQ(ack + (win << sws), dst->seqhi)) {
            dst->seqhi = ack + MAX((win << sws), 1);
        }


	// tcp state machine 更新
        /* update states */
        if (tcp_flags & TCP_SYN && src->state < CT_DPIF_TCPS_SYN_SENT) {
                src->state = CT_DPIF_TCPS_SYN_SENT;
        }
        if (tcp_flags & TCP_FIN && src->state < CT_DPIF_TCPS_CLOSING) {
                src->state = CT_DPIF_TCPS_CLOSING;
        }
        if (tcp_flags & TCP_ACK) {
            if (dst->state == CT_DPIF_TCPS_SYN_SENT) {
                dst->state = CT_DPIF_TCPS_ESTABLISHED;
            } else if (dst->state == CT_DPIF_TCPS_CLOSING) {
                dst->state = CT_DPIF_TCPS_FIN_WAIT_2;
            }
        }
        if (tcp_flags & TCP_RST) {
            src->state = dst->state = CT_DPIF_TCPS_TIME_WAIT;
        }

        if (src->state >= CT_DPIF_TCPS_FIN_WAIT_2
            && dst->state >= CT_DPIF_TCPS_FIN_WAIT_2) {
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_CLOSED, now);
        } else if (src->state >= CT_DPIF_TCPS_CLOSING
                   && dst->state >= CT_DPIF_TCPS_CLOSING) {
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_FIN_WAIT, now);
        } else if (src->state < CT_DPIF_TCPS_ESTABLISHED
                   || dst->state < CT_DPIF_TCPS_ESTABLISHED) {
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_OPENING, now);
        } else if (src->state >= CT_DPIF_TCPS_CLOSING
                   || dst->state >= CT_DPIF_TCPS_CLOSING) {
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_CLOSING, now);
        } else {
            conn_update_expiration(ct, &conn->up, CT_TM_TCP_ESTABLISHED, now);
        }
    } else if ((dst->state < CT_DPIF_TCPS_SYN_SENT
                || dst->state >= CT_DPIF_TCPS_FIN_WAIT_2
                || src->state >= CT_DPIF_TCPS_FIN_WAIT_2)
               && SEQ_GEQ(src->seqhi + MAXACKWINDOW, end)
               /* Within a window forward of the originating packet */
               && SEQ_GEQ(seq, src->seqlo - MAXACKWINDOW)) {
               /* Within a window backward of the originating packet */

        /*
         * This currently handles three situations:
         *  1) Stupid stacks will shotgun SYNs before their peer
         *     replies.
         *  2) When PF catches an already established stream (the
         *     firewall rebooted, the state table was flushed, routes
         *     changed...)
         *  3) Packets get funky immediately after the connection
         *     closes (this should catch Solaris spurious ACK|FINs
         *     that web servers like to spew after a close)
         *
         * This must be a little more careful than the above code
         * since packet floods will also be caught here. We don't
         * update the TTL here to mitigate the damage of a packet
         * flood and so the same code can handle awkward establishment
         * and a loosened connection close.
         * In the establishment case, a correct peer response will
         * validate the connection, go through the normal state code
         * and keep updating the state TTL.
         */

        /* update max window */
        if (src->max_win < win) {
            src->max_win = win;
        }
        /* synchronize sequencing */
        if (SEQ_GT(end, src->seqlo)) {
            src->seqlo = end;
        }
        /* slide the window of what the other end can send */
        if (SEQ_GEQ(ack + (win << sws), dst->seqhi)) {
            dst->seqhi = ack + MAX((win << sws), 1);
        }

        /*
         * Cannot set dst->seqhi here since this could be a shotgunned
         * SYN and not an already established connection.
         */

        if (tcp_flags & TCP_FIN && src->state < CT_DPIF_TCPS_CLOSING) {
            src->state = CT_DPIF_TCPS_CLOSING;
        }

        if (tcp_flags & TCP_RST) {
            src->state = dst->state = CT_DPIF_TCPS_TIME_WAIT;
        }
    } else {
        COVERAGE_INC(conntrack_tcp_seq_chk_failed);
        return CT_UPDATE_INVALID;
    }

    return CT_UPDATE_VALID;
}

static bool
tcp_valid_new(struct dp_packet *pkt)
{
    struct tcp_header *tcp = dp_packet_l4(pkt);
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    if (tcp_invalid_flags(tcp_flags)) {
        return false;
    }

    /* A syn+ack is not allowed to create a connection.  We want to allow
     * totally new connections (syn) or already established, not partially
     * open (syn+ack). */
    if ((tcp_flags & TCP_SYN) && (tcp_flags & TCP_ACK)) {
        return false;
    }

    return true;
}

// 提取 tcp 连接相关的信息(src, dst)并保存
//
// 维护两端的 tcp_peer 结构
//
// ref: comments on tcp_conn_update()
//
//
// 第一个进来的报文不一定是 syn 报文的, 考虑下述情况:
// - ct(force, commit) action
// - ovs 进程重启了, 但是 tcp 连接是一直存在的
static struct conn *
tcp_new_conn(struct conntrack *ct, struct dp_packet *pkt, long long now,
             uint32_t tp_id)
{
    struct conn_tcp* newconn = NULL;
    struct tcp_header *tcp = dp_packet_l4(pkt);
    struct tcp_peer *src, *dst;
    uint16_t tcp_flags = TCP_FLAGS(tcp->tcp_ctl);

    newconn = xzalloc(sizeof *newconn);

    // peer[0] -> peer[1] 是原始方向
    // pkt: 也是原始方向的第一个 syn 报文
    src = &newconn->peer[0];
    dst = &newconn->peer[1];

    src->seqlo = ntohl(get_16aligned_be32(&tcp->tcp_seq));
    src->seqhi = src->seqlo + dp_packet_get_tcp_payload_length(pkt) + 1;

    // 进来的报文不一定非是 SYN 报文的
    if (tcp_flags & TCP_SYN) {
        src->seqhi++; // syn 要占据一个序号
        src->wscale = tcp_get_wscale(tcp);
    } else {
        src->wscale = CT_WSCALE_UNKNOWN;
        dst->wscale = CT_WSCALE_UNKNOWN;
    }
    src->max_win = MAX(ntohs(tcp->tcp_winsz), 1);
    if (src->wscale & CT_WSCALE_MASK) {
        /* Remove scale factor from initial window */
        uint8_t sws = src->wscale & CT_WSCALE_MASK;
        src->max_win = DIV_ROUND_UP((uint32_t) src->max_win, 1 << sws);
    }
    if (tcp_flags & TCP_FIN) {
        src->seqhi++;
    }
    dst->seqhi = 1;			// 这里初始化为这个值, 当第一个 dst->src 的包通过 tcp_conn_update 处理的时候可以平凡的通过么? 可以的, 见后面的 dst->state 的设置, 其会通过特殊路径得到处理. 在哪里会初始化 seqlo 的, 会对 seqhi 做特殊处理, 重新赋值, 同时跳过 ack 号的检查的
    dst->max_win = 1;
    src->state = CT_DPIF_TCPS_SYN_SENT;
    dst->state = CT_DPIF_TCPS_CLOSED;

    newconn->up.tp_id = tp_id;
    conn_init_expiration(ct, &newconn->up, CT_TM_TCP_FIRST_PACKET, now);

    return &newconn->up;
}

static uint8_t
tcp_peer_to_protoinfo_flags(const struct tcp_peer *peer)
{
    uint8_t res = 0;

    if (peer->wscale & CT_WSCALE_FLAG) {
        res |= CT_DPIF_TCPF_WINDOW_SCALE;
    }

    if (peer->wscale & CT_WSCALE_UNKNOWN) {
        res |= CT_DPIF_TCPF_BE_LIBERAL;
    }

    return res;
}

static void
tcp_conn_get_protoinfo(const struct conn *conn_,
                       struct ct_dpif_protoinfo *protoinfo)
{
    const struct conn_tcp *conn = conn_tcp_cast(conn_);

    protoinfo->proto = IPPROTO_TCP;
    protoinfo->tcp.state_orig = conn->peer[0].state;
    protoinfo->tcp.state_reply = conn->peer[1].state;

    protoinfo->tcp.wscale_orig = conn->peer[0].wscale & CT_WSCALE_MASK;
    protoinfo->tcp.wscale_reply = conn->peer[1].wscale & CT_WSCALE_MASK;

    protoinfo->tcp.flags_orig = tcp_peer_to_protoinfo_flags(&conn->peer[0]);
    protoinfo->tcp.flags_reply = tcp_peer_to_protoinfo_flags(&conn->peer[1]);
}

struct ct_l4_proto ct_proto_tcp = {
    .new_conn = tcp_new_conn,
    .valid_new = tcp_valid_new,
    .conn_update = tcp_conn_update,
    .conn_get_protoinfo = tcp_conn_get_protoinfo,
};
