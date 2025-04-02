#ifndef __BPF_NET_STATS_H
#define __BPF_NET_STATS_H

#include "net_bpf.h"


// 连接统计值
typedef struct 
{
  u64 sent_bytes;
  u64 sent_packets;
  u64 recv_bytes;
  u64 recv_packets;
  u64 timestamp;
  u32 flags;
  u32 pid;

} conn_stats_t;

// tcp统计值
typedef struct 
{
  u64 init_timestamp;
  u32 rtt;
  u32 rtt_var;
  u32 retransmits;
  u16 state_transitions;
  conn_stats_t conn_stats;

} tcp_stats_t;

typedef struct 
{
  u32 tcp_backlog;     // backlog
  u32 max_tcp_backlog; // max_backlog
  u64 bytes_acked;     // 已确认的字节数
  u64 bytes_received;  // 已接收的字节数

  u32 snd_cwnd;       // 拥塞窗口大小
  u32 rcv_wnd;        // 接收窗口大小
  u32 snd_ssthresh;   // 慢启动阈值
  u32 sndbuf;         // 发送缓冲区大小(byte)
  u32 sk_wmem_queued; // 已使用的发送缓冲区
  u32 fastRe;         // 快速重传次数
  u32 timeout;        // 超时重传次数

  u64 init_timestamp; // 建立连接时间戳
  u64 duration;       // 连接已建立时长

} tcp_extra_stats_t;

typedef struct 
{
  conn_tuple_t tup;
  tcp_stats_t  tcp_stats;

} tcp_conn_t;



#define CONN_ADD_EXTRA_INFO(conn)                                          \
if (true) {                                                                \
    struct tcp_sock *tp = tcp_sk(sk);                                      \
    conn->duration = bpf_ktime_get_ns()  - conn->init_timestamp;           \
    conn->bytes_acked = BPF_CORE_READ(tp, bytes_acked);                    \
    conn->bytes_received = BPF_CORE_READ(tp, bytes_received);              \
    conn->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);                          \
    conn->rcv_wnd = BPF_CORE_READ(tp, rcv_wnd);                            \
    conn->snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);                  \
    conn->sndbuf = BPF_CORE_READ(sk, sk_sndbuf);                           \
    conn->sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);              \
    conn->tcp_backlog = BPF_CORE_READ(sk, sk_ack_backlog);                 \
    conn->max_tcp_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);         \
}

#endif