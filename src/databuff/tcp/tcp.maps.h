
#include "bpf.h"
#include "trace_bpf.h"

#define MAX_ENTRIES 8192

// 定义 PROG_ARRAY map
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 10); // 最多支持 10 个程序
  __type(key, u32);
  __type(value, u32);
} prog_array_map SEC(".maps");


BPF_HASH_MAP  (connect_map, u32, struct sock_info_t, MAX_ENTRIES)
BPF_HASH_MAP  (tcp_stats, conn_tuple_t, tcp_stats_t, MAX_ENTRIES)
BPF_HASH_MAP  (connect_sks, u64, u32, MAX_ENTRIES)  // 主动connect的套接字
BPF_HASH_MAP  (accept_sks,  u64, u32, MAX_ENTRIES)  // 被动accept的套接字

#ifdef IS_NEW_KERNEL
BPF_CY_RINGBUF(tcp_conn_stats, 1 << 24) // 连接信息
BPF_CY_RINGBUF(spans, 1 << 24)  // 定义 span ringbuf
#else
BPF_PERF_EVENT_ARRAY_MAP(tcp_conn_stats, u32, 10240)
BPF_PERF_EVENT_ARRAY_MAP(spans, u32, 10240)
#endif

static __always_inline tcp_stats_t* get_tcp_stats(conn_tuple_t *t, bool create) {
  tcp_stats_t *cs = bpf_map_lookup_elem(&tcp_stats, t);
  if (cs) {
      return cs;
  }
  if (!create) {
    return NULL;
  }

  tcp_stats_t empty = {0};
  bpf_memset(&empty, 0, sizeof(tcp_stats_t));
  //empty.conn_stats.cookie = get_sk_cookie(sk);

  bpf_map_update_elem(&tcp_stats, t, &empty, BPF_NOEXIST);
  return bpf_map_lookup_elem(&tcp_stats, t);
}

static __always_inline tcp_stats_t* update_tcp_stats(conn_tuple_t *t, tcp_stats_t* stats) {
  // initialize-if-no-exist the connection state, and load it
  tcp_stats_t* val = get_tcp_stats(t, true);
  if (val == NULL) {
    return NULL;
  }

  if (stats->rtt > 0) {
    val->rtt     = stats->rtt >> 3;
    val->rtt_var = stats->rtt_var >> 2;
  }

  if (stats->state_transitions > 0) {
    val->state_transitions |= stats->state_transitions;
  }
  return val;
}


static __always_inline void update_conn_state(conn_tuple_t *t, conn_stats_t *stats, u64 sent_bytes, u64 recv_bytes) {
  if (stats->flags & CONN_ASSURED) {
      return;
  }
  if (stats->recv_bytes == 0 && sent_bytes > 0) {
      stats->flags |= CONN_L_INIT;
      return;
  }
  if (stats->sent_bytes == 0 && recv_bytes > 0) {
      stats->flags |= CONN_R_INIT;
      return;
  }
  // If a three-way "handshake" was established, we mark the connection as assured
  if ((stats->flags & CONN_L_INIT && stats->recv_bytes > 0 && sent_bytes > 0) ||
      (stats->flags & CONN_R_INIT && stats->sent_bytes > 0 && recv_bytes > 0)) {
      stats->flags |= CONN_ASSURED;
  }
}

static __always_inline tcp_stats_t* update_conn_stats(conn_tuple_t *t, struct sock *sk, u64 ts,
    u64 sent_bytes,  u64 recv_bytes, 
    u32 packets_out, u32 packets_in, packet_count_increment_t segs_type) 
{
  tcp_stats_t *stats = get_tcp_stats(t, false);
  if (!stats) {
      return NULL;
  }
  conn_stats_t* val = &stats->conn_stats;

  u32 rtt = 0, rtt_var = 0;
  u64 retran = 0;
  BPF_CORE_READ_INTO(&rtt, tcp_sk(sk), srtt_us);
  BPF_CORE_READ_INTO(&rtt_var, tcp_sk(sk), mdev_us);
  BPF_CORE_READ_INTO(&retran,  tcp_sk(sk), total_retrans);

  if (rtt > 0) {
    stats->rtt     = rtt >> 3;
    stats->rtt_var = rtt_var >> 2;
  }
  stats->retransmits = retran;
  
  update_conn_state(t, val, sent_bytes, recv_bytes);
  if (sent_bytes) {
    __sync_fetch_and_add(&val->sent_bytes, sent_bytes);
  }
  if (recv_bytes) {
      __sync_fetch_and_add(&val->recv_bytes, recv_bytes);
  }
  if (packets_in) {
      if (segs_type == PACKET_COUNT_INCREMENT) {
          __sync_fetch_and_add(&val->recv_packets, packets_in);
      } else if (segs_type == PACKET_COUNT_ABSOLUTE) {
          val->recv_packets = packets_in;
      }
  }
  if (packets_out) {
      if (segs_type == PACKET_COUNT_INCREMENT) {
          __sync_fetch_and_add(&val->sent_packets, packets_out);
      } else if (segs_type == PACKET_COUNT_ABSOLUTE) {
          val->sent_packets = packets_out;
      }
  }
  val->timestamp = ts;
  
  return stats;
}
