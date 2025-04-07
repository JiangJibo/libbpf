#include "bpf/bpf_helper_defs.h"
#include "bpf/bpf_helpers.h"
#include "bpf/net_stats.h"
#include "bpf/net_utils_bpf.h"
#include "bpf/utils_bpf.h"
volatile u32  filter_pid = 0;
volatile u32  extra_conn_info = 1;
volatile char filter_process[16] = {0};


static __always_inline bool need_hook() 
{
  uint64_t pid_tgid = bpf_get_current_pid_tgid();
  uint32_t pid = pid_tgid >> 32;
  uint32_t tid = pid_tgid;

  if (tid == 0 || pid == 0)
    return false;
  if (filter_pid && pid != filter_pid)  // 过滤PID
    return false;

  if (filter_process[0] != 0) { // 过滤进程名
    char pname[16] = {0};
    bpf_get_current_comm(&pname, sizeof(pname));
    return !bpf_memcmp(&pname, (void*)&filter_process, sizeof(pname));
  }

  return true;
}

static __always_inline void get_net4_address(conn_tuple_t* flow, struct sock* sk)
{
  BPF_CORE_READ_INTO(&flow->saddr_v4, sk, __sk_common.skc_rcv_saddr);
  BPF_CORE_READ_INTO(&flow->daddr_v4, sk, __sk_common.skc_daddr);
  BPF_CORE_READ_INTO(&flow->dport,    sk, __sk_common.skc_dport);
  BPF_CORE_READ_INTO(&flow->sport,    sk, __sk_common.skc_num);

  flow->sport = bpf_htons(flow->sport);
}

static __always_inline void get_net6_address(conn_tuple_t* flow, struct sock* sk)
{
  BPF_CORE_READ_INTO(&flow->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
  BPF_CORE_READ_INTO(&flow->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
  BPF_CORE_READ_INTO(&flow->dport,    sk, __sk_common.skc_dport);
  BPF_CORE_READ_INTO(&flow->sport,    sk, __sk_common.skc_num);
  
  flow->sport = bpf_htons(flow->sport);
}

static __always_inline void get_address(conn_tuple_t* t, struct sock* sk)
{
  u8 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  int ip_ver = family == AF_INET ? 4 : 6;
  t->af      = family;
  t->netns   = get_netns_from_sock(sk);

  if (ip_ver == 4) {
    get_net4_address(t, sk);
  } else {
    get_net6_address(t, sk);
  }
}

static __always_inline tcp_stats_t* handle_tcp_stats(conn_tuple_t* t, struct sock* sk, u8 state) {
  u32 rtt = 0, rtt_var = 0;
  BPF_CORE_READ_INTO(&rtt,     tcp_sk(sk), srtt_us);
  BPF_CORE_READ_INTO(&rtt_var, tcp_sk(sk), mdev_us);

  tcp_stats_t stats = { .rtt = rtt, .rtt_var = rtt_var };
  if (state > 0) {
    stats.state_transitions = (1 << state);
  }
  return update_tcp_stats(t, &stats);
}

static __always_inline int trace_v4(struct pt_regs *ctx, u64 start_time, struct sock *sk) 
{
  submit_span(spans, tcp_span_t, NULL, {
    span->flow.af = AF_INET;
    span->flow.netns = get_netns_from_sock(sk);
    span->hook = HOOK_TYPE_CONNECT;
    span->span_base.span_start_time_ns = start_time;
    get_net4_address(&span->flow, sk);
  })
  return 0;
}

static __always_inline int trace_v6(struct pt_regs *ctx, u64 start_time, struct sock *sk) 
{
  submit_span(spans, tcp_span_t, NULL, {
    span->flow.af = AF_INET6;
    span->flow.netns = get_netns_from_sock(sk);
    span->hook = HOOK_TYPE_CONNECT;
    span->span_base.span_start_time_ns = start_time;
    get_net6_address(&span->flow, sk);
  })
  return 0;
}

static __always_inline void trace(struct pt_regs *ctx, u64 start_time, struct sock *sk) 
{
  u8 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family == AF_INET) {
    trace_v4(ctx, start_time, sk);
  } else {
    trace_v6(ctx, start_time, sk);
  }
}

// kprobe/tcp_vX_connect 
static __always_inline int enter_tcp_connect(struct pt_regs *ctx, struct sock *sk, bool use_pid) 
{
  if (!need_hook())
    return 0;

  GET_TPID();

  struct sock_info_t sock_info = {bpf_ktime_get_ns(), (u64)sk};
  if (use_pid) {
    bpf_map_update_elem(&connect_map, &pid, &sock_info, BPF_ANY);
  } else {
    bpf_map_update_elem(&connect_map, &tid, &sock_info, BPF_ANY);
  }
  return 0;
}

// kprobe/tcp_connect_finish
static __always_inline int finish_tcp_connect(struct pt_regs *ctx, int ret) 
{
  if (!need_hook())
    return 0;

  GET_TPID();
  struct sock_info_t *sock_info;
  sock_info = bpf_map_lookup_elem(&connect_map, &tid);
  if (!sock_info) {
    return 0;
  }
  if (ret)  // 连接失败
    goto end;

  struct sock* sk = (struct sock*)sock_info->sk;
  trace(ctx, sock_info->start_time, sk);

  conn_tuple_t t = {};
  get_address(&t, sk);

  tcp_stats_t* tstat = handle_tcp_stats(&t, sk, TCP_ESTABLISHED);
  if (tstat) {
    tstat->init_timestamp = bpf_ktime_get_ns();
  }

  u32 value = 1;
  bpf_map_update_elem(&connect_sks, &sk, &value, BPF_ANY);
  log_debug("tcp_connect_finish: #%u %u -> %u", tid, bpf_htons(t.sport), bpf_htons(t.dport));

end:
  bpf_map_delete_elem(&connect_map, &tid);
  return 0;
}

static __always_inline int finish_tcp_accept(struct pt_regs *ctx) 
{
  struct sock* sk = (struct sock*)PT_REGS_RC(ctx);  // accept成功后返回的套接字
  if (!sk)
    return 0;
  if (!need_hook())
    return 0;

  u64 now = bpf_ktime_get_ns();
  conn_tuple_t t = {};
  
  submit_span(spans, tcp_span_t, NULL, {
    span->hook = HOOK_TYPE_ACCEPT;
    span->span_base.span_start_time_ns = now;
    get_address(&span->flow, sk);
    bpf_memcpy(&t, &span->flow, sizeof(conn_tuple_t));

    tcp_stats_t* tstat = handle_tcp_stats(&t, sk, TCP_ESTABLISHED);
    if (tstat) {
      tstat->init_timestamp = bpf_ktime_get_ns();
    }
    log_debug("tcp_accept_finish: #%u %u -> %u", span->span_base.pid, bpf_htons(SPAN_SPORT), bpf_htons(SPAN_DPORT));
  })
  
  u32 value = 1;
  bpf_map_update_elem(&accept_sks, &sk, &value, BPF_ANY);

  return 0;
}


static __always_inline int sumbit_tcp_stats(struct pt_regs *ctx, struct sock *sk, conn_tuple_t *t)
{
  tcp_stats_t* tcp_stat = get_tcp_stats(t, false);
  if (tcp_stat) {
    GET_TPID();

    submit_conn(tcp_conn_stats, tcp_conn_t, {
      if (sk) {
        u64 retran = 0;
        u32 rtt = 0;
        u32 rtt_var = 0;

        BPF_CORE_READ_INTO(&retran,  tcp_sk(sk), total_retrans);
        BPF_CORE_READ_INTO(&rtt,     tcp_sk(sk), srtt_us);
        BPF_CORE_READ_INTO(&rtt_var, tcp_sk(sk), mdev_us);

        if (rtt > 0) {
          tcp_stat->rtt     = rtt >> 3;
          tcp_stat->rtt_var = rtt_var >> 2;
        }
        conn->tcp_stats.retransmits = retran;

        tcp_extra_stats_t extra_stats;
        CONN_ADD_EXTRA_INFO((&extra_stats));
      }

      conn->tcp_stats = *tcp_stat;
      conn->tcp_stats.conn_stats.pid = pid;
      conn->tup = *t;

      if (bpf_map_lookup_elem(&accept_sks, &sk)) {
        conn->tup.direction = CONN_DIRECTION_INCOMING;
      } else if (bpf_map_lookup_elem(&connect_sks, &sk)) { // connect socket
        conn->tup.direction = CONN_DIRECTION_OUTGOING;
      } else {
        conn->tup.direction = CONN_DIRECTION_UNKNOWN;
      }
    })
  }
  return 0;
}

static __always_inline int sumbit_tcp_stats_2(struct pt_regs *ctx, conn_tuple_t *t, struct sock *sk, tcp_stats_t *tcp_stat)
{
  GET_TPID();

  submit_conn(tcp_conn_stats, tcp_conn_t, {
    conn->tcp_stats = *tcp_stat;
    conn->tcp_stats.conn_stats.pid = pid;
    conn->tup = *t;

    if (bpf_map_lookup_elem(&accept_sks, &sk)) {
      conn->tup.direction = CONN_DIRECTION_INCOMING;
    } else if (bpf_map_lookup_elem(&connect_sks, &sk)) { // connect socket
      conn->tup.direction = CONN_DIRECTION_OUTGOING;
    } else {
      conn->tup.direction = CONN_DIRECTION_UNKNOWN;
    }
  }) 
  return 0;
}

static __always_inline int handle_tcp_msg(struct pt_regs *ctx, struct sock *sk, bool is_recv, size_t size) 
{
  if (!need_hook())
    return 0;

  conn_tuple_t t = {};
  get_address(&t, sk);

  u32 packets_in  = 0;
  u32 packets_out = 0;
  u32 recv_size   = 0;
  u32 send_size   = 0;

  get_tcp_segment_counts(sk, &packets_in, &packets_out);

  if (is_recv) {
    recv_size = size;
  } else {
    send_size = size;
  }

  u64 ts = bpf_ktime_get_ns();
  tcp_stats_t *tcp_stat = update_conn_stats(&t, sk, ts, send_size, recv_size, packets_out, packets_in, PACKET_COUNT_ABSOLUTE);

  if (tcp_stat) {
    sumbit_tcp_stats_2(ctx, &t, sk, tcp_stat);
  }
  return 0;
}


static __always_inline int handle_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) 
{
  if (!need_hook())
    return 0;

  return handle_tcp_msg(ctx, sk, false, size);
}

static __always_inline int handle_tcp_recvmsg(struct pt_regs *ctx, int ret) 
{
  if (!need_hook())
    return 0;

  GET_TPID();
  struct sock_info_t* sock_info;

  sock_info = bpf_map_lookup_elem(&connect_map, &tid);
  if (!sock_info) {
    return 0;
  }

  if (ret < 0)  // 发送失败
    goto end;

  struct sock* sk = (struct sock*)sock_info->sk;
  handle_tcp_msg(ctx, sk, true, ret);

end:
  bpf_map_delete_elem(&connect_map, &tid);
  return 0;
}

static __always_inline int close_tcp(struct pt_regs *ctx, struct sock *sk) 
{
  if (!need_hook())
    return 0;

  GET_TPID();
  conn_tuple_t t = {};
  get_address(&t, sk);

  log_debug("close socket: #%u %u -> %u", tid, bpf_htons(t.sport), bpf_htons(t.dport));

  sumbit_tcp_stats(ctx, sk, &t);

  bpf_map_delete_elem(&connect_map, &tid);  // TODO: 
  bpf_map_delete_elem(&tcp_stats, &t);
  bpf_map_delete_elem(&connect_sks, &sk);
  bpf_map_delete_elem(&accept_sks, &sk);

  return 0;
}
