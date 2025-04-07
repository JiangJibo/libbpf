#ifndef __TRACE_BPF_H
#define __TRACE_BPF_H

#include "net_stats.h"
#include "utils_bpf.h"

#define TASK_COMM_LEN 16


struct span_parent_t 
{
  u64 trace_id;
  u64 span_id;
};

struct span_base_t
{
  struct span_parent_t parent;
  u64  span_id;
  u64  span_start_time_ns;   // 调用开始时间
  u64  span_end_time_ns;     // 调用结束时间
  u32  pid;                  // 进程 ID
  char comm[TASK_COMM_LEN];
};

typedef struct 
{
  struct span_base_t span_base;
  conn_tuple_t flow;
  u16 hook;
  
} tcp_span_t;

struct sock_info_t 
{
  u64 start_time;
  u64 sk;         // struct sock*
};


static inline void fill_span_base(struct span_base_t* span, struct span_parent_t* parent)
{
  if (parent) {
    span->parent = *parent;
  } else {
    span->parent.trace_id = span->span_id;
  }
  span->span_end_time_ns = bpf_ktime_get_ns();
}

#ifdef IS_NEW_KERNEL
#define create_span(map, type)      \
  type *span = bpf_ringbuf_reserve(&map, sizeof(type), 0);      

#define add_span(span, map, type)   \
  bpf_ringbuf_submit(span, 0);

#else
#define create_span(map, type)      \
  type span_obj = {0};              \
  type* span = &span_obj;

#define add_span(span, map, type)   \
  bpf_perf_event_output(ctx, &map, BPF_F_CURRENT_CPU, span, sizeof(type));

#endif

#define start_new_span(map, type)                               \
  create_span(map, type)                                        \
  if (!span) { return 0; }                                      \
  span->span_base.pid = bpf_get_current_pid_tgid() >> 32;       \
  span->span_base.span_id = generate_trace_id();                \
  bpf_get_current_comm(&span->span_base.comm, sizeof(span->span_base.comm));

#define submit_span(map, type, parent, fill)                    \
  start_new_span(map, type)                                     \
  if (!span) { return 0; }                                      \
  fill_span_base(&span->span_base, parent);                     \
  fill;                                                         \
  add_span(span, map, type);

#define SPAN_SPORT  span->flow.sport
#define SPAN_DPORT  span->flow.dport


// 使用 ring buffer
#ifdef IS_NEW_KERNEL
#define submit_conn(map, type, fill)                            \
  type* conn = bpf_ringbuf_reserve(&map, sizeof(type), 0);      \
  if (!conn) { return 0;}                                       \
  fill;                                                         \
  bpf_ringbuf_submit(conn, 0);  

#else
#define submit_conn(map, type, fill)                        \
  type conn_obj = {0};          \
  type* conn = &conn_obj;       \
  fill;                         \
  bpf_perf_event_output(ctx, &map, BPF_F_CURRENT_CPU, conn, sizeof(type));
#endif

#endif
