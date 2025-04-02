#ifndef __COMMON_UTILS_H
#define __COMMON_UTILS_H

#include "bits_bpf.h"

#define GET_TPID()  \
uint64_t pid_tgid = bpf_get_current_pid_tgid(); \
uint32_t tid = pid_tgid;                        \
uint32_t pid = pid_tgid >> 32;                


// 定义一个辅助函数来生成 trace ID
static u64 generate_trace_id(void) 
{
  u64 timestamp = bpf_ktime_get_ns(); // 获取当前纳秒级时间戳
  u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; // 获取当前进程 ID

  // 将时间戳和 PID 结合起来形成一个 19 位的数字
  // 注意：这里假设时间戳的低 15 位和 PID 的低 4 位组合在一起
  u64 trace_id = (timestamp % 100000000000ULL) * 10000ULL + (pid % 10000ULL);
  return trace_id;
}

static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk) {
  return (struct tcp_sock *)sk;
}

static __always_inline struct inet_sock *inet_sk(const struct sock *sk) {
  return (struct inet_sock *)sk;
}

static __always_inline void get_tcp_segment_counts(struct sock* skp, u32* packets_in, u32* packets_out) 
{
  BPF_CORE_READ_INTO(packets_in,  tcp_sk(skp), segs_in);
  BPF_CORE_READ_INTO(packets_out, tcp_sk(skp), segs_out);
}

static __always_inline u32 get_sk_cookie(struct sock *sk) 
{
  u64 t = bpf_ktime_get_ns();
  u64 _sk = 0;
  bpf_probe_read_kernel(&_sk, sizeof(_sk), &sk);
  return (u32)(_sk ^ t);
}

static __always_inline u64 __load_word(void *ptr, u32 offset) 
{
  if (bpf_helper_exists(BPF_FUNC_skb_load_bytes)) {
    u32 res = 0;
    bpf_skb_load_bytes(ptr, offset, &res, sizeof(res));
    return bpf_htonl(res);
  }
  return load_word(ptr, offset);
}
  
static __always_inline u64 __load_half(void *ptr, u32 offset) 
{
  if (bpf_helper_exists(BPF_FUNC_skb_load_bytes)) {
    u16 res = 0;
    bpf_skb_load_bytes(ptr, offset, &res, sizeof(res));
    return bpf_htons(res);
  }
  return load_half(ptr, offset);
}
  
static __always_inline u64 __load_byte(void *ptr, u32 offset) 
{
  if (bpf_helper_exists(BPF_FUNC_skb_load_bytes)) {
    u8 res = 0;
    bpf_skb_load_bytes(ptr, offset, &res, sizeof(res));
    return res;
  }
  return load_byte(ptr, offset);
}


#define BLK_SIZE (16)
#define STRINGIFY(a) #a

// The method is used to read the data buffer from the TCP segment data up to `total_size` bytes.
#define READ_INTO_BUFFER(name, total_size, blk_size)                                                                \
    static __always_inline void read_into_buffer_##name(char *buffer, struct __sk_buff *skb, u32 offset) {          \
        const u32 end = (total_size) < (skb->len - offset) ? offset + (total_size) : skb->len;                      \
        unsigned i = 0;                                                                                             \
                                                                                                                    \
    _Pragma( STRINGIFY(unroll(total_size/blk_size)) )                                                               \
        for (; i < ((total_size) / (blk_size)); i++) {                                                              \
          if (offset + (blk_size) - 1 >= end) { break; }                                                            \
          bpf_skb_load_bytes(skb, offset, buffer, (blk_size));                                                      \
          offset += (blk_size);                                                                                     \
          buffer += (blk_size);                                                                                     \
        }                                                                                                           \
        if ((i * (blk_size)) >= total_size) {                                                                       \
          return;                                                                                                   \
        }                                                                                                           \
        /* Calculating the remaining bytes to read. If we have none, then we abort. */                              \
        const s64 left_payload = (s64)end - (s64)offset;                                                            \
        if (left_payload < 1) {                                                                                     \
          return;                                                                                                   \
        }                                                                                                           \
                                                                                                                    \
        /* The maximum that we can read is (blk_size) - 1. Checking (to please the verifier) that we read no more */\
        /* than the allowed max size. */                                                                            \
        const s64 read_size = left_payload < (blk_size) - 1 ? left_payload : (blk_size) - 1;                        \
                                                                                                                    \
        /* Calculating the absolute size from the allocated buffer, that was left empty, again to please the */     \
        /* verifier so it can be assured we are not exceeding the memory limits. */                                 \
        const s64 left_buffer = (s64)(total_size) < (s64)(i*(blk_size)) ? 0 : total_size - i*(blk_size);            \
        if (read_size <= left_buffer) {                                                                             \
          bpf_skb_load_bytes(skb, offset, buffer, read_size);                                                       \
        }                                                                                                           \
        return;                                                                                                     \
    }                                                                                                               \

#endif
