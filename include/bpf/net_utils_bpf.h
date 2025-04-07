#ifndef __NETNS_H
#define __NETNS_H

#include "map_bpf.h"
#include "utils_bpf.h"
#include "net_def.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohll(x)			__builtin_bswap64(x)
# define __bpf_htonll(x)			__builtin_bswap64(x)
# define __bpf_constant_ntohll(x)	___bpf_swab64(x)
# define __bpf_constant_htonll(x)	___bpf_swab64(x)

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohll(x)			(x)
# define __bpf_htonll(x)			(x)
# define __bpf_constant_ntohll(x)	(x)
# define __bpf_constant_htonll(x)	(x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif


#define bpf_htonll(x)				\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_htonll(x) : __bpf_htonll(x))
#define bpf_ntohll(x)				\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_ntohll(x) : __bpf_ntohll(x))



// 连接信息
typedef struct 
{
  union {
    u32 saddr_v4;
    u8  saddr_v6[16];
  };
  union {
    u32 daddr_v4;
    u8  daddr_v6[16];
  };
  u8    af; // AF_INET or AF_INET6
  u8    direction;
  u16   dport;
  u16   sport;
  u32   netns;
  
} conn_tuple_t;

// skb_info_t embeds a conn_tuple_t extracted from the skb object as well as
// some ancillary data such as the data offset (the byte offset pointing to
// where the application payload begins) and the TCP flags if applicable.
// This struct is populated by calling `read_conn_tuple_skb` from a program type
// that manipulates a `__sk_buff` object.
typedef struct 
{
  u32 data_off;
  u32 data_end;
  u32 tcp_seq;
  u8  tcp_flags;

} skb_info_t;

typedef struct 
{
  u8 layer_api;
  u8 layer_application;
  u8 layer_encryption;
  u8 flags;
} protocol_stack_t;


#define sk_net __sk_common.skc_net

struct net___old {
  unsigned int proc_inum;
};

struct sock_common___old {
  struct net *skc_net;
};

struct sock___old {
  struct sock_common___old __sk_common;
};

static __always_inline u32 get_netns_from_sock(struct sock* sk) 
{
  u32 net_ns_inum = 0;
  struct net *ns = NULL;
  if (bpf_core_field_exists(sk->sk_net.net) ||
      bpf_core_field_exists(((struct sock___old*)sk)->sk_net->ns)) {
      BPF_CORE_READ_INTO(&ns, sk, sk_net);
      BPF_CORE_READ_INTO(&net_ns_inum, ns, ns.inum);
  } else if (bpf_core_field_exists(((struct net___old*)ns)->proc_inum)) {
      BPF_CORE_READ_INTO(&ns, (struct sock___old*)sk, sk_net);
      BPF_CORE_READ_INTO(&net_ns_inum, (struct net___old*)ns, proc_inum);
  }
  return net_ns_inum;
}

static __always_inline bool is_tcp_termination(skb_info_t *skb_info) {
  return skb_info->tcp_flags & (TCPHDR_FIN | TCPHDR_RST);
}

static __always_inline bool is_tcp_ack(skb_info_t *skb_info) {
  return skb_info->tcp_flags == TCPHDR_ACK;
}

static __always_inline void read_ipv6_skb(struct __sk_buff *skb, u64 off, u64 *addr_l, u64 *addr_h) 
{
  *addr_h |= (u64)__load_word(skb, off) << 32;
  *addr_h |= (u64)__load_word(skb, off + 4);
  *addr_h = bpf_ntohll(*addr_h);

  *addr_l |= (u64)__load_word(skb, off + 8) << 32;
  *addr_l |= (u64)__load_word(skb, off + 12);
  *addr_l = bpf_ntohll(*addr_l);
}

static __always_inline void read_ipv4_skb(struct __sk_buff *skb, u64 off, u32 *addr) 
{
  *addr = __load_word(skb, off);
  *addr = bpf_ntohll(*addr) >> 32;
}


static __always_inline u64 read_conn_tuple_skb(struct __sk_buff *skb, skb_info_t *info, conn_tuple_t *tup) {
  bpf_memset(info, 0, sizeof(skb_info_t));
  info->data_off = ETH_HLEN;

  u16 l3_proto = __load_half(skb, offsetof(struct ethhdr, h_proto));
  info->data_end = ETH_HLEN;
  u8 l4_proto = 0;
  switch (l3_proto) {
  case ETH_P_IP:
  {
      u8 ipv4_hdr_len = (__load_byte(skb, info->data_off) & 0x0f) << 2;
      info->data_end += __load_half(skb, info->data_off + offsetof(struct iphdr, tot_len));
      if (ipv4_hdr_len < sizeof(struct iphdr)) {
          return 0;
      }
      l4_proto = __load_byte(skb, info->data_off + offsetof(struct iphdr, protocol));
      read_ipv4_skb(skb, info->data_off + offsetof(struct iphdr, saddr), &tup->saddr_v4);
      read_ipv4_skb(skb, info->data_off + offsetof(struct iphdr, daddr), &tup->daddr_v4);
      info->data_off += ipv4_hdr_len;
      break;
  }
  case ETH_P_IPV6:
      info->data_end += sizeof(struct ipv6hdr) + __load_half(skb, info->data_off + offsetof(struct ipv6hdr, payload_len));
      l4_proto = __load_byte(skb, info->data_off + offsetof(struct ipv6hdr, nexthdr));
      u64* saddr_h = (u64*)(&tup->saddr_v6[8]);
      u64* saddr_l = (u64*)(&tup->saddr_v6[0]);
      u64* daddr_h = (u64*)(&tup->daddr_v6[8]);
      u64* daddr_l = (u64*)(&tup->daddr_v6[0]);
      read_ipv6_skb(skb, info->data_off + offsetof(struct ipv6hdr, saddr), saddr_l, saddr_h);
      read_ipv6_skb(skb, info->data_off + offsetof(struct ipv6hdr, daddr), daddr_l, daddr_h);
      info->data_off += sizeof(struct ipv6hdr);
      break;
  default:
      return 0;
  }

  switch (l4_proto) {
  case IPPROTO_UDP:
      tup->sport = __load_half(skb, info->data_off + offsetof(struct udphdr, source));
      tup->dport = __load_half(skb, info->data_off + offsetof(struct udphdr, dest));
      info->data_off += sizeof(struct udphdr);
      break;
  case IPPROTO_TCP:
      tup->sport = __load_half(skb, info->data_off + offsetof(struct tcphdr, source));
      tup->dport = __load_half(skb, info->data_off + offsetof(struct tcphdr, dest));

      info->tcp_seq   = __load_word(skb, info->data_off + offsetof(struct tcphdr, seq));
      info->tcp_flags = __load_byte(skb, info->data_off + TCP_FLAGS_OFFSET);
      info->data_off += ((__load_byte(skb, info->data_off + offsetof(struct tcphdr, ack_seq) + 4) & 0xF0) >> 4) * 4;
      break;
  default:
      return 0;
  }

  if ((info->data_end - info->data_off) < 0) {
      return 0;
  }
  return 1;
}

#endif
