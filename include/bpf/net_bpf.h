#ifndef __NET_DEFS_H__
#define __NET_DEFS_H__

#include "net_utils_bpf.h"

typedef struct {
  u32 netns;
  u16 port;
  
} port_binding_t;

struct packet_key_t {
    u16 eth_type;
    u16 proto;
    u16 port;
};

struct hdr_cursor {
    void *pos;
};

struct ipv4_flow_key {
	u32 saddr;
	u32 daddr;
  u16 sport;
	u16 dport;
};

struct ipv6_flow_key {
	u8 saddr[16];
	u8 daddr[16];
  u16 sport;
	u16 dport;
};

typedef enum
{
    // Connection type
    HOOK_TYPE_CONNECT   = 1,
    HOOK_TYPE_ACCEPT    = 2,

} bpf_hook_type_t;


#define IPHDR_ADDR(skb) BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header)

#define PARSE_ARGS struct hdr_cursor *cursor, void *data_end, struct
#define PARSE_HEADER(type)                                  \
    static bool parse_##type(PARSE_ARGS type **hdr)         \
    {                                                       \
        size_t offset = sizeof(**hdr);                      \
        if (cursor->pos + offset > data_end) {              \
            return false;                                   \
        }                                                   \
        *hdr = cursor->pos;                                 \
        cursor->pos += offset;                              \
        return true;                                        \
    }

PARSE_HEADER(ethhdr);
PARSE_HEADER(iphdr);
PARSE_HEADER(ipv6hdr);
PARSE_HEADER(tcphdr);
PARSE_HEADER(udphdr);

#endif
