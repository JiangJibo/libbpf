#ifndef __NET_DEF_H
#define __NET_DEF_H


#ifndef AF_INET
#define AF_INET     2
#endif

#ifndef AF_INET6
#define AF_INET6    10
#endif

#ifndef ETH_HLEN
#define ETH_HLEN    14 /* Total octets in header. */
#endif

#ifndef ETH_P_IP
#define ETH_P_IP    0x0800 /* Internet Protocol packet */
#define ETH_P_IPV6  0x86DD /* IPv6 over bluebook */
#endif

#ifndef TCP_FLAGS_OFFSET
#define TCP_FLAGS_OFFSET 13
#endif

#ifndef TCPHDR_FIN
#define TCPHDR_FIN 0x01
#endif

#ifndef TCPHDR_RST
#define TCPHDR_RST 0x04
#endif

#ifndef TCPHDR_ACK
#define TCPHDR_ACK 0x10
#endif


typedef enum
{
    CONN_DIRECTION_UNKNOWN  = 0,
    CONN_DIRECTION_INCOMING = 1,
    CONN_DIRECTION_OUTGOING = 2,
} conn_direction_t;

typedef enum
{
    PACKET_COUNT_NONE      = 0,
    PACKET_COUNT_ABSOLUTE  = 1,
    PACKET_COUNT_INCREMENT = 2,
} packet_count_increment_t;

typedef enum
{
    CONN_L_INIT  = 1 << 0, // initial/first message sent
    CONN_R_INIT  = 1 << 1, // reply received for initial message from remote
    CONN_ASSURED = 1 << 2 // "3-way handshake" complete, i.e. response to initial reply sent
} conn_flags_t;


#define CONN_DIRECTION_MASK 0b11

typedef enum
{
    CONN_TYPE_UDP = 0,
    CONN_TYPE_TCP = 1,

    CONN_V4 = 0 << 1,
    CONN_V6 = 1 << 1,
} metadata_mask_t;

typedef enum 
{
  LAYER_UNKNOWN,
  LAYER_API,
  LAYER_APPLICATION,
  LAYER_ENCRYPTION,
} __attribute__ ((packed)) protocol_layer_t;

// The maximum number of protocols per stack layer
#define MAX_ENTRIES_PER_LAYER 255

#define LAYER_API_BIT         (1 << 13)
#define LAYER_APPLICATION_BIT (1 << 14)
#define LAYER_ENCRYPTION_BIT  (1 << 15)

#define LAYER_API_MAX         (LAYER_API_BIT + MAX_ENTRIES_PER_LAYER)
#define LAYER_APPLICATION_MAX (LAYER_APPLICATION_BIT + MAX_ENTRIES_PER_LAYER)
#define LAYER_ENCRYPTION_MAX  (LAYER_ENCRYPTION_BIT + MAX_ENTRIES_PER_LAYER)

#define FLAG_FULLY_CLASSIFIED       1 << 0
#define FLAG_USM_ENABLED            1 << 1
#define FLAG_NPM_ENABLED            1 << 2
#define FLAG_TCP_CLOSE_DELETION     1 << 3
#define FLAG_SOCKET_FILTER_DELETION 1 << 4
#define FLAG_SERVER_SIDE            1 << 5
#define FLAG_CLIENT_SIDE            1 << 6

// The enum below represents all different protocols we're able to
// classify. Entries are segmented such that it is possible to infer the
// protocol layer from its value. A `protocol_t` value can be represented by
// 16-bits which are encoded like the following:
//
// * Bits 0-7   : Represent the protocol number within a given layer
// * Bits 8-12  : Unused
// * Bits 13-15 : Designates the protocol layer
typedef enum 
{
    PROTOCOL_UNKNOWN = 0,

    __LAYER_API_MIN = LAYER_API_BIT,
    // Add API protocols here (eg. gRPC)
    PROTOCOL_GRPC,
    __LAYER_API_MAX = LAYER_API_MAX,

    __LAYER_APPLICATION_MIN = LAYER_APPLICATION_BIT,
    //  Add application protocols below (eg. HTTP)
    PROTOCOL_HTTP,
    PROTOCOL_HTTP2,
    PROTOCOL_KAFKA,
    PROTOCOL_MONGO,
    PROTOCOL_POSTGRES,
    PROTOCOL_AMQP,
    PROTOCOL_REDIS,
    PROTOCOL_MYSQL,
    __LAYER_APPLICATION_MAX = LAYER_APPLICATION_MAX,

    __LAYER_ENCRYPTION_MIN = LAYER_ENCRYPTION_BIT,
    //  Add encryption protocols below (eg. TLS)
    PROTOCOL_TLS,
    __LAYER_ENCRYPTION_MAX = LAYER_ENCRYPTION_MAX,
} __attribute__ ((packed)) protocol_t;

#endif
