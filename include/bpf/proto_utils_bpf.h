#ifndef __PROTO_UTILS_BPF_
#define __PROTO_UTILS_BPF_
#include "net_utils_bpf.h"

static __always_inline protocol_layer_t get_protocol_layer(protocol_t proto) {
    u16 layer_bit = proto&(LAYER_API_BIT|LAYER_APPLICATION_BIT|LAYER_ENCRYPTION_BIT);

    switch(layer_bit) {
    case LAYER_API_BIT:
        return LAYER_API;
    case LAYER_APPLICATION_BIT:
        return LAYER_APPLICATION;
    case LAYER_ENCRYPTION_BIT:
        return LAYER_ENCRYPTION;
    }

    return LAYER_UNKNOWN;
}

// 设置应用协议
static __always_inline void set_protocol(protocol_stack_t *stack, protocol_t proto) {
    if (!stack || proto == PROTOCOL_UNKNOWN) {
        return;
    }

    protocol_layer_t layer = get_protocol_layer(proto);
    if (!layer) {
        return;
    }

    u8 proto_num = (u8)proto;
    switch(layer) {
    case LAYER_API:
        stack->layer_api = proto_num;
        return;
    case LAYER_APPLICATION:
        stack->layer_application = proto_num;
        return;
    case LAYER_ENCRYPTION:
        stack->layer_encryption = proto_num;
        return;
    default:
        return;
    }
}

static __always_inline protocol_t get_protocol_from_stack(protocol_stack_t *stack, protocol_layer_t layer) {
    if (!stack) {
        return PROTOCOL_UNKNOWN;
    }

    u16 proto_num = 0;
    u16 layer_bit = 0;
    switch(layer) {
    case LAYER_API:
        proto_num = stack->layer_api;
        layer_bit = LAYER_API_BIT;
        break;
    case LAYER_APPLICATION:
        proto_num = stack->layer_application;
        layer_bit = LAYER_APPLICATION_BIT;
        break;
    case LAYER_ENCRYPTION:
        proto_num = stack->layer_encryption;
        layer_bit = LAYER_ENCRYPTION_BIT;
        break;
    default:
        break;
    }

    if (!proto_num) {
        return PROTOCOL_UNKNOWN;
    }
    return proto_num | layer_bit;
}

static __always_inline bool is_protocol_layer_known(protocol_stack_t *stack, protocol_layer_t layer) {
    if (!stack) {
        return false;
    }
    protocol_t proto = get_protocol_from_stack(stack, layer);
    return proto != PROTOCOL_UNKNOWN;
}

static __always_inline void set_protocol_flag(protocol_stack_t *stack, u8 flag) {
    if (!stack) {
        return;
    }
    stack->flags |= flag;
}

#endif
