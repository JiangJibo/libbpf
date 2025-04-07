//go:build ignore

#include "tcp.maps.h"
#include "tcp.bpf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk) {
    return enter_tcp_connect(ctx, sk, false);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret) {
  return finish_tcp_connect(ctx, ret);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk) {
  return enter_tcp_connect(ctx, sk, false);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_ret, int ret) {
  return finish_tcp_connect(ctx, ret);
}

SEC("kprobe/tcp_finish_connect")
int BPF_KPROBE(tcp_finish_connect, struct sock *sk) {
  return finish_tcp_connect(ctx, 0);
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(tcp_accept_ret, int ret) {
  return finish_tcp_accept(ctx);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
  return handle_tcp_sendmsg(ctx, sk, msg, size);
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(tcp_recvmsg, struct sock *sk) {
  return enter_tcp_connect(ctx, sk, false);
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(tcp_recvmsg_ret, int ret) {
  return handle_tcp_recvmsg(ctx, ret);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk) {
  return close_tcp(ctx, sk);
}
