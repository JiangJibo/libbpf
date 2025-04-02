package tcp

import "github.com/cilium/ebpf"

type TcpObjects = tcpObjects

type ObjWithBss struct {
	TcpObjects
	Bss *ebpf.Map `ebpf:".bss"`
}

// 定义一个枚举类型
type HOOK_TYPE uint16

const (
	CONNECT HOOK_TYPE = iota + 1
	ACCEPT
)

const (
	CONN_DIRECTION_UNKNOWN = iota
	CONN_DIRECTION_INCOMING
	CONN_DIRECTION_OUTGOING
	CONN_DIRECTION_LOCAL
)

const (
	NS_PER_SECOND = uint64(1000000000)
	NS_PER_MS     = uint64(1000000)
)
