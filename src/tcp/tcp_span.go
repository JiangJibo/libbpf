package tcp

import (
	"fmt"

	"github.com/cilium/ebpf"
)

const (
	TASK_COMM_LEN = 16 // 假设 TASK_COMM_LEN 的值为 16
	AF_INET       = 2  // IPv4
	AF_INET6      = 10 // IPv6
)

// span_parent_t 结构体
type SpanParent struct {
	TraceID uint64
	SpanID  uint64
}

// span_base_t 结构体
type SpanBase struct {
	Parent          SpanParent // 嵌套的 span_parent_t
	SpanID          uint64
	SpanStartTimeNS uint64 // 调用开始时间
	SpanEndTimeNS   uint64 // 调用结束时间
	PID             uint32 // 进程 ID
	Comm            [TASK_COMM_LEN]byte
}

// tcp_span_t 结构体
// 该结构必须与tcp.bpf.h中定义的结构一致
type TCPSpan struct {
	SpanBase // 嵌套的 span_base_t
	ConnTuple
	Hook uint16
}

// 获取源地址
func (t *TCPSpan) Duration() int64 {
	return int64(t.SpanBase.SpanEndTimeNS - t.SpanBase.SpanStartTimeNS)
}

func (t *TCPSpan) Kind() string {
	switch t.Hook {
	case uint16(CONNECT):
		return "client"
	case uint16(ACCEPT):
		return "server"
	}
	return ""
}

func (t *TCPSpan) HookName() string {
	switch t.Hook {
	case uint16(CONNECT):
		return "connect"
	case uint16(ACCEPT):
		return "accept"
	}
	return ""
}

func (t *TCPSpan) ProcessName() string {
	end := len(t.SpanBase.Comm)
	for i, b := range t.SpanBase.Comm {
		if b == 0 {
			break
		}
		end = i + 1
	}

	return fmt.Sprintf("%s", t.SpanBase.Comm[:end])
}

func LoadTcpObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadTcpObjects(obj, opts)
}

func LoadTcp() (*ebpf.CollectionSpec, error) {
	return loadTcp()
}
