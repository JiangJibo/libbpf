package tcp

import (
	"fmt"
	"net"
	"time"
)

type ConnTuple struct {
	Saddr     [16]byte
	Daddr     [16]byte
	AF        uint8 // AF_INET or AF_INET6
	Direction uint8
	Dport     uint16
	Sport     uint16
	Netns     uint32
}

type ConnStats struct {
	SentBytes   uint64
	SentPackets uint64
	RecvBytes   uint64
	RecvPackets uint64
	Timestamp   uint64
	Flags       uint32
	Pid         uint32
}

type TcpStats struct {
	InitTimestamp uint64
	Rtt           uint32
	RttVar        uint32
	Retransmit    uint32
	TranState     uint16
	ConnState     ConnStats
}

type TcpConnStats struct {
	ConnTuple
	TcpStats
}

func (t *TcpConnStats) Match(flows []ConnTuple) bool {
	if len(flows) == 0 {
		return true
	}

	for _, conn := range flows {
		if conn.Sport > 0 && conn.Dport > 0 {
			b := (conn.Sport == t.Sport && conn.Dport == t.Dport) ||
				(conn.Sport == t.Dport && conn.Dport == t.Sport)
			if !b {
				continue
			}
		}

		if conn.Daddr[0] == 0 && conn.Daddr[3] == 0 {
			b := conn.Saddr == t.Saddr || conn.Saddr == t.Daddr
			if !b {
				continue
			}

			if conn.Sport > 0 {
				b = (conn.Saddr == t.Saddr && conn.Sport == t.Sport) ||
					(conn.Saddr == t.Daddr && conn.Sport == t.Dport)
				if !b {
					continue
				}
			}
			return true
		}

		b := (conn.Saddr == t.Saddr && conn.Daddr == t.Daddr) ||
			(conn.Saddr == t.Daddr && conn.Daddr == t.Saddr)
		if b {
			return true
		}
	}
	return false
}

// ts(0), src_ip(1), src_port(2), dst_ip(3), dst_port(4),
// protocol(5), rtt(6), rtt-var(7), art(8), ptt(9),
// packets_sent(10), bytes_sent(11), packets_retr(12), packets_received(13), bytes_received(14)
// is_local(15), cpid(16), adapter_name(17), netns(18)
func (t *TcpConnStats) Output() string {
	return fmt.Sprintf("%d, %s, %d, %s, %d,	%s, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %s, %d\n",
		t.Timestamp(), t.GetSourceIp(), t.GetSrcPort(), t.GetDestIp(), t.GetDestPort(),
		"TCP", t.Rtt, t.RttVar, 0, 0,
		t.ConnState.SentPackets, t.ConnState.SentBytes, t.Retransmit, t.ConnState.RecvPackets, t.ConnState.RecvBytes,
		t.Direction, t.ConnState.Pid, "ebpf", t.Netns)
}

func (t *TcpConnStats) String() string {
	return fmt.Sprintf("%s (#%d): %s, %d, %d, rtt=%d, %d", t.Time(), t.ConnState.Pid, t.Addr(),
		t.ConnState.RecvBytes, t.ConnState.SentBytes, t.Rtt, t.RttVar)
}

func (t *TcpConnStats) Time() string {
	absoluteTime := SysBootime.Add(time.Duration(t.ConnState.Timestamp)).Local()
	timeStr := absoluteTime.Format("2006-01-02 15:04:05.999")
	return timeStr
}

func (t *TcpConnStats) Timestamp() uint64 {
	absoluteTime := SysBootime.Add(time.Duration(t.ConnState.Timestamp))
	return uint64(absoluteTime.Local().Unix())
}

func (t *TcpConnStats) Addr() string {
	addr := t.GetSourceAddr()
	if t.Direction == CONN_DIRECTION_OUTGOING {
		addr += " (*)"
	}
	addr += " -> "

	addr += t.GetDestAddr()
	if t.Direction == CONN_DIRECTION_INCOMING {
		addr += " (*)"
	}
	return addr
}

func (t *TcpConnStats) Key() string {
	return t.GetSourceAddr() + "-" + t.GetDestAddr()
}

func (t *ConnTuple) GetSourceIp() string {
	if t.AF == AF_INET {
		return fmt.Sprintf("%d.%d.%d.%d", t.Saddr[0], t.Saddr[1], t.Saddr[2], t.Saddr[3])
	} else if t.AF == AF_INET6 {
		return net.IP(t.Saddr[:]).String()
	}
	return ""
}

// 获取目标地址
func (t *ConnTuple) GetDestIp() string {
	if t.AF == AF_INET {
		return fmt.Sprintf("%d.%d.%d.%d", t.Daddr[0], t.Daddr[1], t.Daddr[2], t.Daddr[3])
	} else if t.AF == AF_INET6 {
		return net.IP(t.Daddr[:]).String()
	}
	return ""
}

func (t *ConnTuple) GetSourceAddr() string {
	if t.AF == AF_INET {
		return fmt.Sprintf("%d.%d.%d.%d:%d", t.Saddr[0], t.Saddr[1], t.Saddr[2], t.Saddr[3], t.GetSrcPort())
	} else if t.AF == AF_INET6 {
		ip := net.IP(t.Saddr[:])
		return fmt.Sprintf("%s:%d", ip.String(), t.GetSrcPort())
	}
	return ""
}

// 获取目标地址
func (t *ConnTuple) GetDestAddr() string {
	if t.AF == AF_INET {
		return fmt.Sprintf("%d.%d.%d.%d:%d", t.Daddr[0], t.Daddr[1], t.Daddr[2], t.Daddr[3], t.GetDestPort())
	} else if t.AF == AF_INET6 {
		ip := net.IP(t.Daddr[:])
		return fmt.Sprintf("%s:%d", ip.String(), t.GetDestPort())
	}
	return ""
}

func (t *ConnTuple) GetSrcPort() uint16 {
	return t.Sport
}

func (t *ConnTuple) GetDestPort() uint16 {
	return t.Dport
}
