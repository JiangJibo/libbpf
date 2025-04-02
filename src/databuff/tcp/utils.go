package tcp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	SysBootime time.Time
)

func init() {
	SysBootime = getBootTime()
}

func getBootTime() time.Time {
	var btime int64

	if value := readProcStat(); value != "" {
		_, err := fmt.Sscanf(readProcStat(), "btime %d", &btime)
		if err != nil {
			fmt.Printf("Failed to read boot time: %v", err)
		}
	}

	return time.Unix(btime, 0)
}

func readProcStat() string {
	filename := "/proc/stat"
	f, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime") {
			return line
		}
	}
	return ""
}

// Htons 将 16 位整数从主机字节序转换为网络字节序
func Htons(value uint16) uint16 {
	return binary.BigEndian.Uint16([]byte{byte(value), byte(value >> 8)})
}

// Htonl 将 32 位整数从主机字节序转换为网络字节序
func Htonl(value uint32) uint32 {
	return binary.BigEndian.Uint32([]byte{
		byte(value),
		byte(value >> 8),
		byte(value >> 16),
		byte(value >> 24),
	})
}
