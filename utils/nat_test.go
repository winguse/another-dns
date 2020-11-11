package utils

import (
	"net"
	"testing"
)

func TestIPConvert(t *testing.T) {
	ip := net.IPv4(1, 2, 3, 4)
	if ipv4ToUint32(ip) != 16909060 {
		t.Error("ipv4 to uint32 is wrong")
	}
	if uint32ToIPv4(16909060).String() != "1.2.3.4" {
		t.Error("uint32 to ipv4 is wrong")
	}
}
