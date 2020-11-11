package utils

import (
	"net"

	"github.com/miekg/dns"
)

// VPNResponseMgr defines how do we manage the VPN DNS response
// for example:
// 1. in server mode, it can use DNAT
// 2. in client mode, it can adding route
type VPNResponseMgr interface {
	Manage(vpnResponse *dns.Msg, temporary bool) *dns.Msg
	Stop()
}

type allocateFn func(net.IP, uint32) net.IP

func manageOneARecord(vpnDNSResponse *dns.Msg, allocate allocateFn, temporary bool) *dns.Msg {
	var selectedARecord *dns.A

	for _, ans := range vpnDNSResponse.Answer {
		if aRecord, ok := ans.(*dns.A); ok {
			selectedARecord = aRecord
			break
		}
	}

	if selectedARecord == nil {
		return vpnDNSResponse
	}

	dnsTTL := selectedARecord.Hdr.Ttl
	allocateTTL := dnsTTL
	if allocateTTL < minTTL {
		allocateTTL = minTTL
	}
	if temporary {
		allocateTTL = 60
		if allocateTTL > dnsTTL {
			allocateTTL = dnsTTL
		}
	}

	// allowcate nat
	if fakeIP := allocate(selectedARecord.A, allocateTTL); fakeIP != nil {
		newResponse := new(dns.Msg)
		aRecord := &dns.A{
			A:   fakeIP,
			Hdr: selectedARecord.Hdr,
		}
		if aRecord.Hdr.Ttl > allocateTTL {
			aRecord.Hdr.Ttl = allocateTTL
		}
		newResponse.Answer = append(newResponse.Answer, aRecord)
		return newResponse
	}

	return vpnDNSResponse
}
