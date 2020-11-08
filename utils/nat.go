package utils

import (
	"log"
	"net"
	"os/exec"
	"sync"
	"time"
)

const chainName = "another-dns-prerouting"

type allocatedNat struct {
	real   *net.IP
	fake   *net.IP
	expire time.Time
}

// Nat utils
type Nat struct {
	lock        *sync.Mutex
	pool        []*net.IP
	allocated   []*allocatedNat
	gcTricker   *time.Ticker
	addressCIDR string
	ifIn        string
	done        chan bool

	allocationStartIP uint32
	allocatedMaxIP    uint32
	allocationEndIP   uint32
	allocatedIPs      map[uint32]*allocatedNat
}

func iptablesNat(ignoreError bool, action string, args ...string) {
	cmd := exec.Command("iptables", append([]string{"-t", "nat", "-" + action}, args...)...)
	err := cmd.Run()
	if ignoreError == false && err != nil {
		log.Fatal(err)
	}
}

func ipv4ToUint32(ip *net.IP) uint32 {
	bytes := ([]byte)(ip.To4())
	ret := uint32(0)
	for i := 0; i < len(bytes); i++ {
		ret = ret<<8 | uint32(bytes[i])
	}
	return ret
}

func uint32ToIPv4(ip uint32) *net.IP {
	res := net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
	return &res
}

// NewNat create new NAT
func NewNat(addressCIDR string, ifIn string) *Nat {
	_, network, err := net.ParseCIDR(addressCIDR)
	if err != nil {
		log.Fatalf("%s is invalid CIDR: %s", addressCIDR, err.Error())
	}
	allocationStartIP := ipv4ToUint32(&network.IP)
	ones, bits := network.Mask.Size()

	nat := &Nat{
		lock:        &sync.Mutex{},
		pool:        []*net.IP{},
		allocated:   []*allocatedNat{},
		gcTricker:   time.NewTicker(time.Minute),
		addressCIDR: addressCIDR,
		ifIn:        ifIn,
		done:        make(chan bool),

		allocationStartIP: allocationStartIP,
		allocatedMaxIP:    allocationStartIP,
		allocationEndIP:   allocationStartIP + uint32(1)<<(bits-ones),
		allocatedIPs:      make(map[uint32]*allocatedNat),
	}
	nat.setupIptables(true)
	nat.setupIptables(false)
	go func() {
		for {
			select {
			case <-nat.done:
				return
			case <-nat.gcTricker.C:
				nat.gc()
			}
		}
	}()
	return nat
}

func (n *Nat) processEntry(action string, real *net.IP, fake *net.IP) {
	iptablesNat(false, action, chainName, "-d", fake.String(), "-j", "DNAT", "--to-destination", real.String())
}

func (n *Nat) setupIptables(clear bool) {
	routeToChain := []string{"PREROUTING", "-i", n.ifIn, "-d", n.addressCIDR, "-j", chainName}
	if clear {
		// route fake ip range to the chain
		iptablesNat(true, "D", routeToChain...)
		// clear and create chain
		iptablesNat(true, "F", chainName)
		iptablesNat(true, "X", chainName)
	} else {
		iptablesNat(false, "N", chainName)
		iptablesNat(false, "I", routeToChain...)
	}
}

func (n *Nat) gc() {
	n.lock.Lock()
	defer n.lock.Unlock()

	now := time.Now()

	newAllocated := []*allocatedNat{}
	for _, pre := range n.allocated {
		if pre.expire.After(now) {
			n.processEntry("D", pre.real, pre.fake)
			delete(n.allocatedIPs, ipv4ToUint32(pre.real))
			n.pool = append(n.pool, pre.fake)
		} else {
			newAllocated = append(newAllocated, pre)
		}
	}
	n.allocated = newAllocated
}

// Allocate a NAT
func (n *Nat) Allocate(real *net.IP, ttl uint32) *net.IP {
	n.lock.Lock()
	defer n.lock.Unlock()

	realU32 := ipv4ToUint32(real)
	if allocation, ok := n.allocatedIPs[realU32]; ok {
		log.Printf("previous allocated nat: %s -> %s, expire at %s\n", allocation.real.String(), allocation.fake.String(), allocation.expire.String())
		return allocation.fake
	}

	var fake *net.IP
	if len(n.pool) > 0 {
		fake = n.pool[0]
		n.pool = n.pool[1:]
	} else {
		if n.allocatedMaxIP >= n.allocationEndIP {
			log.Printf("cannot allocate new addresses for %s\n", real.String())
			return nil
		}
		fake = uint32ToIPv4(n.allocatedMaxIP)
		n.allocatedMaxIP = n.allocatedMaxIP + 1
	}

	n.processEntry("I", real, fake)
	allocation := &allocatedNat{
		real:   real,
		fake:   fake,
		expire: time.Now().Add(time.Second * time.Duration(ttl)),
	}
	n.allocated = append(n.allocated, allocation)
	n.allocatedIPs[realU32] = allocation
	log.Printf("allocated nat: %s -> %s, expire at %s\n", real.String(), fake.String(), allocation.expire.String())

	return fake
}

// Stop the nat
func (n *Nat) Stop() {
	n.done <- true
	n.gcTricker.Stop()
	n.setupIptables(true)
}
