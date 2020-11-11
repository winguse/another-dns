// this is for macos/ipv4 for now

package utils

import (
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const defaultDestination = "default"
const vpnIf = "ppp0"

type addedRoute struct {
	ip     net.IP
	expire time.Time
}

// RouteMgr to manage route by cli
type RouteMgr struct {
	vpnGateway     net.IP
	regularGateway net.IP
	addedRoutes    map[uint32]*addedRoute

	done      chan bool
	lock      *sync.Mutex
	gcTricker *time.Ticker

	vpnName string
}

// NewRouteMgr new route manager
// the params can get from /etc/ppp/ip-up see:
func NewRouteMgr(vpnGateway, regularGateway string) *RouteMgr {
	listVPNCmd, err := exec.Command("scutil", "--nc", "list").Output()
	if err != nil {
		log.Fatalf("failed to get VPN list: %s", err.Error())
	}
	vpnName := ""
	for _, line := range strings.Split(string(listVPNCmd), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 6 && fields[1] == "(Connected)" {
			vpnName = strings.Trim(fields[6], "\"")
			break
		}
	}

	if vpnName == "" {
		log.Fatal("Cannot find the connected VPN.")
	}

	mgr := &RouteMgr{
		vpnGateway:     net.ParseIP(vpnGateway).To4(),
		regularGateway: net.ParseIP(regularGateway),
		addedRoutes:    make(map[uint32]*addedRoute),

		done:      make(chan bool),
		lock:      &sync.Mutex{},
		gcTricker: time.NewTicker(time.Minute),
		vpnName:   vpnName,
	}

	if mgr.vpnGateway == nil {
		log.Fatal("The VPN gateway is not IPv4, which another-dns won't work.")
		return nil
	}
	go func() {
		for {
			select {
			case <-mgr.done:
				return
			case <-mgr.gcTricker.C:
				mgr.gc()
			}
		}
	}()
	return mgr
}

func (r *RouteMgr) route(original net.IP, ttl uint32) net.IP {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.addedRoutes[ipv4ToUint32(original)] = &addedRoute{
		ip:     original,
		expire: time.Now().Add(time.Second * time.Duration(ttl)),
	}
	setRoute(original.String(), r.vpnGateway.String())
	return original
}

// Manage the dns response
func (r *RouteMgr) Manage(vpnDNSResponse *dns.Msg, temporary bool) *dns.Msg {
	return manageOneARecord(vpnDNSResponse, r.route, temporary)
}

// Stop the manager
func (r *RouteMgr) Stop() {
	r.done <- true
	r.gcTricker.Stop()
	deleteRoute("0/1")
	deleteRoute("128/1")
	r.setDNS(false)
}

func (r *RouteMgr) gc() {
	r.lock.Lock()
	defer r.lock.Unlock()
	now := time.Now()
	newAddedRoutes := make(map[uint32]*addedRoute)
	for ip, route := range r.addedRoutes {
		if route.expire.Before(now) {
			deleteRoute(route.ip.String())
		} else {
			newAddedRoutes[ip] = route
		}
	}
	r.addedRoutes = newAddedRoutes
}

func (r *RouteMgr) setDNS(on bool) {
	dns := "127.0.0.1"
	if !on {
		dns = "Empty"
	}
	err := exec.Command("networksetup", "-setdnsservers", r.vpnName, dns).Run()
	if err != nil {
		log.Fatalf("failed to set VPN DNS: %s", err.Error())
	}
}

func deleteRoute(network string) {
	exec.Command("route", "delete", network).Run()
}

func setRoute(network, gateway string) {
	deleteRoute(network) // just to ensure the route not exist
	exec.Command("route", "add", network, gateway).Run()
}

func setAllRouteTo(ip net.IP) {
	setRoute("0/1", ip.String())
	setRoute("128/1", ip.String())
}

// VPNAll vpn all the traffic
func (r *RouteMgr) VPNAll() {
	r.setDNS(false)
	setAllRouteTo(r.vpnGateway)
	for _, added := range r.addedRoutes {
		deleteRoute(added.ip.String())
	}
}

// VPNNothing regular all traffic
func (r *RouteMgr) VPNNothing() {
	r.setDNS(true)
	setAllRouteTo(r.regularGateway)
	for _, added := range r.addedRoutes {
		deleteRoute(added.ip.String())
	}
}

// VPNAuto auto vpn traffic
func (r *RouteMgr) VPNAuto() {
	r.setDNS(true)
	setAllRouteTo(r.regularGateway)
	for _, added := range r.addedRoutes {
		setRoute(added.ip.String(), r.vpnGateway.String())
	}
}
