package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"github.com/yl2chen/cidranger"
	"golang.org/x/net/context"
)

// DNSImpl yet anther DNS
type DNSImpl struct {
	cache                 *cache.Cache
	localDNS              string
	vpnDNS                string
	eDNSSourceV4          *net.IPNet
	eDNSSourceV6          *net.IPNet
	net                   string
	localRanger           cidranger.Ranger
	queryTimeoutInSeconds int
	strictMode            bool
}

func (a *DNSImpl) query(request *dns.Msg, useVPNDNS bool) (response *dns.Msg, err error) {
	client := dns.Client{
		Net: a.net,
	}
	ctx, _ := context.WithTimeout(context.Background(), time.Second*time.Duration(a.queryTimeoutInSeconds))
	dnsServerAddr := a.vpnDNS
	if !useVPNDNS {
		if a.localDNS == "" {
			isV6Request := len(request.Question) > 0 && request.Question[0].Qtype == dns.TypeAAAA
			request.Extra = append(request.Extra, a.buildEDNSSource(!isV6Request))
		} else {
			dnsServerAddr = a.localDNS
		}
	}
	response, _, err = client.ExchangeContext(ctx, request, dnsServerAddr)
	return
}

func (a *DNSImpl) buildEDNSSource(useIPv4 bool) *dns.OPT {
	dnsOption := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	address := a.eDNSSourceV4.IP
	sourceScope, _ := a.eDNSSourceV4.Mask.Size()
	family := (uint16)(1)
	sourceNetmask := 32
	if !useIPv4 {
		address = a.eDNSSourceV6.IP
		sourceScope, _ = a.eDNSSourceV6.Mask.Size()
		family = 2
		sourceNetmask = 128
	}

	eDNSSubnet := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Address:       address,
		Family:        family,
		SourceScope:   (uint8)(sourceScope),
		SourceNetmask: (uint8)(sourceNetmask),
	}
	dnsOption.Option = append(dnsOption.Option, eDNSSubnet)
	return dnsOption
}

func (a *DNSImpl) isLocalDomain(domain string) bool {
	cacheKey := "is-local:" + domain
	if res, ok := a.cache.Get(cacheKey); ok {
		return res.(bool)
	}
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	request.Extra = append(request.Extra, a.buildEDNSSource(true))
	response, err := a.query(request, true)
	if err != nil {
		if a.strictMode { // if strict mode, always query vpn dns
			return false
		}
		return true
	}
	result := false
	for _, ans := range response.Answer {
		if aRecord, ok := ans.(*dns.A); ok {
			if contains, err := a.localRanger.Contains(aRecord.A); contains && err == nil {
				result = true
				break
			}
		}
	}
	log.Printf("%s is local %t\n", domain, result)
	a.cache.SetDefault(cacheKey, result)
	return result
}

// ServeDNS serve DNS request
func (a *DNSImpl) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	useVPNDNS := len(request.Question) > 0 && !a.isLocalDomain(request.Question[0].Name)
	response, err := a.query(request, useVPNDNS)
	if err == nil {
		w.WriteMsg(response.SetReply(request))
	} else {
		log.Printf("Error while query DNS: %s\n", err)
		w.WriteMsg((&dns.Msg{}).SetReply(request))
	}
}

func startServer(cache *cache.Cache, port int, net string, localDNS string, vpnDNS string, eDNSSourceV4 *net.IPNet, eDNSSourceV6 *net.IPNet, localRanger cidranger.Ranger, queryTimeoutInSeconds int, strictMode bool) {
	impl := &DNSImpl{
		cache:                 cache,
		localDNS:              localDNS,
		vpnDNS:                vpnDNS,
		eDNSSourceV4:          eDNSSourceV4,
		eDNSSourceV6:          eDNSSourceV6,
		net:                   net,
		localRanger:           localRanger,
		queryTimeoutInSeconds: queryTimeoutInSeconds,
		strictMode:            strictMode,
	}
	srv := &dns.Server{
		Addr:    ":" + strconv.Itoa(port),
		Net:     net,
		Handler: impl,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to set %s listener %s\n", net, err.Error())
	}
}

func loadLocalCIDR(filePath string) cidranger.Ranger {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read CIDR file from %s\n", err.Error())
	}
	ranger := cidranger.NewPCTrieRanger()
	for _, line := range strings.Split(string(data), "\n") {
		cidr := strings.TrimSpace(line)
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Skiping %s\n", line)
		} else {
			ranger.Insert(cidranger.NewBasicRangerEntry(*network))
		}
	}
	return ranger
}

func main() {

	port := flag.Int("port", 8053, "port to run on")
	localDNS := flag.String("local-dns", "", "local DNS server, default empty. if empty, then query vpn DNS with eDNS source")
	vpnDNS := flag.String("vpn-dns", "8.8.8.8:53", "vpn DNS server")
	eDNSSourceV4String := flag.String("edns-source-v4", "101.6.8.193/32", "the source range of edns v4, default to a range in Beijing")
	eDNSSourceV6String := flag.String("edns-source-v6", "2402:f000:1:408:8100::1/128", "the source range of edns v6, default to a range in Beijing")
	localIPListFile := flag.String("local-ip-list-file", "cn-cidrs.txt", "the file path of a file contains one local CIDR per line")
	queryTimeoutInSeconds := flag.Int("timeout-seconds", 5, "DNS query timeout in seconds")
	strictMode := flag.Bool("strict", false, "when strict mode is true, then we will never leak DNS query to local DNS event the VPN dns is down")

	flag.Parse()

	localRanger := loadLocalCIDR(*localIPListFile)
	cache := cache.New(5*time.Minute, 10*time.Minute)

	_, eDNSSourceV4, err := net.ParseCIDR(*eDNSSourceV4String)
	if err != nil || eDNSSourceV4.IP.To4() == nil {
		log.Panicf("Failed to parse eDNS source V4 from %s", *eDNSSourceV4String)
	}

	_, eDNSSourceV6, err := net.ParseCIDR(*eDNSSourceV6String)
	if err != nil || eDNSSourceV6.IP.To4() != nil {
		log.Panicf("Failed to parse eDNS source V6 from %s", *eDNSSourceV4String)
	}

	go startServer(cache, *port, "udp", *localDNS, *vpnDNS, eDNSSourceV4, eDNSSourceV6, localRanger, *queryTimeoutInSeconds, *strictMode)
	go startServer(cache, *port, "tcp", *localDNS, *vpnDNS, eDNSSourceV4, eDNSSourceV6, localRanger, *queryTimeoutInSeconds, *strictMode)

	log.Printf("Working on port %d\n", *port)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Fatalf("Signal (%v) received, stopping\n", s)
}
