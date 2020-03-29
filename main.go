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
	"github.com/yl2chen/cidranger"
	"golang.org/x/net/context"
)

// DNSImpl yet anther DNS
type DNSImpl struct {
	localDNS              string
	vpnDNS                string
	net                   string
	localRanger           cidranger.Ranger
	queryTimeoutInSeconds int
}

type exchangeRes struct {
	local    bool
	response *dns.Msg
	err      error
}

func (e *exchangeRes) getARecords() []net.IP {
	result := make([]net.IP, 0)
	if e.err == nil {
		for _, v := range e.response.Answer {
			if a, ok := v.(*dns.A); ok {
				result = append(result, a.A)
			}
		}
	}
	return result
}

// ServeDNS serve DNS request
func (a *DNSImpl) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	defaultResponse := &dns.Msg{}
	defaultResponse.SetReply(request)

	client := dns.Client{
		Net: a.net,
	}
	ch := make(chan *exchangeRes)
	defer close(ch)

	ctx, _ := context.WithTimeout(context.TODO(), time.Second*time.Duration(a.queryTimeoutInSeconds))

	go func() {
		response, _, err := client.ExchangeContext(ctx, request, a.localDNS)
		ch <- &exchangeRes{true, response, err}
	}()

	queryVpnDNS := len(request.Question) > 0 && request.Question[0].Qtype == dns.TypeA
	if queryVpnDNS {
		go func() {
			response, _, err := client.ExchangeContext(ctx, request, a.vpnDNS)
			ch <- &exchangeRes{false, response, err}
		}()
	}

	if !queryVpnDNS {
		res := <-ch
		if res.err == nil {
			w.WriteMsg(res.response.SetReply(request))
		} else {
			w.WriteMsg(defaultResponse)
		}
		return
	}

	var localRes *exchangeRes
	var vpnRes *exchangeRes
	for i := 0; i < 2; i++ {
		res := <-ch
		if res.local {
			localRes = res
		} else {
			vpnRes = res
		}
	}

	if localRes.err == nil {
		localRes.response.SetReply(request)
	}
	if vpnRes.err == nil {
		vpnRes.response.SetReply(request)
	}

	localARecords := localRes.getARecords()

	if localRes.err != nil || len(localARecords) == 0 || vpnRes.err != nil {
		if localRes.err == nil && len(localRes.response.Answer) > 0 {
			log.Printf("* local response for %s\n", request.Question[0].Name)
			w.WriteMsg(localRes.response)
		} else if vpnRes.err == nil && len(vpnRes.response.Answer) > 0 {
			log.Printf("* vpn response for %s\n", request.Question[0].Name)
			w.WriteMsg(vpnRes.response)
		} else {
			w.WriteMsg(defaultResponse)
		}
		return
	}

	localResIP := localARecords[0]
	isLocal, err := a.localRanger.Contains(localResIP)

	log.Printf(localResIP.String())

	if err == nil && isLocal {
		log.Printf("local response for %s\n", request.Question[0].Name)
		w.WriteMsg(localRes.response)
	} else {
		log.Printf("vpn response for %s\n", request.Question[0].Name)
		w.WriteMsg(vpnRes.response)
	}
}

func startServer(port int, net string, localDNS string, vpnDNS string, localRanger cidranger.Ranger, queryTimeoutInSeconds int) {
	impl := &DNSImpl{
		localDNS:              localDNS,
		vpnDNS:                vpnDNS,
		net:                   net,
		localRanger:           localRanger,
		queryTimeoutInSeconds: queryTimeoutInSeconds,
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
	localDNS := flag.String("local-dns", "114.114.114.114:53", "local DNS server")
	vpnDNS := flag.String("vpn-dns", "8.8.8.8:53", "vpn DNS server")
	localIPListFile := flag.String("local-ip-list-file", "cn-cidrs.txt", "the file path of a file contains one local CIDR per line")
	queryTimeoutInSeconds := flag.Int("timeout-seconds", 5, "DNS query timeout in seconds")

	flag.Parse()

	localRanger := loadLocalCIDR(*localIPListFile)

	go startServer(*port, "udp", *localDNS, *vpnDNS, localRanger, *queryTimeoutInSeconds)
	go startServer(*port, "tcp", *localDNS, *vpnDNS, localRanger, *queryTimeoutInSeconds)

	log.Printf("Working on port %d\n", *port)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Fatalf("Signal (%v) received, stopping\n", s)
}
