package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"golang.org/x/net/context"
)

// AnotherDNS yet anther DNS
type AnotherDNS struct {
	net string
}

var (
	isLocalCache = cache.New(60*time.Minute, 10*time.Minute)
	probeTimeout = time.Second * time.Duration(2)

	port                  = flag.Int("port", 8053, "port to run on")
	localDNS              = flag.String("local-dns", "119.28.28.28:53", "local DNS server")
	vpnDNS                = flag.String("vpn-dns", "8.8.8.8:53", "vpn DNS server")
	probeDNS              = flag.String("probe-dns", "192.168.11.253:8053", "probe DNS server, when this DNS returns a response, mark the query is polluted")
	probeDomain           = flag.String("probe-domain", "www.google.com", "probe domain")
	probeTimeoutFactor    = flag.Float64("probe-timeout-factor", 1.5, "probe DNS query timeout factor")
	queryTimeoutInSeconds = flag.Int("timeout-seconds", 60, "DNS query timeout in seconds")
)

func refreshProbeTimeout() {
	client := dns.Client{
		Net:     "udp",
		Timeout: time.Second * time.Duration(*queryTimeoutInSeconds),
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(*probeDomain), dns.TypeA)
	for {
		startTime := time.Now()
		client.Exchange(msg, *probeDNS) // ignore any result
		probeTimeout = time.Nanosecond * time.Duration(int64(float64(time.Now().Sub(startTime).Nanoseconds())**probeTimeoutFactor))
		log.Println("new probe timeout ms:", int64(probeTimeout/time.Millisecond))
		time.Sleep(time.Minute)
	}
}

func isLocal(domain string) bool {
	if res, ok := isLocalCache.Get(domain); ok {
		return res.(bool)
	}
	client := dns.Client{
		Net:     "udp",
		Timeout: time.Second * time.Duration(*queryTimeoutInSeconds),
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	ctx, _ := context.WithTimeout(context.Background(), probeTimeout)
	ch := make(chan bool)

	probe := func() {
		_, _, err := client.ExchangeContext(ctx, msg, *probeDNS)
		ch <- err != nil // local domain will be timeout
	}

	// probe twice, to make the result more stable
	go probe()
	go probe()

	firstProbe := <-ch
	secondProbe := <-ch

	result := firstProbe && secondProbe

	res := ""
	if result {
		res = "not"
	}

	log.Printf("%s is %s polluted domain.", domain, res)
	isLocalCache.SetDefault(domain, result)

	return result
}

// ServeDNS serve DNS request
func (a *AnotherDNS) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	ctx, _ := context.WithTimeout(context.Background(), time.Second*time.Duration(*queryTimeoutInSeconds))
	client := dns.Client{
		Net:     a.net,
		Timeout: time.Second * time.Duration(*queryTimeoutInSeconds),
	}

	ch := make(chan interface{})
	go func() {
		response, _, err := client.ExchangeContext(ctx, request, *vpnDNS)
		if err != nil {
			ch <- err
		} else {
			ch <- response
		}
	}()

	useVPNDNS := len(request.Question) > 0 && !isLocal(request.Question[0].Name)
	if useVPNDNS {
		res := <-ch
		if err, isErr := res.(error); isErr {
			log.Printf("Error while query VPN DNS: %s\n", err)
		} else if response, isResponse := res.(*dns.Msg); isResponse {
			w.WriteMsg(response.SetReply(request))
		} else {
			log.Fatal("Unknown message.", res)
		}
	} else {
		response, _, err := client.ExchangeContext(ctx, request, *localDNS)
		if response != nil {
			w.WriteMsg(response.SetReply(request))
		}
		if err != nil {
			log.Printf("Error while query DNS: %s\n", err)
		}
	}
}

func startServer(net string) {
	impl := &AnotherDNS{
		net: net,
	}
	srv := &dns.Server{
		Addr:    ":" + strconv.Itoa(*port),
		Net:     net,
		Handler: impl,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to set %s listener %s\n", net, err.Error())
	}
}

func main() {
	flag.Parse()

	go refreshProbeTimeout()
	go startServer("udp")
	go startServer("tcp")

	log.Printf("Working on port %d\n", *port)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Fatalf("Signal (%v) received, stopping\n", s)
}
