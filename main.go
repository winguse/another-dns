package main

import (
	"bufio"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/yl2chen/cidranger"
	"golang.org/x/net/context"
)

// AnotherDNS yet anther DNS
type AnotherDNS struct {
	net string
}

type dnsPolicy struct {
	domain     string
	useVPN     bool
	queryCount int64
}

type policyManager struct {
	policies       map[string]*dnsPolicy
	lock           sync.RWMutex
	maxMemoryItems int
}

func (p *policyManager) load(fileName string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Failed to policy file %s\n", err.Error())
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		items := strings.Split(line, "\t")
		if len(items) != 3 {
			log.Printf("Skipping line %s\n", line)
			continue
		}
		useVPN := items[0] == "T"
		queryCount, _ := strconv.ParseInt(items[1], 10, 64)
		domain := items[2]
		policy := &dnsPolicy{
			domain,
			useVPN,
			queryCount,
		}
		p.policies[domain] = policy
	}
}

func (p *policyManager) write(fileName string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	file, err := os.Create(fileName)
	if err != nil {
		log.Printf("Failed to write policy file %s\n", err.Error())
		return
	}
	defer file.Close()

	for _, policy := range p.policies {
		useVPNField := "F"
		if policy.useVPN {
			useVPNField = "T"
		}
		file.WriteString(useVPNField + "\t" + strconv.FormatInt(policy.queryCount, 10) + "\t" + policy.domain + "\n")
	}
}

func (p *policyManager) get(domain string) (bool, bool) {
	p.lock.RLock()
	defer p.lock.RUnlock()
	if res, ok := p.policies[domain]; ok {
		res.queryCount++
		return res.useVPN, true
	}
	return false, false
}

func (p *policyManager) set(domain string, useVPN bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.policies[domain] = &dnsPolicy{
		domain:     domain,
		useVPN:     useVPN,
		queryCount: 1,
	}
}

func (p *policyManager) gc() {
	p.lock.Lock()
	defer p.lock.Unlock()
	all := make([]*dnsPolicy, len(p.policies))
	i := 0
	for _, policy := range p.policies {
		all[i] = policy
		i++
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].queryCount > all[j].queryCount
	})
	for i = p.maxMemoryItems; i < len(all); i++ {
		delete(p.policies, all[i].domain)
	}
}

var (
	probeTimeout = time.Second * time.Duration(2)
	cnRages      = cidranger.NewPCTrieRanger()
	policies     = policyManager{}

	port                  = flag.Int("port", 8053, "port to run on")
	localDNS              = flag.String("local-dns", "119.28.28.28:53", "local DNS server")
	vpnDNS                = flag.String("vpn-dns", "8.8.8.8:53", "vpn DNS server")
	probeDNS              = flag.String("probe-dns", "192.168.11.253:8053", "probe DNS server, when this DNS returns a response, mark the query is polluted")
	probeDomain           = flag.String("probe-domain", "www.google.com", "probe domain")
	probeTimeoutFactor    = flag.Float64("probe-timeout-factor", 2, "probe DNS query timeout factor")
	queryTimeoutInSeconds = flag.Int("timeout-seconds", 30, "DNS query timeout in seconds")
	localIPListFile       = flag.String("local-ip-list-file", "cn-cidrs.txt", "the file path of a file contains one local CIDR per line")
	policyMemoryFile      = flag.String("policy-memory-file", "dns-policy.txt", "the file to save policies")
	maxMemoryItems        = flag.Int("max-memory-items", 10240, "the max number of policy to remember")
	noKnowledgeUseVPN     = flag.Bool("no-knowledge-use-vpn", false, "when we first seen a domain, if we use VPN response directly. by doing so, we can reduce the DNS response time")
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
		_, _, err := client.Exchange(msg, *probeDNS) // ignore any result
		if err == nil {
			probeTimeout = time.Nanosecond * time.Duration(int64(float64(time.Now().Sub(startTime).Nanoseconds())**probeTimeoutFactor))
			log.Println("new probe timeout ms:", int64(probeTimeout/time.Millisecond))
		} else {
			log.Panicln("Failed to probe domain, if it happen every time, it can be wrong setting of probe domain or probe DNS.")
		}
		policies.gc()
		policies.write(*policyMemoryFile)
		time.Sleep(time.Minute)
	}
}

func shouldUseVPN(domain string) bool {
	if domain == "" {
		return true
	}
	if res, ok := policies.get(domain); ok {
		return res
	}

	detectCh := make(chan bool)

	// async check domain
	go func() {
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
			ch <- err == nil // success means it's polluted
		}

		// probe twice, to make the result more stable
		go probe()
		go probe()

		firstProbe := <-ch
		secondProbe := <-ch

		polluted := firstProbe || secondProbe

		res := " not"
		if polluted {
			res = ""
		}

		log.Printf("%s is%s polluted domain.", domain, res)
		policies.set(domain, polluted)
		detectCh <- polluted
	}()

	if *noKnowledgeUseVPN {
		return true // use vpn dns as I don't know
	}

	return <-detectCh
}

// ServeDNS serve DNS request
func (a *AnotherDNS) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	domain := ""
	if len(request.Question) > 0 {
		domain = request.Question[0].Name
	}
	ctx, _ := context.WithTimeout(context.Background(), time.Second*time.Duration(*queryTimeoutInSeconds))
	client := dns.Client{
		Net:     a.net,
		Timeout: time.Second * time.Duration(*queryTimeoutInSeconds),
	}

	if strings.HasSuffix(domain, ".arpa.") {
		response, _, err := client.ExchangeContext(ctx, request, *localDNS)
		if err == nil {
			w.WriteMsg(response.SetReply(request))
		}
		return
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

	sendVPNDNSResponse := func() {
		res := <-ch
		if err, isErr := res.(error); isErr {
			log.Printf("Error while query VPN DNS: %s\n", err)
		} else if response, isResponse := res.(*dns.Msg); isResponse {
			w.WriteMsg(response.SetReply(request))
		} else {
			log.Fatal("Unknown message.", res)
		}
	}

	useVPNDNS := shouldUseVPN(domain)
	if useVPNDNS {
		sendVPNDNSResponse()
	} else {
		response, _, err := client.ExchangeContext(ctx, request, *localDNS)
		if response != nil {
			var useVPNDNSResponse = true
			var isARecord = false
			for _, ans := range response.Answer {
				if aRecord, ok := ans.(*dns.A); ok {
					isARecord = true
					if contains, err := cnRages.Contains(aRecord.A); contains && err == nil {
						useVPNDNSResponse = false
						break
					}
				}
			}
			if isARecord && useVPNDNSResponse {
				log.Printf("%s is foreign domain\n", domain)
				policies.set(domain, true) // override as we use VPN dns
				sendVPNDNSResponse()
			} else {
				w.WriteMsg(response.SetReply(request))
			}
		}
		if err != nil {
			log.Printf("Error while query DNS: %s\n", err)
		}
	}
}

func loadLocalCIDR() {
	data, err := ioutil.ReadFile(*localIPListFile)
	if err != nil {
		log.Fatalf("Failed to read CIDR file from %s\n", err.Error())
	}
	for _, line := range strings.Split(string(data), "\n") {
		cidr := strings.TrimSpace(line)
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Skiping line: %s\n", line)
		} else {
			cnRages.Insert(cidranger.NewBasicRangerEntry(*network))
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

	policies.maxMemoryItems = *maxMemoryItems
	policies.policies = make(map[string]*dnsPolicy)
	policies.load(*policyMemoryFile)
	loadLocalCIDR()

	go refreshProbeTimeout()
	go startServer("udp")
	go startServer("tcp")

	log.Printf("Working on port %d\n", *port)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	policies.write(*policyMemoryFile)
	log.Printf("Signal (%v) received, stopping\n", s)
}
