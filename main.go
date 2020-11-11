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

	"github.com/getlantern/systray"
	"github.com/miekg/dns"
	"github.com/winguse/another-dns/utils"
	"github.com/yl2chen/cidranger"
	"golang.org/x/net/context"
)

// AnotherDNS yet anther DNS
type AnotherDNS struct {
	client *dns.Client
}

var (
	probeTimeout = time.Second * time.Duration(2)
	cnRages      = cidranger.NewPCTrieRanger()
	policies     *utils.PolicyManager
	vpnResMgr    utils.VPNResponseMgr

	port                  = flag.Int("port", 8053, "port to run on")
	localDNS              = flag.String("local-dns", "119.28.28.28:53", "local DNS server")
	vpnDNS                = flag.String("vpn-dns", "8.8.8.8:53", "vpn DNS server")
	probeDNS              = flag.String("probe-dns", "192.168.11.253:8053", "probe DNS server, when this DNS returns a response, mark the query is polluted")
	probeDomain           = flag.String("probe-domain", "www.google.com", "probe domain")
	probeTimeoutFactor    = flag.Float64("probe-timeout-factor", 2, "probe DNS query timeout factor")
	queryTimeoutInSeconds = flag.Int("timeout-seconds", 10, "DNS query timeout in seconds")
	localIPListFile       = flag.String("local-ip-list-file", "cn-cidrs.txt", "the file path of a file contains one local CIDR per line. if all the dns A response is not in this list, another-dns will response with vpn DNS response.")
	policyMemorizeFile    = flag.String("policy-memorize-file", "dns-policy.txt", "the file to save policies")
	policyStaticFile      = flag.String("policy-static-file", "static-dns-policy.txt", "the file to save policies")
	maxMemorizeItems      = flag.Int("max-memorize-items", 10240, "the max number of policy to remember")
	noKnowledgeMode       = flag.Int("no-knowledge-mode", 0, "when we first seen a domain: 0 -> detect; 1 -> use local DNS response (may leak your intent to local dns); 2 -> use VPN response. detect will run in background.")
	ignoreArpaRequest     = flag.Bool("ignore-arpa-dns", true, "ignore all .arpa reqeust")
	detectMode            = flag.Int("mode", 0, "running mode: 0 -> auto detect and save result learned; 1 -> detect deisabled, base on static policy, if it's not matched, use local dns; 2 -> detect deisabled, base on static policy, if it's not matched, use vpn dns")
	enableNATOnVPNDNS     = flag.Bool("enable-nat-on-vpn-dns", false, "if enable NAT on VPN DNS responses")
	natRange              = flag.String("nat-range", "198.18.0.0/15", "the fake IP of NAT")
	natIn                 = flag.String("nat-in", "wg0", "NAT source interface. We only set PREROUTING here, assuming POSTROUTING already handle by MASQUERADE. If you have multiple interfaces, you can use ',' to sparate them.")
	macOSMode             = flag.Bool("macos", false, "macOS VPN GUI mode, in this mode, will ignore NAT feature")
	vpnGateway            = flag.String("vpn-gateway", "", "VPN gateway, only used when macos=true")
	regularGateway        = flag.String("regular-gateway", "", "Regular gateway, only used when macos=true")
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
			log.Println("Failed to probe domain, if it happen every time, it can be wrong setting of probe domain or probe DNS.")
		}
		policies.Gc()
		policies.Write(*policyMemorizeFile)
		time.Sleep(time.Minute)
	}
}

// return (isTemporaryDecision, shouldUseVPN)
func (a *AnotherDNS) shouldUseVPN(domain string) (bool, bool) {
	if domain == "" {
		return false, false
	}
	if res, ok := policies.Get(domain); ok {
		return false, res
	}

	if *detectMode == 1 { // detect disabled, default to local dns
		return false, false
	}
	if *detectMode == 2 { // detect disabled, default to vpn dns
		return false, true
	}

	detectCh := make(chan bool)

	// async check domain
	go func() {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

		ctx, _ := context.WithTimeout(context.Background(), probeTimeout)
		ch := make(chan bool)

		probe := func() {
			_, _, err := a.client.ExchangeContext(ctx, msg, *probeDNS)
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
		policies.Set(domain, polluted)
		detectCh <- polluted
	}()

	if *noKnowledgeMode == 1 { // no knowledge, default to local dns
		return true, false
	}
	if *noKnowledgeMode == 2 { // no knowledge, default to vpn dns
		return true, true
	}

	return false, <-detectCh
}

func manipulateVPNDNSResponse(vpnDNSResponse *dns.Msg, temporary bool) *dns.Msg {
	if !*enableNATOnVPNDNS && !*macOSMode {
		return vpnDNSResponse
	}

	return vpnResMgr.Manage(vpnDNSResponse, temporary)
}

func isForeignDomainARecord(response *dns.Msg) bool {
	var isForeignDomain = true
	var isARecord = false
	for _, ans := range response.Answer {
		if aRecord, ok := ans.(*dns.A); ok {
			isARecord = true
			if contains, err := cnRages.Contains(aRecord.A); contains && err == nil {
				isForeignDomain = false
				break
			}
		}
	}
	return isARecord && isForeignDomain
}

// ServeDNS serve DNS request
func (a *AnotherDNS) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	defer w.Close()
	domain := ""
	if len(request.Question) > 0 {
		domain = request.Question[0].Name
	}

	if *ignoreArpaRequest && strings.HasSuffix(domain, ".arpa.") {
		return
	}

	if *detectMode != 0 {
		selectedDNS := *localDNS
		_, useVPN := a.shouldUseVPN(domain)
		if useVPN {
			selectedDNS = *vpnDNS
		}
		response, _, err := a.client.Exchange(request, selectedDNS)
		if err == nil {
			if useVPN {
				response = manipulateVPNDNSResponse(response, false)
			}
			w.WriteMsg(response.SetReply(request))
		}
		return
	}

	ctx, _ := context.WithTimeout(context.Background(), time.Second*time.Duration(*queryTimeoutInSeconds))
	ch := make(chan interface{})
	go func() { // send request to vpn dns
		response, _, err := a.client.ExchangeContext(ctx, request, *vpnDNS)
		if err != nil {
			ch <- err
		} else {
			ch <- response
		}
	}()

	sendVPNDNSResponse := func(temporary bool) {
		res := <-ch
		if err, isErr := res.(error); isErr {
			log.Printf("Error while query VPN DNS: %s\n", err)
		} else if response, isResponse := res.(*dns.Msg); isResponse {
			if isForeignDomainARecord(response) { // only manipulate if it's foreign domain
				response = manipulateVPNDNSResponse(response, temporary)
			}
			w.WriteMsg(response.SetReply(request))
		} else {
			log.Fatal("Unknown message.", res)
		}
	}

	isTemporaryDecision, useVPNDNS := a.shouldUseVPN(domain)
	if useVPNDNS {
		sendVPNDNSResponse(isTemporaryDecision)
	} else {
		response, _, err := a.client.ExchangeContext(ctx, request, *localDNS)
		if response != nil {
			// if one of the A record is not foreign IP, we won't use VPN response
			if isForeignDomainARecord(response) {
				log.Printf("%s is foreign domain\n", domain)
				policies.Set(domain, true) // override as we use VPN dns
			}
			isTemporaryDecision, useVPNDNS := a.shouldUseVPN(domain) // get again in case there is high priority rules
			if useVPNDNS {
				sendVPNDNSResponse(isTemporaryDecision)
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
		log.Printf("Failed to read CIDR file from %s, skip loading local CIDR info.\n", err.Error())
		return
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
		client: &dns.Client{
			Net:     net,
			Timeout: time.Second * time.Duration(*queryTimeoutInSeconds),
		},
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

func onReady() {
	routeMgr := utils.NewRouteMgr(*vpnGateway, *regularGateway)
	anotherDNSStart()
	systray.SetTitle("🚥")
	vpnResMgr = routeMgr

	vpnAll := systray.AddMenuItem("All", "Send all traffic to VPN")
	vpnNothing := systray.AddMenuItem("Direct", "Send all traffic to original network, nothing through VPN")
	autoDetect := systray.AddMenuItem("Auto", "Auto detect")
	detectOnTheFly := autoDetect.AddSubMenuItem("Detect on the fly", "will be slidely slower on domain first seen")
	quickLocalFallback := autoDetect.AddSubMenuItem("Quick local fallback", "for domain first seen, use local network first")
	quickVPNFallback := autoDetect.AddSubMenuItem("Quick VPN fallback", "for domain first seen, use VPN network first")
	static := systray.AddMenuItem("Static", "Based on static config and previous knowledge")
	staticLocalFallback := static.AddSubMenuItem("Prefer local", "Unmatched domain prefer on local network")
	staticVPNFallback := static.AddSubMenuItem("Prefer VPN", "Unmatched domain prefer on VPN network")

	allOptions := []*systray.MenuItem{
		vpnAll, vpnNothing,
		autoDetect, detectOnTheFly, quickLocalFallback, quickVPNFallback,
		static, staticLocalFallback, staticVPNFallback,
	}

	unCheckAll := func() {
		for _, opt := range allOptions {
			opt.Uncheck()
		}
	}

	routeMgr.VPNAuto()
	switch *detectMode {
	case 0:
		autoDetect.Check()
		switch *noKnowledgeMode {
		case 0:
			detectOnTheFly.Check()
		case 1:
			quickLocalFallback.Check()
		case 2:
			quickVPNFallback.Check()
		}
	case 1:
		static.Check()
		staticLocalFallback.Check()
	case 2:
		static.Check()
		staticVPNFallback.Check()
	}

	terminateCh := buildTerminateSignalCh()

	for {
		select {
		case <-terminateCh:
			systray.Quit()
		case <-vpnAll.ClickedCh:
			unCheckAll()
			routeMgr.VPNAll()
			vpnAll.Check()
		case <-vpnNothing.ClickedCh:
			unCheckAll()
			routeMgr.VPNNothing()
			vpnNothing.Check()
		case <-detectOnTheFly.ClickedCh:
			unCheckAll()
			routeMgr.VPNAuto()
			*detectMode = 0
			*noKnowledgeMode = 0
			autoDetect.Check()
			detectOnTheFly.Check()
		case <-quickLocalFallback.ClickedCh:
			unCheckAll()
			routeMgr.VPNAuto()
			*detectMode = 0
			*noKnowledgeMode = 1
			autoDetect.Check()
			quickLocalFallback.Check()
		case <-quickVPNFallback.ClickedCh:
			unCheckAll()
			routeMgr.VPNAuto()
			*detectMode = 0
			*noKnowledgeMode = 2
			autoDetect.Check()
			quickVPNFallback.Check()
		case <-staticLocalFallback.ClickedCh:
			unCheckAll()
			routeMgr.VPNAuto()
			*detectMode = 1
			static.Check()
			staticLocalFallback.Check()
		case <-staticVPNFallback.ClickedCh:
			routeMgr.VPNAuto()
			*detectMode = 2
			unCheckAll()
			static.Check()
			staticVPNFallback.Check()
		}
	}
}

func onExit() {
	// clean up here
	vpnResMgr.Stop()
	anotherDNSCleanup()
	log.Println("exit.")
}

func anotherDNSStart() {
	policies = utils.NewPolicyMgr(*maxMemorizeItems)
	policies.Load(*policyStaticFile, *policyMemorizeFile)

	loadLocalCIDR()

	go refreshProbeTimeout()
	go startServer("udp")
	go startServer("tcp")

	log.Printf("Working on port %d\n", *port)
}

func anotherDNSCleanup() {
	policies.Write(*policyMemorizeFile)
}

func buildTerminateSignalCh() chan os.Signal {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGKILL)
	return sig
}

func main() {
	flag.Parse()

	if *macOSMode {
		systray.Run(onReady, onExit)
	} else {
		if *enableNATOnVPNDNS {
			vpnResMgr = utils.NewNat(*natRange, *natIn)
			defer vpnResMgr.Stop()
		}
		anotherDNSStart()
		s := <-buildTerminateSignalCh()
		log.Printf("Signal (%v) received, stopping\n", s)
		anotherDNSCleanup()
	}
}
