package utils

import (
	"bufio"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type dnsPolicy struct {
	domain     string
	useVPN     bool
	queryCount int64
}

type keywordPolicy struct {
	keyword string
	useVPN  bool
}

// PolicyManager defines how we manage DNS policy
type PolicyManager struct {
	domainPolicies  map[string]bool
	suffixPolicies  map[string]bool
	keywordPolicies []keywordPolicy
	learnedPolicies map[string]*dnsPolicy // learned policy will be lowest priority
	lock            sync.RWMutex
	maxMemoryItems  int
}

// NewPolicyMgr new policy manager instance
func NewPolicyMgr(maxMemorizeItems int) *PolicyManager {
	policies := PolicyManager{}
	policies.maxMemoryItems = maxMemorizeItems
	policies.domainPolicies = make(map[string]bool)
	policies.suffixPolicies = make(map[string]bool)
	policies.keywordPolicies = []keywordPolicy{}
	policies.learnedPolicies = make(map[string]*dnsPolicy)
	policies.learnedPolicies = make(map[string]*dnsPolicy)
	return &policies
}

// Load config files
func (p *PolicyManager) Load(staticFilePath string, memorizeFilePath string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	staticFile, err := os.Open(staticFilePath)
	if err != nil {
		log.Printf("Failed to static policy file %s, skip loading static config file.\n", err.Error())
		return
	}
	defer staticFile.Close()
	staticScanner := bufio.NewScanner(staticFile)
	for staticScanner.Scan() {
		line := strings.TrimSpace(strings.Split(strings.TrimSpace(staticScanner.Text()), "#")[0])
		if line == "" {
			continue
		}
		items := strings.Split(line, "\t")
		if len(items) != 3 {
			log.Panicf("Cannot read config: %s\n", line)
		}
		useVPN := items[1] == "T"
		if items[0] == "DOMAIN" {
			p.domainPolicies[items[2]] = useVPN
		} else if items[0] == "SUFFIX" {
			p.suffixPolicies[items[2]] = useVPN
		} else if items[0] == "KEYWORD" {
			p.keywordPolicies = append(p.keywordPolicies, keywordPolicy{items[2], useVPN})
		} else {
			log.Panicf("Cannot read config: %s, unknown type: %s\n", line, items[0])
		}
	}

	memorizeFile, err := os.Open(memorizeFilePath)
	if err != nil {
		log.Printf("Failed to memorize policy file %s, skip loading memory policy file.\n", err.Error())
		return
	}
	defer memorizeFile.Close()
	scanner := bufio.NewScanner(memorizeFile)
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
		p.learnedPolicies[domain] = policy
	}
}

// Write dynamic learned policy
func (p *PolicyManager) Write(fileName string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	file, err := os.Create(fileName)
	if err != nil {
		log.Printf("Failed to write policy file %s\n", err.Error())
		return
	}
	defer file.Close()

	for _, policy := range p.learnedPolicies {
		useVPNField := "F"
		if policy.useVPN {
			useVPNField = "T"
		}
		file.WriteString(useVPNField + "\t" + strconv.FormatInt(policy.queryCount, 10) + "\t" + policy.domain + "\n")
	}
}

// Get policy for domain
func (p *PolicyManager) Get(domain string) (bool, bool) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	withoutDotDomain := strings.TrimSuffix(domain, ".")

	items := strings.Split(withoutDotDomain, ".")
	itemsLen := len(items)

	if useVPN, ok := p.domainPolicies[strings.Join(items, ".")]; ok {
		log.Printf("matched static domain rule: %s, %t\n", domain, useVPN)
		return useVPN, true
	}

	for i := itemsLen - 1; i >= 0; i-- {
		if useVPN, ok := p.suffixPolicies[strings.Join(items[i:itemsLen], ".")]; ok {
			log.Printf("matched suffix domain rule: %s, %t\n", domain, useVPN)
			return useVPN, true
		}
	}

	for _, keywordPolicy := range p.keywordPolicies {
		if strings.Contains(domain, keywordPolicy.keyword) {
			log.Printf("matched keyword domain rule: %s, %t\n", domain, keywordPolicy.useVPN)
			return keywordPolicy.useVPN, true
		}
	}

	if res, ok := p.learnedPolicies[domain]; ok {
		res.queryCount++
		return res.useVPN, true
	}
	return false, false
}

// Set domain policy
func (p *PolicyManager) Set(domain string, useVPN bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.learnedPolicies[domain] = &dnsPolicy{
		domain:     domain,
		useVPN:     useVPN,
		queryCount: 1,
	}
}

// Gc clean grabage
func (p *PolicyManager) Gc() {
	p.lock.Lock()
	defer p.lock.Unlock()
	all := make([]*dnsPolicy, len(p.learnedPolicies))
	i := 0
	for _, policy := range p.learnedPolicies {
		all[i] = policy
		i++
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].queryCount > all[j].queryCount
	})
	for i = p.maxMemoryItems; i < len(all); i++ {
		delete(p.learnedPolicies, all[i].domain)
	}
}
