// TODO: support IP addresses (including non-/32 subnets)

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Ip   string `json:"ip"`
	Host string `json:"hostname"`
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// Some sites return different sets of IPs among lookup calls (due to load balancing,  etc.).
// We make multiple lookup iterations to collect most/all of them.
const lookupIterations = 4

// Sleep period in ms between consequent lookups.
const sleepBetweenLookupsMs = 5 * time.Millisecond

// Parse plain-text file with domain names.
// - domains are space-/newline-separated
// - empty lines are ignored
// - everything starting from '#' symbol is ignored up to the EOL
func readDomainsFromFile(file *os.File) ([]string, error) {
	// Here we slighly patch the predefined `ScanWords` scanner in order to support '#'-comments.
	//
	// see ScanWords in https://cs.opensource.google/go/go/+/refs/tags/go1.25.7:src/bufio/scan.go;l=403
	// use plain ASCII, no unicode in domain names :)
	wordScannerWithoutComments := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		start := 0
		// skip leading spaces
		for ; start < len(data); start++ {
			if !isSpace(data[start]) {
				break
			}
		}
		// remove one or more consecutive comments ('#...') if any
		for { // this loop is when there are multiple commented lines
			if start >= len(data) || data[start] != '#' {
				break
			}
			start++
			for ; start < len(data); start++ { // skip until EOL
				if data[start] == '\n' {
					break
				}
			}
			for ; start < len(data); start++ { // skip spaces
				if !isSpace(data[start]) {
					break
				}
			}
		}
		// scan until space, marking end of word
		for i := start; i < len(data); i++ {
			if isSpace(data[i]) {
				return i + 1, data[start:i], nil
			}
		}
		// if we're at EOF, we have a final, non-empty, non-terminated word; return it
		if atEOF && len(data) > start {
			return len(data), data[start:], nil
		}
		// request more data
		return start, nil, nil
	}

	domains := []string{}

	scanner := bufio.NewScanner(file)
	scanner.Split(wordScannerWithoutComments)
	for scanner.Scan() {
		domain := scanner.Text()
		if domain == "" {
			continue
		}
		domains = append(domains, domain)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

func processDomainsFile(wg *sync.WaitGroup, path string, domainsCh chan<- string) {
	defer wg.Done()

	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("File %v cannot be read: %v", path, err)
	}
	defer file.Close()

	domains, err := readDomainsFromFile(file)
	if err != nil {
		log.Fatalf("failed to read domains from file: %v", err)
	}

	log.Printf("total domains: %v", len(domains))

	slices.Sort(domains)

	origLen := len(domains)
	domains = slices.Compact(domains)

	if len(domains) != origLen {
		log.Printf("Warning: domains list contains %d duplicates.", origLen-len(domains))
	}

	for _, d := range domains {
		domainsCh <- d
	}
	close(domainsCh)
}

func processIps(wg *sync.WaitGroup, ipsCh <-chan string) {
	defer wg.Done()

	ips := []string{}
	for ip := range ipsCh {
		ips = append(ips, ip)
	}
	slices.Sort(ips)
	ips = slices.Compact(ips)

	entries := []Entry{}
	for _, ip := range ips {
		entries = append(entries, Entry{
			Host: ip + "/32",
			Ip:   "",
		})
	}

	js, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		log.Fatalln("conversion to JSON failed:", err)
	}
	fmt.Println(string(js))
}

func skipIP(ip string) bool {
	// TODO: skip other private ranges also:
	// - 192.168.0.0/16
	// - 172.16.0.0/12
	// - 10.0.0.0/8
	// - 169.254.0.0/16
	// - 100.64.0.0/10
	// - 224.0.0.0/4
	return ip == "0.0.0.0" || strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "169.254.")
}

func lookup(wg *sync.WaitGroup, id int, domainsCh <-chan string, ipsCh chan<- string) {
	defer wg.Done()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rs := &net.Resolver{PreferGo: true}

	for domain := range domainsCh {
		ips := map[string]bool{}

		for range lookupIterations {
			ipsRaw, err := rs.LookupIP(ctx, "ip4", domain)
			//log.Println("processing domain", domain)
			if err != nil {
				log.Printf("worker %v: Domain lookup failed for %v : %v", id, domain, err)
				break
			}

			for _, ip := range ipsRaw {
				ipStr := ip.String()
				if skipIP(ipStr) {
					log.Printf("Waning: domain %v resolved into suspicious IP %v", domain, ipStr)
					continue
				}
				ips[ipStr] = true
			}
			time.Sleep(sleepBetweenLookupsMs)
		}

		ipsArr := []string{}
		for ip := range ips {
			ipsArr = append(ipsArr, ip)
		}
		slices.Sort(ipsArr)

		log.Printf("IPs for domain %v: %v", domain, ipsArr)

		for _, ip := range ipsArr {
			ipsCh <- ip
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalln("Usage: go run list-to-json.go my-sites.lst > my-sites.json")
	}
	domainsFile := os.Args[1]

	chanSize := 5
	domainsCh := make(chan string, chanSize) // domains
	ipsCh := make(chan string, chanSize)     // IP addreses resolved from domains

	var wg1 sync.WaitGroup
	var wg2 sync.WaitGroup

	// write domains to channel
	go processDomainsFile(&wg1, domainsFile, domainsCh)
	wg1.Add(1)

	// read domains from channel, resolve IPs, and write results to another channel
	maxWorkers := 10
	for i := range maxWorkers {
		go lookup(&wg1, i, domainsCh, ipsCh)
		wg1.Add(1)
	}

	// collect all IPs
	go processIps(&wg2, ipsCh)
	wg2.Add(1)

	wg1.Wait()
	// processDomainsFile() and all lookup() threads are finished => we can close ipsCh
	close(ipsCh)

	wg2.Wait()

	log.Println("All IPs are successfully resolved!")
}
