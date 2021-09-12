package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	Client           http.Client
	ErrorLogger      *log.Logger
	ValidStatusCodes map[int]bool
)

// HTTP client and Loggers initialization
func init() {
	Client = http.Client{}
	ErrorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)
	flag.Usage = usage
	ValidStatusCodes = make(map[int]bool)
}

// Prints command's usage
func usage() {
	_, _ = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	print("\n")
}

func main() {
	// Flag parsing
	addressList := flag.String("l", "", "File with every IP/Range to test")
	httpProxy := flag.String("proxy", "", "HTTP proxy to use. HTTP, HTTPs and SOCKS5 are supported")
	cookieString := flag.String("c", "", "Cookie string to send with every request. Helps to deal with WAFs blocking automated requests")
	validStatusCodes := flag.String("s", "", "Valid status codes other than 2xx")
	responseTimeout := flag.String("t", "10s", "Timeout in seconds while checking hosts")

	flag.Parse()

	// Base URL / Target positional argument parsing
	if flag.NArg() != 1 {
		flag.Usage()
		ErrorLogger.Fatalln("missing target to bypass")
	}
	baseUrl := flag.Arg(0)

	// Set up HTTP Proxy
	if len(*httpProxy) > 0 {
		proxyURL, err := url.Parse(*httpProxy)
		if err != nil {
			ErrorLogger.Fatalln(err.Error())
		}
		Client.Transport = &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		Client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// Parse Valid status codes
	for _, strCode := range strings.Split(*validStatusCodes, ",") {
		code, err := strconv.Atoi(strCode)
		if err == nil {
			ValidStatusCodes[code] = true
		}
	}

	// Set timeout to client
	timeoutDuration, err := time.ParseDuration(*responseTimeout)
	if err != nil {
		ErrorLogger.Fatalln(err.Error())
	}
	Client.Timeout = timeoutDuration

	// Begin test execution

	var (
		addresses []string
	)

	// Posible Origin Server Addresses reading
	if len(*addressList) > 0 {
		addresses, err = getAddressesFromFile(*addressList)
		if err != nil {
			ErrorLogger.Fatalf("Unable to read \"%s\"", addressList)
		}
	} else {
		addresses, err = getAddressesFromStdin()
		if err != nil {
			ErrorLogger.Fatalln(err)
		}
	}

	// VHost and path parsing
	u, err := url.Parse(baseUrl)
	if err != nil {
		ErrorLogger.Fatalf("Could not parse given url: %s", baseUrl)
	}
	vhost := u.Host

	// Original request
	originalBody, err := doRequest(http.MethodGet, u.String(), vhost, *cookieString)
	if err != nil {
		ErrorLogger.Fatalf(err.Error())
	}
	comparator := metrics.NewSorensenDice()
	comparator.CaseSensitive = true
	comparator.NgramSize = 8

	var wg sync.WaitGroup

	for _, address := range addresses {
		wg.Add(1)
		go performTest(originalBody, *u, comparator, address, &wg, *cookieString)
	}

	// Wait for every goroutine to finish
	wg.Wait()
}

// Reads and parses a file with IPs, ranges and networks in CIDR format
func getAddressesFromFile(filename string) ([]string, error) {
	var addresses []string
	f, err := os.ReadFile(filename)
	if err != nil {
		return []string{}, err
	}
	fileLines := strings.Split(string(f), "\n")

	for _, fileLine := range fileLines {
		parsedAddresses, _ := parseAddresses(fileLine)
		addresses = append(addresses, parsedAddresses...)
	}

	return addresses, nil
}

// Reads and parses from stdin IPs, ranges and networks in CIDR format
func getAddressesFromStdin() ([]string, error) {
	var addresses []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		parsedAddresses, _ := parseAddresses(sc.Text())
		addresses = append(addresses, parsedAddresses...)
	}
	return addresses, nil
}

// Worker to make a request and compare it
func performTest(originalBody string, u url.URL, comparator strutil.StringMetric, address string, wg *sync.WaitGroup, cookieString string) {
	defer wg.Done()
	vhost := u.Host
	u.Host = address
	checkedBody, err := doRequest(http.MethodGet, u.String(), vhost, cookieString)

	if err != nil {

	} else {
		similarity := strutil.Similarity(checkedBody, originalBody, comparator)
		fmt.Printf("%-17s%.2f%%\n", address, similarity*100)
	}
}

// Parses networks in CIDR format to an address list
func parseCIDRNetwork(ipRange string) ([]string, error) {
	var addresses []string
	_, ipv4Net, err := net.ParseCIDR(ipRange)
	if err != nil {
		return nil, err
	}

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	end := (start & mask) | (mask ^ 0xffffffff)

	for i := start; i < end; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		addresses = append(addresses, ip.String())
	}

	return addresses, nil
}

// Parses networks in a "block" format to an IP address list. A format like
// this would be 192.168.0.0-192.168.0.255
func parseNetworkBlock(ipBlock string) ([]string, error) {
	block := strings.TrimSpace(ipBlock)
	edges := strings.Split(block, "-")
	if len(edges) != 2 {
		ErrorLogger.Panicf("\"%s\" is not a valid block. Missing or more than 1 slash\n")
	}

	// Block start/end parsing
	ipv4AddrStart := net.ParseIP(edges[0])
	start := binary.BigEndian.Uint32(ipv4AddrStart.To4())
	ipv4AddrEnd := net.ParseIP(edges[1])
	end := binary.BigEndian.Uint32(ipv4AddrEnd.To4())

	// IP calculation
	var addresses []string
	for i := start; i <= end; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		addresses = append(addresses, ip.String())
	}

	return addresses, nil
}

// Parses given addresses into an IP list. Accepts the following formats:
//   - 192.168.0.0/24
//   - 192.168.0.1 - 192.168.0.255
//   - 192.168.0.4 (Just an IP)
func parseAddresses(address string) ([]string, error) {
	var (
		parsedRange []string
		err         error
	)
	if strings.Contains(address, "/") {
		parsedRange, err = parseCIDRNetwork(address)
	} else if strings.Contains(address, "-") {
		parsedRange, err = parseNetworkBlock(address)
		if err != nil {
			println(err.Error())
		}
	} else {
		parsedRange = []string{address}
	}

	if err != nil {
		ErrorLogger.Printf("Unable to parse \"%s\". Skipping...\n", address)
		err = nil
	}
	return parsedRange, nil
}

// Makes a request to a given url changing its host header. Returns response
// body as a string
func doRequest(method string, u string, vhost string, cookieString string) (string, error) {
	req, err := http.NewRequest(method, u, strings.NewReader(""))
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36")
	if len(cookieString) > 0 {
		req.Header.Set("Cookie", cookieString)
	}
	req.Host = vhost

	response, err := Client.Do(req)
	if err != nil {
		return "", err
	}
	statusCode := response.StatusCode
	if statusCode >= 300 && !ValidStatusCodes[statusCode] {
		return "", fmt.Errorf("server error: status %d", response.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(bodyBytes), nil
}
