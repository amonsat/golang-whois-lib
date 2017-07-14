package whois

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	ZoneWhoisServer   = "whois.iana.org"
	defaulWhoisServer = "whois.arin.net"
	aliasWhoisServer  = ".whois-servers.net"
)

func GetWhois(domain string) (string, error) {
	return GetWhoisTimeout(domain, time.Second*5)
}

func GetWhoisTimeout(domain string, timeout time.Duration) (string, error) {
	log.Printf("Analize domain: %v\n", domain)

	if !strings.Contains(domain, ".") {
		return "", fmt.Errorf("domain (%v) name is wrong", domain)
	}

	domainUnicode, err := idna.ToASCII(domain)
	if err != nil {
		return "", err
	}
	log.Printf("Convert domain to ASCII: %v\n", domainUnicode)

	servers, errPos := GetPossibleWhoisServers(domainUnicode, timeout)
	if errPos != nil {
		return "", errPos
	}

	var res string
	for _, server := range servers {
		res, err = GetWhoisData(domainUnicode, server, timeout)
		if CorrectWhoisInfo(res) {
			log.Printf("Correct whois server: %v\n", server)
			break
		}
		res = ""
		// errorAnswer := regexp.MustCompile(`(?i)(Not found|No match for|No entries found)`)
		// if len(errorAnswer.FindStringSubmatch(res)) == 0 {
		// 	fmt.Printf("Correct whois server: %v\n", server)
		// 	break
		// }
	}

	return res, err
}

func GetPossibleWhoisServers(domain string, timeout time.Duration) (whoisServers []string, err error) {
	parts := strings.Split(domain, ".")
	lenDomain := len(parts)

	topLevelDomain := parts[lenDomain-1]
	if lenDomain > 2 {
		secondLevelDomain := parts[lenDomain-2] + "." + parts[lenDomain-1]
		whoisServers = append(whoisServers, "whois.nic."+secondLevelDomain)
		whoisServers = append(whoisServers, "whois."+secondLevelDomain)
	}

	whoisServers = append(whoisServers, "whois.nic."+topLevelDomain)
	whoisServers = append(whoisServers, "whois."+topLevelDomain)
	whoisServers = append(whoisServers, defaulWhoisServer)
	whoisServers = append(whoisServers, topLevelDomain+aliasWhoisServer)

	if whoisFromIANA := GetWhoisServerFromIANA(topLevelDomain, timeout); whoisFromIANA != "" {
		whoisServers = append(whoisServers, whoisFromIANA)
	}

	log.Printf("possible whois server: %v\n", strings.Join(whoisServers, ", "))
	return
}

func GetWhoisServerFromIANA(zone string, timeout time.Duration) string {
	data, err := GetWhoisData(zone, ZoneWhoisServer, timeout)
	if err != nil {
		return ""
	}
	result := ParseWhoisServer(data)
	return result
}

func GetWhoisData(domain, server string, timeout time.Duration) (string, error) {
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), timeout)
	if err != nil {
		return "", err
	}
	defer connection.Close()

	connection.Write([]byte(domain + "\r\n"))
	buffer, err := ioutil.ReadAll(connection)
	if err != nil {
		return "", err
	}
	return string(buffer[:]), nil
}
