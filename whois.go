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

var (
	CacheIANA  = make(map[string]string)
	CacheWhois = make(map[string]string)
)

type server struct {
	domain string
	zone   string
}

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
		res, err = GetWhoisData(domainUnicode, server.domain, timeout)
		if CorrectWhoisInfo(res) {
			CacheWhois[server.zone] = server.domain
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

func GetPossibleWhoisServers(domain string, timeout time.Duration) (whoisServers []*server, err error) {
	parts := strings.Split(domain, ".")
	lenDomain := len(parts)

	topLevelDomain := parts[lenDomain-1]
	if lenDomain > 2 {
		secondLevelDomain := parts[lenDomain-2] + "." + parts[lenDomain-1]
		if val, ok := CacheWhois[secondLevelDomain]; ok {

			whoisServers = append(whoisServers, &server{val, secondLevelDomain})
		}
		whoisServers = append(whoisServers, &server{"whois.nic." + secondLevelDomain, secondLevelDomain})
		whoisServers = append(whoisServers, &server{"whois." + secondLevelDomain, secondLevelDomain})
	}

	if val, ok := CacheWhois[topLevelDomain]; ok {
		whoisServers = append(whoisServers, &server{topLevelDomain, val})
	}
	whoisServers = append(whoisServers, &server{"whois.nic." + topLevelDomain, topLevelDomain})
	whoisServers = append(whoisServers, &server{"whois." + topLevelDomain, topLevelDomain})
	whoisServers = append(whoisServers, &server{defaulWhoisServer, topLevelDomain})
	whoisServers = append(whoisServers, &server{topLevelDomain + aliasWhoisServer, topLevelDomain})

	if val, ok := CacheIANA[topLevelDomain]; ok {
		whoisServers = append(whoisServers, &server{val, topLevelDomain})
	} else if whoisFromIANA := GetWhoisServerFromIANA(topLevelDomain, timeout); whoisFromIANA != "" {
		whoisServers = append(whoisServers, &server{whoisFromIANA, topLevelDomain})
		CacheIANA[topLevelDomain] = whoisFromIANA
	}

	// log.Printf("possible whois server: %v\n", strings.Join(whoisServers, ", "))
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
