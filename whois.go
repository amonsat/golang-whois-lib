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
	zoneWhoisServer   = "whois.iana.org"
	defaulWhoisServer = "whois.arin.net"
	aliasWhoisServer  = ".whois-servers.net"
	brandWhoisServer  = "whois.markmonitor.com"
)

var (
	CacheIANA  = make(map[string]string)
	CacheWhois = make(map[string]string)
)

var whoisServerTemplate = map[string]string{
	"base":                   "%s\r\n",
	"whois.nic.de":           "-T dn,ace %s\r\n",
	"whois.denic.de":         "-T dn,ace %s\r\n",
	"whois.nic.name":         "domain = %s\r\n",
	"whois.dk-hostmaster.dk": "--show-handles %s\r\n",
	"whois.verisign-grs.com": "domain %s\r\n",
	"verisign-group":         "domain %s\r\n",
}

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
	domainUnicode = strings.ToLower(domainUnicode)

	servers, errPos := GetPossibleWhoisServers(domainUnicode, timeout)
	if errPos != nil {
		return "", errPos
	}

	var res string
	for _, server := range servers {

		template := whoisServerTemplate["base"]
		if val, ok := whoisServerTemplate[server.domain]; ok {
			template = val
		}

		res, err = GetWhoisData(domainUnicode, server.domain, template, timeout)

		if res != "" {
			if isVerisignGroup(res) {
				res, err = GetWhoisData(domainUnicode, server.domain, whoisServerTemplate["verisign-group"], timeout)
			}

			if refWhoisServer, ok := hasRefferWhoisServer(res); ok {
				template := whoisServerTemplate["base"]
				if val, ok := whoisServerTemplate[refWhoisServer]; ok {
					template = val
				}

				refRes, _ := GetWhoisData(domainUnicode, refWhoisServer, template, timeout)
				if whoisWeight(refRes) > whoisWeight(res) {
					res = refRes
				}
			}
		}

		if IsWhoisDataCorrect(res) {
			CacheWhois[server.zone] = server.domain
			log.Printf("Correct whois server: %v\n", server.domain)
			break
		} else if ParseNofound(res) {
			return "", nil
		}
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

	return
}

func GetWhoisServerFromIANA(zone string, timeout time.Duration) string {
	data, err := GetWhoisData(zone, zoneWhoisServer, whoisServerTemplate["base"], timeout)
	if err != nil {
		return ""
	}
	result := ParseWhoisServer(data)
	return result
}

func GetWhoisData(domain, server, template string, timeout time.Duration) (string, error) {
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), timeout)
	if err != nil {
		return "", err
	}
	defer connection.Close()

	connection.Write([]byte(fmt.Sprintf(template, domain)))
	buffer, err := ioutil.ReadAll(connection)
	if err != nil {
		return "", err
	}
	result := string(buffer[:])

	return result, nil
}

func isVerisignGroup(data string) bool {
	veriSignGroupTemplate1 := `To single out one record, look it up with "xxx"`
	veriSignGroupTemplate2 := `look them up with "=xxx" to receive a full display`

	return strings.Contains(data, veriSignGroupTemplate1) && strings.Contains(data, veriSignGroupTemplate2)
}

func hasRefferWhoisServer(whoisString string) (string, bool) {
	data := ParseWhoisServer(whoisString)
	if len(data) > 0 {
		return data, true
	}
	return "", false
}
