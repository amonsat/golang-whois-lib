package whois

import (
	"regexp"
	"strings"
)

func parser(re *regexp.Regexp, group int, data string) (result []string) {
	found := re.FindAllStringSubmatch(data, -1)
	if len(found) > 0 {
		for _, one := range found {
			if len(one) >= 2 && len(one[group]) > 0 {
				result = appendIfMissing(result, one[group])
			}
		}
	}
	return
}

func ParseWhoisServer(whois string) string {
	return parser(regexp.MustCompile(`(?i)whois:\s+(.*?)(\s|$)`), 1, whois)[0]
}

func ParseReferServer(whois string) string {
	return parser(regexp.MustCompile(`(?i)refer:\s+(.*?)(\s|$)`), 1, whois)[0]
}

//Parse uniq name servers from whois
func ParseNameServers(whois string) []string {
	return parser(regexp.MustCompile(`(?i)(Name )?(n)?Server:\s+(.*?)(\s|$)`), 3, whois)
}

//Parse uniq domain status(codes) from whois
func ParseDomainStatus(whois string) []string {
	return parser(regexp.MustCompile(`(?i)(Domain )?Status:\s+(.*?)(\s|$)`), 2, whois)
}

func CorrectWhoisInfo(whois string) bool {
	if len(whois) == 0 {
		return false
	}
	hasDomain := parser(regexp.MustCompile(`(?i)(Domain)?( Name)?:\s+(.*?)(\s|$)`), 1, whois)
	return len(hasDomain) > 0
}

func appendIfMissing(slice []string, i string) []string {
	i = strings.ToLower(i)

	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}
