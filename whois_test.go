package whois

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestGetWhois(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"whois data", args{"google.com"}, "google.com", false},
		{"whois error", args{"8.8.8.8"}, "", true},
		{"whois error", args{"abracadabra"}, "", true},
		{"whois IDNA", args{"кирпич.москва"}, "xn--h1aaeve8b.xn--80adxhks", false},
		{"whois server with second level domains", args{"russia.edu.ru"}, "russia.edu.ru", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetWhois(tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetWhois() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			got = strings.Join(parser(regexp.MustCompile(`(?i)(Domain Name|domain):\s+(.*?)(\s|$)`), 2, got), "")

			if got != tt.want {
				t.Errorf("GetWhois() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetWhoisTimeout(t *testing.T) {
	type args struct {
		domain  string
		timeout time.Duration
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"whois error", args{"google.com", 10 * time.Millisecond}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetWhoisTimeout(tt.args.domain, tt.args.timeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetWhoisTimeout() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetWhoisTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetWhoisServerFromIANA(t *testing.T) {
	type args struct {
		zone    string
		timeout time.Duration
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"whois zone server com", args{"com", 5 * time.Second}, "whois.verisign-grs.com"},
		{"whois zone server jp", args{"jp", 5 * time.Second}, "whois.jprs.jp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetWhoisServerFromIANA(tt.args.zone, tt.args.timeout); got != tt.want {
				t.Errorf("GetWhoisServerFromIANA() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetWhoisData(t *testing.T) {
	type args struct {
		domain  string
		server  string
		timeout time.Duration
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"whois data", args{"google.com", "whois.markmonitor.com", 5 * time.Second}, "Domain Name: google.com", false},
		{"whois data", args{"webo.jp", "whois.jprs.jp", 5 * time.Second}, "[ JPRS database provides", false},
		{"whois data", args{"asgard.de", "whois.denic.de", 5 * time.Second}, "Domain: asgard.de", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetWhoisData(tt.args.domain, tt.args.server, tt.args.timeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetWhoisData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got = got[:len(tt.want)]
			if got != tt.want {
				t.Errorf("GetWhoisData() = '%v', want '%v'", got, tt.want)
			}
		})
	}
}
