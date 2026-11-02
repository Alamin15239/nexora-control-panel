package main

import "testing"

func TestUsernamePattern(t *testing.T) {
	valid := []string{"web001", "client_01", "abc"}
	for _, value := range valid {
		if !usernamePattern.MatchString(value) { t.Errorf("expected %q to be accepted", value) }
	}
	invalid := []string{"ab", "1client", "Client01", "client-name", "client.name", "client;id", "sixteen_char_name"}
	for _, value := range invalid {
		if usernamePattern.MatchString(value) { t.Errorf("expected %q to be rejected", value) }
	}
}

func TestDomainPattern(t *testing.T) {
	valid := []string{"example.com", "sub.example.co.uk", "nxoratest01.test", "a1.example-domain.com"}
	for _, value := range valid {
		if !domainPattern.MatchString(value) { t.Errorf("expected domain %q to be accepted", value) }
	}
	invalid := []string{"", "localhost", "-bad.example.com", "bad-.example.com", "bad..example.com", "bad;domain.com", "example.com/path", "example .com", "example.com\n"}
	for _, value := range invalid {
		if domainPattern.MatchString(value) { t.Errorf("expected domain %q to be rejected", value) }
	}
}

func TestDocumentRootPattern(t *testing.T) {
	valid := []string{"/home/client01/public_html", "/home/client_01/public_html/example.com"}
	for _, value := range valid {
		if !validDocumentRoot(value) { t.Errorf("expected document root %q to be accepted", value) }
	}
	invalid := []string{"/home/client01/public_html;include", "/home/client01/public_html with spaces", "/home/client01/../other", "/tmp/site", "/home/client01/.ssh", "/home/client01/public_html/.private", "/home/client01/public_html\\n"}
	for _, value := range invalid {
		if validDocumentRoot(value) { t.Errorf("expected document root %q to be rejected", value) }
	}
}
