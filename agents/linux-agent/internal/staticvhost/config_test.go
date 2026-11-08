package staticvhost

import (
	"strings"
	"testing"
)

func TestRenderUsesOnlyAccountDerivedReleaseRoot(t *testing.T) {
	config, err := Render(Binding{
		DomainID: "domain_123",
		Hostname: "www.example.test",
		HostingAccountID: "account_123",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"server_name www.example.test;",
		"root /var/lib/nexora-static/accounts/account_123/current;",
		"index index.html;",
		"autoindex off;",
		"try_files $uri $uri/ =404;",
		"return 404;",
		"deny all;",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("rendered config missing %q", want)
		}
	}
	for _, forbidden := range []string{"fastcgi_pass", "proxy_pass", "include ", "alias ", "lua_"} {
		if strings.Contains(config, forbidden) {
			t.Errorf("rendered config contains forbidden directive %q", forbidden)
		}
	}
}

func TestRenderRejectsUntrustedBindingValues(t *testing.T) {
	tests := []struct {
		name string
		binding Binding
	}{
		{"missing domain id", Binding{Hostname: "example.test", HostingAccountID: "account_1"}},
		{"invalid account id", Binding{DomainID: "domain_1", Hostname: "example.test", HostingAccountID: "../other"}},
		{"uppercase hostname", Binding{DomainID: "domain_1", Hostname: "Example.test", HostingAccountID: "account_1"}},
		{"hostname directive injection", Binding{DomainID: "domain_1", Hostname: "example.test; return 200", HostingAccountID: "account_1"}},
		{"wildcard hostname", Binding{DomainID: "domain_1", Hostname: "*.example.test", HostingAccountID: "account_1"}},
		{"single label", Binding{DomainID: "domain_1", Hostname: "localhost", HostingAccountID: "account_1"}},
		{"trailing dot", Binding{DomainID: "domain_1", Hostname: "example.test.", HostingAccountID: "account_1"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Render(test.binding); err == nil {
				t.Fatal("Render accepted an invalid binding")
			}
		})
	}
}

func TestConfigNameIsStableAndDoesNotContainDomainInput(t *testing.T) {
	first, err := ConfigName("domain_123")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ConfigName("domain_123")
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first == "" || strings.Contains(first, "domain_123") {
		t.Fatalf("unexpected config name: %q, %q", first, second)
	}
	if _, err := ConfigName("../etc/nginx"); err == nil {
		t.Fatal("ConfigName accepted a path-like domain identity")
	}
}
