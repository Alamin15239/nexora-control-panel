//go:build linux

package staticvhost

import "testing"

func validRegistryEntries() ([]brokerAccountRecord, []brokerDomainRecord) {
	return []brokerAccountRecord{
		{HostingAccountID:"hosting_a", LinuxUsername:"nexora_a", LinuxUID:1101},
		{HostingAccountID:"hosting_b", LinuxUsername:"nexora_b", LinuxUID:1102},
	}, []brokerDomainRecord{
		{DomainID:"domain_a", HostingAccountID:"hosting_a", Hostname:"www.a.example.test"},
		{DomainID:"domain_b", HostingAccountID:"hosting_b", Hostname:"www.b.example.test"},
	}
}

func TestNewBindingRegistryAcceptsConsistentAccountAndDomainMappings(t *testing.T) {
	accounts, domains := validRegistryEntries()
	registry, err := NewBindingRegistry(accounts, domains)
	if err != nil { t.Fatal(err) }
	if err := registry.Validate(Binding{DomainID:"domain_a", HostingAccountID:"hosting_a", Hostname:"www.a.example.test"}); err != nil {
		t.Fatalf("valid root-owned mapping was rejected: %v", err)
	}
}

func TestBindingRegistryRejectsSignedClaimMismatches(t *testing.T) {
	accounts, domains := validRegistryEntries()
	registry, err := NewBindingRegistry(accounts, domains)
	if err != nil { t.Fatal(err) }
	tests := []struct{name string; binding Binding}{
		{"unknown domain", Binding{DomainID:"domain_missing", HostingAccountID:"hosting_a", Hostname:"www.a.example.test"}},
		{"wrong account", Binding{DomainID:"domain_a", HostingAccountID:"hosting_b", Hostname:"www.a.example.test"}},
		{"wrong hostname", Binding{DomainID:"domain_a", HostingAccountID:"hosting_a", Hostname:"attacker.example.test"}},
		{"missing hostname", Binding{DomainID:"domain_a", HostingAccountID:"hosting_a"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := registry.Validate(tc.binding); err == nil {
				t.Fatal("accepted signed claims that do not match the root-owned registry")
			}
		})
	}
}

func TestNewBindingRegistryRejectsDuplicateOrInvalidLinuxIdentities(t *testing.T) {
	tests := []struct{name string; mutate func([]brokerAccountRecord, []brokerDomainRecord) ([]brokerAccountRecord, []brokerDomainRecord)}{
		{"duplicate account id", func(a []brokerAccountRecord, d []brokerDomainRecord) ([]brokerAccountRecord, []brokerDomainRecord) {
			a = append(a, a[0]); return a, d
		}},
		{"duplicate Linux username", func(a []brokerAccountRecord, d []brokerDomainRecord) ([]brokerAccountRecord, []brokerDomainRecord) {
			a[1].LinuxUsername = a[0].LinuxUsername; return a, d
		}},
		{"duplicate Linux UID", func(a []brokerAccountRecord, d []brokerDomainRecord) ([]brokerAccountRecord, []brokerDomainRecord) {
			a[1].LinuxUID = a[0].LinuxUID; return a, d
		}},
		{"root UID", func(a []brokerAccountRecord, d []brokerDomainRecord) ([]brokerAccountRecord, []brokerDomainRecord) {
			a[0].LinuxUID = 0; return a, d
		}},
		{"unsafe username", func(a []brokerAccountRecord, d []brokerDomainRecord) ([]brokerAccountRecord, []brokerDomainRecord) {
			a[0].LinuxUsername = "../root"; return a, d
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, d := validRegistryEntries()
			a, d = tc.mutate(a, d)
			if _, err := NewBindingRegistry(a, d); err == nil {
				t.Fatal("accepted invalid Linux account mapping")
			}
		})
	}
}

func TestNewBindingRegistryRejectsUnknownAccountAndInvalidDomain(t *testing.T) {
	t.Run("unknown account", func(t *testing.T) {
		a, d := validRegistryEntries()
		d[0].HostingAccountID = "hosting_missing"
		if _, err := NewBindingRegistry(a, d); err == nil { t.Fatal("accepted a domain for an unknown account") }
	})
	t.Run("invalid hostname", func(t *testing.T) {
		a, d := validRegistryEntries()
		d[0].Hostname = "example.test; include /etc/passwd;"
		if _, err := NewBindingRegistry(a, d); err == nil { t.Fatal("accepted an unsafe hostname") }
	})
	t.Run("duplicate domain id", func(t *testing.T) {
		a, d := validRegistryEntries()
		d = append(d, d[0])
		if _, err := NewBindingRegistry(a, d); err == nil { t.Fatal("accepted duplicate domain identity") }
	})
}

func TestBindingRegistryFailsClosedWhenUnavailable(t *testing.T) {
	var registry *BindingRegistry
	if err := registry.Validate(Binding{DomainID:"domain_a", HostingAccountID:"hosting_a", Hostname:"www.a.example.test"}); err == nil {
		t.Fatal("accepted a binding without a loaded registry")
	}
}
