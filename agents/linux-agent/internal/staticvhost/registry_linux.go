//go:build linux

package staticvhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const brokerBindingRegistryPath = "/etc/nexora-static-vhost/bindings.json"

var linuxUsernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

type brokerBindingRegistryFile struct {
	Accounts []brokerAccountRecord `json:"accounts"`
	Domains  []brokerDomainRecord  `json:"domains"`
}

type brokerAccountRecord struct {
	HostingAccountID string `json:"hostingAccountId"`
	LinuxUsername    string `json:"linuxUsername"`
	LinuxUID         uint32 `json:"linuxUid"`
}

type brokerDomainRecord struct {
	DomainID         string `json:"domainId"`
	HostingAccountID string `json:"hostingAccountId"`
	Hostname         string `json:"hostname"`
}

// BindingRegistry is loaded only from the root-owned broker configuration.
// It is the independent trust anchor that ties signed control-plane claims to
// locally provisioned Linux accounts and domains.
type BindingRegistry struct {
	accounts map[string]brokerAccountRecord
	domains  map[string]brokerDomainRecord
}

func LoadRootBindingRegistry() (*BindingRegistry, error) {
	data, err := readRootOwnedFile(brokerBindingRegistryPath, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("read root-owned account/domain registry: %w", err)
	}
	var document brokerBindingRegistryFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode account/domain registry: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("account/domain registry contains trailing data")
	}
	return newBindingRegistry(document.Accounts, document.Domains)
}

// newBindingRegistry validates the complete registry before it can be used.
// Production loads it only from the fixed root-owned path above.
func newBindingRegistry(accounts []brokerAccountRecord, domains []brokerDomainRecord) (*BindingRegistry, error) {
	if len(accounts) == 0 || len(accounts) > 10000 || len(domains) == 0 || len(domains) > 50000 {
		return nil, errors.New("account/domain registry has invalid entry counts")
	}
	registry := &BindingRegistry{
		accounts: make(map[string]brokerAccountRecord, len(accounts)),
		domains:  make(map[string]brokerDomainRecord, len(domains)),
	}
	usernames := make(map[string]struct{}, len(accounts))
	uids := make(map[uint32]struct{}, len(accounts))
	for _, account := range accounts {
		if !accountIDPattern.MatchString(account.HostingAccountID) ||
			!linuxUsernamePattern.MatchString(account.LinuxUsername) ||
			account.LinuxUID < 1000 || account.LinuxUsername == "root" || account.LinuxUsername == "nobody" ||
			account.LinuxUsername == "nexora-runtime" || account.LinuxUsername == "nexora-agent" {
			return nil, errors.New("account registry contains an invalid hosting account or Linux identity")
		}
		if _, exists := registry.accounts[account.HostingAccountID]; exists {
			return nil, errors.New("account registry contains a duplicate hosting account")
		}
		if _, exists := usernames[account.LinuxUsername]; exists {
			return nil, errors.New("account registry contains a duplicate Linux username")
		}
		if _, exists := uids[account.LinuxUID]; exists {
			return nil, errors.New("account registry contains a duplicate Linux UID")
		}
		usernames[account.LinuxUsername] = struct{}{}
		uids[account.LinuxUID] = struct{}{}
		registry.accounts[account.HostingAccountID] = account
	}
	for _, domain := range domains {
		if !domainIDPattern.MatchString(domain.DomainID) ||
			!accountIDPattern.MatchString(domain.HostingAccountID) {
			return nil, errors.New("domain registry contains an invalid identity")
		}
		if _, exists := registry.domains[domain.DomainID]; exists {
			return nil, errors.New("domain registry contains a duplicate domain identity")
		}
		if _, exists := registry.accounts[domain.HostingAccountID]; !exists {
			return nil, errors.New("domain registry references an unknown hosting account")
		}
		binding := Binding{
			DomainID: domain.DomainID,
			Hostname: domain.Hostname,
			HostingAccountID: domain.HostingAccountID,
		}
		if _, err := Render(binding); err != nil {
			return nil, fmt.Errorf("domain registry contains an invalid canonical binding: %w", err)
		}
		registry.domains[domain.DomainID] = domain
	}
	return registry, nil
}

// Validate rejects signed claims unless all three identity fields exactly
// match one root-provisioned domain-to-account binding.
func (r *BindingRegistry) Validate(binding Binding) error {
	if r == nil {
		return errors.New("account/domain registry is unavailable")
	}
	domain, ok := r.domains[binding.DomainID]
	if !ok || domain.HostingAccountID != binding.HostingAccountID || domain.Hostname != binding.Hostname {
		return errors.New("signed domain/account claims do not match the root-owned registry")
	}
	if _, ok := r.accounts[binding.HostingAccountID]; !ok {
		return errors.New("signed hosting account is not present in the root-owned registry")
	}
	return nil
}
