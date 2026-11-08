// Package staticvhost renders a deliberately narrow Nginx server block for
// Nexora-managed static releases. It does not install, enable, test, or reload
// Nginx; those operations belong to the privileged provisioning boundary.
package staticvhost

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	accountIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	domainIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Binding is resolved by the control plane from the project's hosting account
// and its eligible domain. Callers must not populate it from artifact content.
type Binding struct {
	DomainID string
	Hostname string
	HostingAccountID string
}

// ConfigName returns a deterministic, collision-resistant filename that does
// not expose customer-controlled domain text in the Nginx filesystem namespace.
func ConfigName(domainID string) (string, error) {
	if !domainIDPattern.MatchString(domainID) {
		return "", errors.New("invalid domain identity")
	}
	sum := sha256.Sum256([]byte(domainID))
	return "nexora-static-" + hex.EncodeToString(sum[:16]) + ".conf", nil
}

// Render derives the document root exclusively from the validated hosting
// account ID. It intentionally emits no PHP/FastCGI, alias, include, or
// customer-supplied Nginx directives.
func Render(binding Binding) (string, error) {
	if !domainIDPattern.MatchString(binding.DomainID) {
		return "", errors.New("invalid domain identity")
	}
	if !accountIDPattern.MatchString(binding.HostingAccountID) {
		return "", errors.New("invalid hosting account identity")
	}
	hostname := strings.ToLower(strings.TrimSpace(binding.Hostname))
	if hostname != binding.Hostname || len(hostname) > 253 || strings.HasSuffix(hostname, ".") {
		return "", errors.New("hostname must be canonical lowercase DNS text")
	}
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return "", errors.New("hostname must be a fully-qualified domain name")
	}
	for _, label := range labels {
		if len(label) > 63 || !dnsLabelPattern.MatchString(label) {
			return "", errors.New("hostname contains an invalid DNS label")
		}
	}

	root := fmt.Sprintf("/var/lib/nexora-static/accounts/%s/current", binding.HostingAccountID)
	return fmt.Sprintf(`# Managed by Nexora. Do not edit.
server {
    listen 80;
    server_name %s;

    root %s;
    index index.html;
    autoindex off;
    server_tokens off;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~* \.php(?:$|/) {
        return 404;
    }

    location ~ /\. {
        deny all;
    }
}
`, hostname, root), nil
}
