# Cloudflare Tunnel for a Nexora Linux node

This setup publishes an Nginx origin that is behind NAT or a private VM network. It does not require inbound ports 80 or 443 on the VM.

## Prerequisites

- A real domain added to the same Cloudflare account, with its authoritative nameservers delegated to Cloudflare.
- A remotely-managed Cloudflare Tunnel created in Cloudflare Zero Trust under **Networking > Tunnels**.
- The Linux node can make outbound connections to Cloudflare. Cloudflare Tunnel uses outbound connections; allow the documented Tunnel connectivity ports in restrictive firewalls.
- Nginx is running and serves the intended virtual hosts on local port 80.

## Install the connector on Ubuntu

Pull the latest Nexora repository changes, then run:

```sh
cd ~/nexora-control-panel
git pull --ff-only origin main
sudo bash scripts/setup-cloudflare-tunnel.sh
```

The script installs the signed Cloudflare APT package, reads the remotely-managed tunnel token silently from the terminal, and registers `cloudflared` as a systemd service. Never paste the tunnel token into chat, Git, an issue, or a command that will be saved in shell history.

## Publish the first hostname

In **Cloudflare Zero Trust > Networking > Tunnels**, open the tunnel and add a **Published application** route:

- Hostname: a real hostname in a Cloudflare-managed zone, for example `www.example.com`
- Service: `http://localhost:80`

Save the route. Cloudflare creates or prompts for the corresponding proxied DNS record. The tunnel routes the request to local Nginx, and Nginx selects the matching virtual host from the HTTP Host header.

For each additional customer hostname, the hostname must be in a zone managed by Cloudflare and must have a matching published application route (or a deliberately designed wildcard route and DNS record). Do not assume that adding a domain to Nexora automatically creates its Cloudflare route; that API integration is a separate implementation step.

## Verify

On the Linux node:

```sh
sudo systemctl is-active cloudflared
sudo systemctl --no-pager --full status cloudflared
curl -I -H 'Host: www.example.com' http://127.0.0.1/
```

Then verify the tunnel is **Healthy** in Cloudflare and open the real hostname using HTTPS from a device outside the VM.

## Important limitations

- The reserved `.test` domain is for local testing only. It cannot be publicly delegated or receive a publicly trusted certificate.
- Cloudflare Tunnel does not configure the Nginx virtual host; Nexora's Linux agent continues to do that.
- This first connector setup does not yet automate per-customer hostname route creation, DNS record management, or SSL status reporting in the Nexora dashboard.
- Do not expose the VM's SSH port through a public application route. Keep SSH restricted to your administrative access path.
