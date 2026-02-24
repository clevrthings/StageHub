# StageHub

Realtime stage communication app with channels, file sharing, notifications, audio intercom, multi-project data separation and admin controls.

## One-click install (Raspberry Pi)

```bash
curl -fsSL https://raw.githubusercontent.com/clevrthings/StageHub/main/install.sh | sudo bash
```

The installer will:

- download/update the latest code from GitHub
- create a Python virtual environment and install dependencies
- show compact, colored progress steps during install/update (instead of verbose command output)
- ask for main config values (`port`, `username_case_sensitive`) with defaults
- install and enable a `systemd` service so StageHub auto-starts after reboot
- automatically migrate legacy `/opt/stagechat` installs/data to `/opt/stagehub`
- when updating an existing install with "keep data/config", reuse current service user and config without asking port/user settings again
- install CLI commands:
  - `stagehub start`
  - `stagehub stop`
  - `stagehub restart`
  - `stagehub status`
  - `stagehub update`
  - `stagehub expose ...`
  - `stagehub uninstall`
  - `stagehub` (help)

Default install values:

- `port`: `80` (so `http://<hostname>` works directly and redirects to HTTPS)
- `username_case_sensitive`: `false`

## Manual run (development)

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Notes

- Runtime config is stored in `config.json`.
- Project data is stored under `projects/`.
- HTTP requests on the configured port are redirected to HTTPS.
- Public/private internet exposure is managed only via Pi CLI (`stagehub expose`), not via web UI.

## Expose via CLI (Pi)

```bash
stagehub expose
```

`stagehub expose` starts an interactive menu so users do not need extra arguments.
Use arrow keys + Enter to navigate interactive CLI menus.

You can always check current state with:

```bash
stagehub expose status
```

### Cloudflare (full setup)

#### Option A: Quick one-click public URL (fastest)

```bash
stagehub expose cloudflare enable --mode quick
```

This creates a persistent Cloudflare quick tunnel and exposes StageHub on a `trycloudflare.com` URL.
If Cloudflare apt repo is unavailable for your Debian release (for example `trixie`), StageHub automatically falls back to GitHub release installation.
Installer updates also auto-remove an incompatible `cloudflared` apt source if present, so `stagehub update` keeps working.
StageHub now resolves the quick URL from the latest service start to avoid stale links.

Check status:

```bash
stagehub expose cloudflare status
stagehub expose status
```

If URL is not shown yet, check logs:

```bash
sudo journalctl -u stagehub-cloudflared-quick.service -n 120 --no-pager
```

Disable:

```bash
stagehub expose cloudflare disable
```

#### Option B: Custom domain (token-based tunnel)

1. In Cloudflare Zero Trust, create a tunnel and copy the tunnel token.  
2. Configure the public hostname in Cloudflare to point to StageHub backend:
   - target URL: `https://127.0.0.1:8443`
   - TLS verification: disabled (`no-tls-verify`) because StageHub uses local self-signed cert
3. Enable from Pi:

```bash
stagehub expose cloudflare enable --mode public --token '<TOKEN>'
```

For Access policy workflow (still token-based):

```bash
stagehub expose cloudflare enable --mode access-ready --token '<TOKEN>'
```

Then enforce authentication in Cloudflare Access dashboard.

#### API key / API token note

StageHub currently uses Cloudflare **tunnel token** for setup.  
No global API key/API-token automation is required in StageHub for the current flow.

### Tailscale (full setup)

#### One-time login on the Pi

```bash
sudo tailscale up
```

#### Private (tailnet-only) access

```bash
stagehub expose tailscale enable --mode private --local-port 8443
```

#### Public internet access (Funnel)

```bash
stagehub expose tailscale enable --mode public --local-port 8443
```

StageHub configures Tailscale Funnel on public HTTPS port `443` and proxies to the StageHub backend on `8443` (interactive mode uses this automatically).
After enable, StageHub prints the detected Tailscale URL (`https://<device>.ts.net`).

Status and routes:

```bash
stagehub expose tailscale status
stagehub expose status
tailscale serve status
tailscale funnel status
```

Disable:

```bash
stagehub expose tailscale disable
```

Equivalent manual cleanup command used under the hood:

```bash
tailscale funnel --https=443 off
```

### Troubleshooting

#### Cloudflare

```bash
sudo systemctl status cloudflared --no-pager
sudo systemctl status stagehub-cloudflared-quick.service --no-pager
sudo journalctl -u cloudflared -n 120 --no-pager
sudo journalctl -u stagehub-cloudflared-quick.service -n 120 --no-pager
```

#### Tailscale

If public link does not connect:

1. Verify Tailscale login:

```bash
tailscale status
```

2. Verify Funnel is allowed in your tailnet admin policy.  
3. Re-enable with explicit StageHub backend:

```bash
stagehub expose tailscale disable
stagehub expose tailscale enable --mode public --local-port 8443
```

To force-clear old routes manually:

```bash
tailscale funnel --https=443 off
tailscale serve --https=443 off
tailscale funnel reset
tailscale serve reset
```

4. Verify StageHub is running:

```bash
stagehub status
```

#### Quick reference commands

```bash
stagehub expose cloudflare enable --mode quick
stagehub expose cloudflare enable --mode public --token '<TOKEN>'
stagehub expose cloudflare enable --mode access-ready --token '<TOKEN>'
stagehub expose tailscale enable --mode public
stagehub expose tailscale enable --mode private
stagehub expose cloudflare disable
stagehub expose tailscale disable
```

## Uninstall via CLI (Pi)

```bash
stagehub uninstall
```

`stagehub uninstall` interactive prompts also support arrow-key selection.

Non-interactive examples:

```bash
stagehub uninstall --yes --keep-data --keep-expose
stagehub uninstall --yes --purge-data --remove-expose --remove-expose-packages
```
