# StageHub Raspberry Pi Install

Run this one-liner on the Raspberry Pi:

```bash
curl -fsSL https://raw.githubusercontent.com/clevrthings/StageHub/main/install.sh | sudo bash
```

What it does:

- clones or updates StageHub in `/opt/stagehub`
- migrates old `/opt/stagechat` installations and data automatically
- creates a Python virtual environment and installs dependencies
- shows compact, colored checklist-style progress output during install/update
- asks for main config values (`port`, `username_case_sensitive`) with defaults
- creates and enables a `systemd` service so StageHub restarts automatically
- installs the `stagehub` command in `/usr/local/bin` (incl. update/expose/uninstall commands)
- when choosing "Update existing installation", reuses current config/service user without re-asking port/user settings

Defaults:

- `port`: `80`
- `username_case_sensitive`: `false`

Service commands:

```bash
stagehub start
stagehub stop
stagehub restart
stagehub status
stagehub update
stagehub expose
stagehub uninstall
stagehub
```

`stagehub` without arguments shows help.

`stagehub expose` without extra args starts an interactive menu (Cloudflare/Tailscale).  
Use arrow keys + Enter to choose options.
Cloudflare quick one-click mode is available and prints a public `trycloudflare.com` URL.
Tailscale public mode uses Funnel on HTTPS port `443`; `stagehub expose tailscale disable` also clears that funnel mapping.
Interactive Tailscale enable uses the internal StageHub backend port `8443` automatically.
On Tailscale enable, StageHub also prints the detected `https://<device>.ts.net` address.

`stagehub uninstall` is interactive by default and can keep backups under `/var/backups/stagehub-<timestamp>/`.
