# StageHub

Realtime stage communication app with channels, file sharing, notifications, audio intercom, multi-project data separation and admin controls.

## One-click install (Raspberry Pi)

```bash
curl -fsSL https://raw.githubusercontent.com/clevrthings/StageHub/main/install.sh | sudo bash
```

The installer will:

- download/update the latest code from GitHub
- create a Python virtual environment and install dependencies
- ask for main config values (`port`, `username_case_sensitive`) with defaults
- install and enable a `systemd` service so StageHub auto-starts after reboot
- automatically migrate legacy `/opt/stagechat` installs/data to `/opt/stagehub`
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
stagehub expose status
stagehub expose cloudflare enable --mode public
stagehub expose tailscale enable --mode public
stagehub expose tailscale enable --mode private
stagehub expose cloudflare disable
stagehub expose tailscale disable
```

Cloudflare `access-ready` mode keeps tunnel setup in CLI and expects Access policy configuration in the Cloudflare dashboard.

## Uninstall via CLI (Pi)

```bash
stagehub uninstall
```

Non-interactive examples:

```bash
stagehub uninstall --yes --keep-data --keep-expose
stagehub uninstall --yes --purge-data --remove-expose --remove-expose-packages
```
