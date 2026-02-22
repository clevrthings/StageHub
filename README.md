# StageChat

Realtime stage communication app with channels, file sharing, notifications, audio intercom, multi-project data separation and admin controls.

## One-click install (Raspberry Pi)

```bash
curl -fsSL https://raw.githubusercontent.com/clevrthings/StageChat/main/install.sh | sudo bash
```

The installer will:

- download/update the latest code from GitHub
- create a Python virtual environment and install dependencies
- ask for main config values (`port`, `username_case_sensitive`) with defaults
- install and enable a `systemd` service so StageChat auto-starts after reboot
- install CLI commands:
  - `stagechat start`
  - `stagechat stop`
  - `stagechat restart`
  - `stagechat` (help)

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
