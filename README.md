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
  - `stagehub update`
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
