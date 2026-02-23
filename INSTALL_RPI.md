# StageHub Raspberry Pi Install

Run this one-liner on the Raspberry Pi:

```bash
curl -fsSL https://raw.githubusercontent.com/clevrthings/StageHub/main/install.sh | sudo bash
```

What it does:

- clones or updates StageHub in `/opt/stagehub`
- migrates old `/opt/stagechat` installations and data automatically
- creates a Python virtual environment and installs dependencies
- asks for main config values (`port`, `username_case_sensitive`) with defaults
- creates and enables a `systemd` service so StageHub restarts automatically
- installs the `stagehub` command in `/usr/local/bin` (incl. update command)

Defaults:

- `port`: `80`
- `username_case_sensitive`: `false`

Service commands:

```bash
stagehub start
stagehub stop
stagehub restart
stagehub update
stagehub
```

`stagehub` without arguments shows help.
