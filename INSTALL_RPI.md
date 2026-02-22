# StageChat Raspberry Pi Install

Run this one-liner on the Raspberry Pi:

```bash
curl -fsSL https://raw.githubusercontent.com/clevrthings/StageChat/main/install.sh | sudo bash
```

What it does:

- clones or updates StageChat in `/opt/stagechat`
- creates a Python virtual environment and installs dependencies
- asks for main config values (`port`, `username_case_sensitive`) with defaults
- creates and enables a `systemd` service so StageChat restarts automatically
- installs the `stagechat` command in `/usr/local/bin`

Service commands:

```bash
stagechat start
stagechat stop
stagechat restart
stagechat
```

`stagechat` without arguments shows help.
