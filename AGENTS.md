# Repository Guidelines

## Project Structure & Module Organization
StageChat is a small Python web app with a flat layout:
- `app.py`: main Flask + Socket.IO server, routes, auth, uploads, and runtime startup.
- `templates/index.html`: primary frontend UI and client-side behavior.
- `static/js/socket.io-4.7.5.min.js`: vendored Socket.IO client script.
- `install.sh`: Raspberry Pi installer, service setup, and `stagechat` CLI wrapper.
- `config.json`: runtime app configuration (`active_project`, `port`, case sensitivity).
- `projects/`: runtime data (messages, users, uploads) per project.
- Docs: `README.md`, `INSTALL_RPI.md`, and local runbook notes in `CLAUDE.md`.

## Runtime & Deployment Context
- Raspberry Pi install target: `/opt/stagechat`.
- Service/CLI workflow: `stagechat start|stop|restart|status|update`.
- Local dev run: `python app.py` from repo root after venv + dependencies.
- Default network behavior: app serves HTTPS backend and muxes/redirects through public ports (`80/443`, backend typically `8443`).
- Runtime/project state lives under `projects/` and is environment-specific.

## Build, Test, and Development Commands
- `python3 -m venv .venv && . .venv/bin/activate`: create and activate local venv.
- `pip install -r requirements.txt`: install server dependencies.
- `python app.py`: run StageChat locally (HTTPS backend + mux behavior in app startup).
- `bash -n install.sh`: shell syntax check for installer changes.
- `.venv/bin/python -m py_compile app.py`: quick Python syntax validation.

## Coding Style & Naming Conventions
- Python: 4-space indentation, `snake_case` for functions/variables, short focused helpers.
- JavaScript in `templates/index.html`: keep logic grouped by feature blocks (chat, upload, countdown), avoid spreading globals.
- Shell (`install.sh`): keep `set -euo pipefail`, prefer explicit helper functions, and maintain safe default behavior.

## Testing Guidelines
There is currently no dedicated automated test suite. For changes, run syntax checks and perform manual smoke tests:
- login/auth flow
- channel message send/receive
- file upload and file link open
- HTTP-to-HTTPS redirect and service restart behavior

## Commit & Pull Request Guidelines
Use short, imperative commit subjects consistent with history (examples: `Add ...`, `Fix ...`, `Release ...`). Keep commits focused by concern.  
PRs should include:
- clear summary and scope
- risk/impact notes (auth, uploads, installer, networking)
- manual test evidence (commands run, outcomes)
- screenshots for visible UI changes

## Release Versioning Policy (Mandatory)
On **every change that is committed and pushed to GitHub**, bump version numbers:
- **Bug fix:** increment patch version (`1.0.0` -> `1.0.1`)
- **New feature:** increment minor version (`1.0.0` -> `1.1.0`)
- **Major redesign / large app change:** increment major version (`1.0.0` -> `2.0.0`)

Apply the same version in:
- `app.py` -> `APP_VERSION`
- `install.sh` -> `STAGECHAT_VERSION`

If installer behavior changes, also bump `INSTALLER_VERSION` in `install.sh`.

### Release Checklist
- Classify change type (patch/minor/major) using the policy above.
- Update `APP_VERSION` and `STAGECHAT_VERSION` before commit.
- Run `bash -n install.sh` and `.venv/bin/python -m py_compile app.py`.
- Commit with clear message and push to `origin/main`.
- Ensure docs reflect behavior changes (`README.md`, `INSTALL_RPI.md`, `CLAUDE.md`, and this file when needed).

## Security & Configuration Tips
Do not commit secrets or host-specific cert material. Treat `projects/` as environment state, not portable source. Keep changes to `config.json` deliberate and documented in the PR.
