# mini-sync

Minimal PC <-> Android sync for standalone WMs (Sway/Hyprland).

Goals:
- Clipboard text sync
- File sharing
- Minimal dependencies, CLI + simple UI
- No KDE/Qt/KF stack

Status: skeleton (M0). CLI/daemon stubs only.

## Repository layout
- desktop/ - Rust CLI and daemon
- android/ - Android app (Kotlin + Jetpack Compose; TODO)
- proto/ - Message schema (TODO)

## Quick start (desktop)
- `cargo run -p mini-sync -- --help`
- `cargo run -p mini-syncd -- --version`
- Manual device entry (stub): `mini-sync pair --device-id <id> --pubkey <key> [--name <name>]`
- Generate/load local identity: `mini-sync status` (writes `~/.local/state/mini-sync/identity.toml`)
- Pairing QR payload (stub): `mini-sync pair` (use `--addr <ip>` / `--port <port>` as needed)
- mDNS advertise/browse (daemon): `mini-syncd` (prints discovered services)
- Pairing session is stored at `~/.local/state/mini-sync/pairing.toml` (use `--no-store` to skip)
- Daemon listens on `listen_port` for JSON `PAIR_REQUEST` messages and replies with `PAIR_ACCEPT`/`PAIR_REJECT`
- Pairing requests are newline-delimited JSON (one message per line)

## Notes
- Wayland clipboard via `wl-clipboard` is planned
- Pairing + encrypted transport planned (see `AGENTS.md`)
