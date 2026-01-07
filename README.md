# mini-sync

Minimal PC <-> Android sync for standalone WMs (Sway/Hyprland).

Goals:
- Clipboard text sync
- File sharing
- Minimal dependencies, CLI + simple UI
- No KDE/Qt/KF stack

Status: early dev; control channel, discovery cache, and clipboard push are in place.

## Repository layout
- desktop/ - Rust CLI and daemon
- android/ - Android app (Kotlin + Jetpack Compose; TODO)
- proto/ - Message schema (TODO)

## Quick start (desktop)
- `cargo run -p mini-sync -- --help`
- `cargo run -p mini-syncd -- --version`
- Manual device entry (stub): `mini-sync pair --device-id <id> --pubkey <key> [--name <name>]`
- Optional DH key on manual entry: `--dh-pubkey <key>` (required for `--secure`)
- Generate/load local identity: `mini-sync status` (writes `~/.local/state/mini-sync/identity.toml`)
- Pairing QR payload (stub): `mini-sync pair` (use `--addr <ip>` / `--port <port>` as needed)
- Send PAIR_REQUEST (dev helper): `mini-sync pair-request --addr <ip> --port <port>`
- Control channel ping (paired only): `mini-sync ping --addr <ip> --port <port>`
- Control channel hello (paired only): `mini-sync hello --addr <ip> --port <port>`
- Control channel status (daemon IPC): `mini-sync daemon-status --addr <ip> --port <port> [--include-discovery]`
- Clipboard push (paired only): `mini-sync clipboard push <device> --addr <ip> --port <port>`
- Add `--secure --device <id>` to use Noise on control commands (requires dh keys)
- mDNS advertise/browse (daemon): `mini-syncd` (prints discovered services)
- Pairing session is stored at `~/.local/state/mini-sync/pairing.toml` (use `--no-store` to skip)
- Daemon listens on `listen_port` for length-prefixed JSON frames (u32 BE)
- Control channel supports optional Noise IK handshake (`--secure`) using pinned dh keys
- For `--secure`, pass `--device <id>` or `--peer-dh-pubkey <key>` so the peer key is known
- `control.require_secure=true` rejects plaintext control messages (except pairing); `control.prefer_secure=true` auto-enables secure when keys exist
- Discovered devices are cached in `~/.local/state/mini-sync/discovered.toml` (use `mini-sync devices --available`)
- `mini-sync devices --all` shows paired + available
- Discovery cache is pruned on updates/removals (TTL 5m)

## Notes
- Clipboard push uses `wl-paste` (client) and `wl-copy` (daemon); install `wl-clipboard`.
- Pairing + encrypted transport planned (see `AGENTS.md`)
