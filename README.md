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

## Notes
- Wayland clipboard via `wl-clipboard` is planned
- Pairing + encrypted transport planned (see `AGENTS.md`)
