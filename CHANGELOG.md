# Changelog

## 0.2.0 — 2026-08-17

- Renamed the primary CLI from `aapt` to `apiat` to avoid collision with Android's Asset Packaging Tool.
- Added `apiat demo` for a one-command local lab demonstration.
- Added `apiat lab start|stop|status` lifecycle commands.
- Added Linux installer with pipx support and a venv fallback.
- Added Windows PowerShell installer.
- Automatically create parent directories for JSON/HTML reports.
- Added friendly CLI error handling for missing files and invalid inputs.
- Added CLI/reporting tests.
- Kept `aapt` as a compatibility alias for earlier installs.
