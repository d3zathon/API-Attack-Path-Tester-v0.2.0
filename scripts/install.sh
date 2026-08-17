#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v python3 >/dev/null 2>&1 || { echo "[!] Python 3 is required."; exit 1; }

PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [[ "$PY_MAJOR" -lt 3 || "$PY_MINOR" -lt 11 ]]; then
  echo "[!] Python 3.11+ is required. Found: $(python3 --version)"
  exit 1
fi

if command -v pipx >/dev/null 2>&1; then
  echo "[+] Installing APIAT with pipx..."
  pipx install . --force
  echo "[+] Installed. Try: apiat --help"
  exit 0
fi

echo "[+] pipx not found; creating a local virtual environment..."
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'

mkdir -p "$HOME/.local/bin"
ln -sf "$ROOT/.venv/bin/apiat" "$HOME/.local/bin/apiat"

echo "[+] Installed APIAT into $ROOT/.venv"
echo "[+] User command: $HOME/.local/bin/apiat"
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo "[!] Add ~/.local/bin to PATH, or run: export PATH=\"$HOME/.local/bin:\$PATH\""
fi

echo
echo "Next:"
echo "  apiat demo"
