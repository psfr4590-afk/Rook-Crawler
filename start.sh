#!/data/data/com.termux/files/usr/bin/bash
set -eu
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
    echo "[ERROR] Node.js is required. Install it with: pkg install nodejs"
    exit 1
fi

node_major="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$node_major" -lt 18 ]; then
    echo "[ERROR] Node.js 18.17+ is required. Found: $(node --version)"
    exit 1
fi

if [ ! -f package-lock.json ]; then
    echo "[ERROR] package-lock.json is required for a deterministic install."
    exit 1
fi

if [ ! -d node_modules ]; then
    echo "[SETUP] Installing locked dependencies..."
    npm ci
fi

echo "[LAUNCH] Rook Crawler on http://127.0.0.1:${PORT:-8010}"
exec npm start
