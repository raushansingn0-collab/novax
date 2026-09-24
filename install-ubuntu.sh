#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update
sudo apt-get install -y nginx certbot python3-certbot-nginx build-essential
if ! command -v node >/dev/null 2>&1; then curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs; fi
npm install
cp -n .env.example .env || true
echo 'Base install complete. Edit .env and run npm start.'
