#!/usr/bin/env bash
set -euo pipefail

certificate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certificates"
mkdir -p "${certificate_dir}"

if command -v mkcert >/dev/null 2>&1; then
  mkcert -install
  mkcert -cert-file "${certificate_dir}/localhost.pem" \
    -key-file "${certificate_dir}/localhost-key.pem" localhost 127.0.0.1 ::1
  printf 'Trusted local certificate created in %s\n' "${certificate_dir}"
  exit 0
fi

openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout "${certificate_dir}/localhost-key.pem" \
  -out "${certificate_dir}/localhost.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

printf '%s\n' 'A self-signed certificate was created. Install frontend/certificates/localhost.pem in your local trust store before using authenticated development.'
