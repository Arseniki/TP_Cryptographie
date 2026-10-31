#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-${EC1_PKI_DIR:-$HOME/ec1-pki}}"
CLIENT="${2:-bob}"

case "$CLIENT" in
  alice)
    extension=ext_client
    email=alice@tp.local
    ;;
  bob)
    extension=ext_client_bob
    email=bob@tp.local
    ;;
  *)
    echo "Usage : $0 [dossier-IGC] [alice|bob]" >&2
    exit 2
    ;;
esac

test -f "$OUT/inter.cnf" || {
  echo "Configuration IGC absente : $OUT/inter.cnf" >&2
  exit 1
}
cd "$OUT"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$CLIENT.key"
chmod 600 "$CLIENT.key"
openssl req -new -key "$CLIENT.key" -sha256 -subj "/CN=$email" \
  -out "$CLIENT.csr"
openssl ca -batch -config inter.cnf -extensions "$extension" -days 90 \
  -in "$CLIENT.csr" -out "$CLIENT.crt"
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient "$CLIENT.crt"
