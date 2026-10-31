#!/usr/bin/env bash
set -euo pipefail

PKI_DIR="${EC1_PKI_DIR:-$HOME/ec1-pki}"
DEPLOY_DIR="${EC1_TLS_DIR:-/etc/nginx/tls}"
HOST="www.tp.local"
CERT="$DEPLOY_DIR/serveur_chaine.crt"
KEY="$DEPLOY_DIR/serveur.key"

if [[ -f "$CERT" ]] && openssl x509 -in "$CERT" -noout -checkend $((30 * 86400)); then
  echo "Le certificat expire dans plus de 30 jours ; aucun renouvellement."
  exit 0
fi

for fichier in "$PKI_DIR/inter.cnf" "$PKI_DIR/inter/inter.key" \
  "$PKI_DIR/inter/inter.crt" "$PKI_DIR/racine/racine.crt"; do
  if [[ ! -f "$fichier" ]]; then
    echo "Fichier IGC manquant : $fichier" >&2
    exit 1
  fi
done
if [[ ! -f "$PKI_DIR/crls.pem" ]]; then
  echo "CRL combinées manquantes : $PKI_DIR/crls.pem" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP/serveur.key"
chmod 600 "$TMP/serveur.key"
openssl req -new -key "$TMP/serveur.key" -sha256 \
  -subj "/CN=$HOST" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" \
  -out "$TMP/serveur.csr"
(
  cd "$PKI_DIR"
  openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
    -in "$TMP/serveur.csr" -out "$TMP/serveur.crt"
)
cat "$TMP/serveur.crt" "$PKI_DIR/inter/inter.crt" > "$TMP/serveur_chaine.crt"
openssl verify -CAfile "$PKI_DIR/racine/racine.crt" \
  -untrusted "$PKI_DIR/inter/inter.crt" \
  -verify_hostname "$HOST" "$TMP/serveur.crt"
openssl verify -crl_check_all -CRLfile "$PKI_DIR/crls.pem" \
  -CAfile "$PKI_DIR/racine/racine.crt" \
  -untrusted "$PKI_DIR/inter/inter.crt" \
  -verify_hostname "$HOST" "$TMP/serveur.crt"

mkdir -p "$DEPLOY_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="$DEPLOY_DIR/archives/$STAMP"
if [[ -e "$KEY" || -e "$CERT" || -e "$DEPLOY_DIR/racine.crt" || -e "$DEPLOY_DIR/crls.pem" ]]; then
  mkdir -p "$BACKUP"
  [[ ! -e "$KEY" ]] || cp -p "$KEY" "$BACKUP/serveur.key"
  [[ ! -e "$CERT" ]] || cp -p "$CERT" "$BACKUP/serveur_chaine.crt"
  [[ ! -e "$DEPLOY_DIR/racine.crt" ]] || cp -p "$DEPLOY_DIR/racine.crt" "$BACKUP/racine.crt"
  [[ ! -e "$DEPLOY_DIR/crls.pem" ]] || cp -p "$DEPLOY_DIR/crls.pem" "$BACKUP/crls.pem"
fi

restore_previous() {
  if [[ -f "$BACKUP/serveur.key" ]]; then
    install -m 600 "$BACKUP/serveur.key" "$KEY"
  else
    rm -f "$KEY"
  fi
  if [[ -f "$BACKUP/serveur_chaine.crt" ]]; then
    install -m 644 "$BACKUP/serveur_chaine.crt" "$CERT"
  else
    rm -f "$CERT"
  fi
  if [[ -f "$BACKUP/racine.crt" ]]; then
    install -m 644 "$BACKUP/racine.crt" "$DEPLOY_DIR/racine.crt"
  else
    rm -f "$DEPLOY_DIR/racine.crt"
  fi
  if [[ -f "$BACKUP/crls.pem" ]]; then
    install -m 644 "$BACKUP/crls.pem" "$DEPLOY_DIR/crls.pem"
  else
    rm -f "$DEPLOY_DIR/crls.pem"
  fi
  if nginx -t; then
    if ! systemctl reload nginx; then
      echo "Restauration copiée, mais nginx n’a pas pu être rechargé." >&2
    fi
  else
    echo "Restauration copiée, mais nginx -t échoue ; vérifier le service." >&2
  fi
}

install -m 600 "$TMP/serveur.key" "$KEY.new"
install -m 644 "$TMP/serveur_chaine.crt" "$CERT.new"
install -m 644 "$PKI_DIR/racine/racine.crt" "$DEPLOY_DIR/racine.crt.new"
install -m 644 "$PKI_DIR/crls.pem" "$DEPLOY_DIR/crls.pem.new"
mv -f "$KEY.new" "$KEY"
mv -f "$CERT.new" "$CERT"
mv -f "$DEPLOY_DIR/racine.crt.new" "$DEPLOY_DIR/racine.crt"
mv -f "$DEPLOY_DIR/crls.pem.new" "$DEPLOY_DIR/crls.pem"

if ! nginx -t; then
  echo "Configuration invalide après installation ; restauration de l’ancien certificat." >&2
  restore_previous
  exit 1
fi
if ! systemctl reload nginx; then
  echo "Rechargement nginx échoué ; restauration de l’ancien certificat." >&2
  restore_previous
  exit 1
fi

echo "Certificat renouvelé et nginx rechargé. Sauvegarde : $BACKUP"
