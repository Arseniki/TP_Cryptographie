#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-${EC1_PKI_DIR:-$HOME/ec1-pki}}"
mkdir -p "$OUT"

if find "$OUT" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "Erreur : le dossier de sortie doit être vide : $OUT" >&2
  exit 1
fi

cp "$SCRIPT_DIR/racine.cnf" "$SCRIPT_DIR/inter.cnf" "$OUT/"
cd "$OUT"
mkdir -p racine/{certs,crl,newcerts} inter/{certs,crl,newcerts}
: > racine/index.txt
: > inter/index.txt
printf 'unique_subject = no\n' > inter/index.txt.attr
printf '1000\n' > racine/serial
printf '1000\n' > racine/crlnumber
printf '2000\n' > inter/serial
printf '2000\n' > inter/crlnumber

echo "==> Étape 2 : autorité racine P-384"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
  -out racine/racine.key
chmod 600 racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

echo "==> Étape 3 : autorité intermédiaire P-256"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out inter/inter.key
chmod 600 inter/inter.key
openssl req -new -key inter/inter.key -sha256 \
  -subj "/C=BF/O=Universite TP/CN=Intermediaire TP" \
  -out inter/inter.csr
openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

echo "==> Étape 4 : certificat serveur"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out serveur.key
chmod 600 serveur.key
openssl req -new -key serveur.key -sha256 \
  -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" \
  -out serveur.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in serveur.csr -out serveur.crt

echo "==> Étapes 4 à 6 : certificat Alice, validations et révocation"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out alice.key
chmod 600 alice.key
openssl req -new -key alice.key -sha256 \
  -subj "/CN=alice@tp.local" -out alice.csr
openssl ca -batch -config inter.cnf -extensions ext_client -days 90 \
  -in alice.csr -out alice.crt

openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient alice.crt
if openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname autre.example serveur.crt; then
  echo "Erreur : le contrôle de nom aurait dû échouer." >&2
  exit 1
fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out serveur_hors_perimetre.key
chmod 600 serveur_hors_perimetre.key
openssl req -new -key serveur_hors_perimetre.key \
  -subj "/CN=www.example.com" \
  -addext "subjectAltName=DNS:www.example.com" \
  -out serveur_hors_perimetre.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in serveur_hors_perimetre.csr -out serveur_hors_perimetre.crt
if openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.example.com serveur_hors_perimetre.crt; then
  echo "Erreur : le certificat hors périmètre aurait dû être refusé." >&2
  exit 1
fi

openssl ca -batch -config inter.cnf -revoke alice.crt \
  -crl_reason keyCompromise
openssl ca -batch -config inter.cnf -gencrl -out inter/crl/inter.crl
openssl ca -batch -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
if openssl verify -crl_check_all -CRLfile crls.pem \
  -CAfile racine/racine.crt -untrusted inter/inter.crt alice.crt \
  > alice-revocation-check.txt 2>&1; then
  echo "Erreur : le certificat révoqué d’Alice a été accepté." >&2
  exit 1
elif ! grep -qi revoked alice-revocation-check.txt; then
  cat alice-revocation-check.txt >&2
  echo "Erreur : échec inattendu du contrôle de révocation." >&2
  exit 1
fi
cat alice-revocation-check.txt

echo "==> Certificat Bob pour le TP3"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out bob.key
chmod 600 bob.key
openssl req -new -key bob.key -sha256 \
  -subj "/CN=bob@tp.local" -out bob.csr
openssl ca -batch -config inter.cnf -extensions ext_client_bob -days 90 \
  -in bob.csr -out bob.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient bob.crt

echo "IGC créée dans : $OUT"
echo "Les clés privées et l’état de l’AC restent dans ce répertoire local."
