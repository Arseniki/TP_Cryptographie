#!/usr/bin/env python3
"""Surveille les échéances des certificats PEM d'un dossier."""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509


CERTIFICATE_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


def surveiller(dossier: Path) -> int:
    fichiers = sorted(
        path
        for path in dossier.rglob("*")
        if path.is_file() and path.suffix.lower() in {".pem", ".crt", ".cer"}
    )
    if not fichiers:
        print(f"Aucun certificat PEM trouvé dans {dossier}", file=sys.stderr)
        return 2

    maintenant = datetime.now(timezone.utc)
    code = 0
    nombre_certificats = 0
    for chemin in fichiers:
        try:
            contenu = chemin.read_bytes()
        except (OSError, ValueError) as erreur:
            print(f"ERREUR {chemin}: {erreur}", file=sys.stderr)
            code = 2
            continue

        blocs = CERTIFICATE_BLOCK.findall(contenu)
        if not blocs:
            if b"-----BEGIN X509 CRL-----" in contenu:
                try:
                    x509.load_pem_x509_crl(contenu)
                except ValueError as erreur:
                    print(f"ERREUR {chemin}: {erreur}", file=sys.stderr)
                    code = 2
                continue
            print(f"ERREUR {chemin}: aucun certificat PEM reconnu", file=sys.stderr)
            code = 2
            continue

        for numero, bloc in enumerate(blocs, start=1):
            try:
                certificat = x509.load_pem_x509_certificate(bloc)
            except ValueError as erreur:
                print(f"ERREUR {chemin} (certificat {numero}): {erreur}", file=sys.stderr)
                code = 2
                continue

            nombre_certificats += 1
            expiration = certificat.not_valid_after_utc
            jours = (expiration - maintenant).total_seconds() / 86400
            if jours < 7:
                niveau, code = "CRITIQUE", 2
            elif jours < 30:
                niveau, code = "ALERTE", max(code, 1)
            else:
                niveau = "OK"
            print(f"{niveau:8} {chemin}: {jours:.1f} jour(s) restant(s)")

    if not nombre_certificats:
        print(f"Aucun certificat PEM trouvé dans {dossier}", file=sys.stderr)
        return 2
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dossier", type=Path, help="dossier à parcourir récursivement")
    args = parser.parse_args()
    if not args.dossier.is_dir():
        print(f"Dossier introuvable : {args.dossier}", file=sys.stderr)
        return 2
    return surveiller(args.dossier)


if __name__ == "__main__":
    raise SystemExit(main())
