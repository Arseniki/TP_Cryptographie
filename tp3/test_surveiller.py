from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from tp3.surveiller import surveiller


def _certificat(jours: int) -> bytes:
    maintenant = datetime.now(timezone.utc)
    cle = ec.generate_private_key(ec.SECP256R1())
    sujet = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tp.local")])
    certificat = (
        x509.CertificateBuilder()
        .subject_name(sujet)
        .issuer_name(sujet)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - timedelta(minutes=1))
        .not_valid_after(maintenant + timedelta(days=jours))
        .sign(cle, hashes.SHA256())
    )
    return certificat.public_bytes(Encoding.PEM)


def _crl() -> bytes:
    maintenant = datetime.now(timezone.utc)
    cle = ec.generate_private_key(ec.SECP256R1())
    sujet = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tp.local")])
    liste = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(sujet)
        .last_update(maintenant - timedelta(minutes=1))
        .next_update(maintenant + timedelta(days=7))
        .sign(cle, hashes.SHA256())
    )
    return liste.public_bytes(Encoding.PEM)


def test_expiration_ok(tmp_path, capsys):
    (tmp_path / "ok.crt").write_bytes(_certificat(45))
    assert surveiller(tmp_path) == 0
    assert "OK" in capsys.readouterr().out


def test_expiration_alerte(tmp_path, capsys):
    (tmp_path / "alerte.crt").write_bytes(_certificat(20))
    assert surveiller(tmp_path) == 1
    assert "ALERTE" in capsys.readouterr().out


def test_expiration_critique(tmp_path, capsys):
    (tmp_path / "critique.crt").write_bytes(_certificat(5))
    assert surveiller(tmp_path) == 2
    assert "CRITIQUE" in capsys.readouterr().out


def test_dossier_sans_certificat(tmp_path, capsys):
    assert surveiller(tmp_path) == 2
    assert "Aucun certificat" in capsys.readouterr().err


def test_ignore_une_crl_pem(tmp_path, capsys):
    (tmp_path / "certificat.crt").write_bytes(_certificat(45))
    (tmp_path / "crls.pem").write_bytes(_crl())
    assert surveiller(tmp_path) == 0
    sortie = capsys.readouterr()
    assert "OK" in sortie.out
    assert not sortie.err
