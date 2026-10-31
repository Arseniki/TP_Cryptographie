import os
import struct

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


T, M, P = 3, 64 * 1024, 4
MAGIC = b"CFR1"
HEADER_LEN = 44
MAX_TIME_COST = 10
MAX_MEMORY_KIB = 256 * 1024
MAX_PARALLELISM = 8


def _verifier_parametres(t: int, m: int, p: int) -> None:
    if not (1 <= t <= MAX_TIME_COST):
        raise ValueError("paramètre Argon2id t hors limites")
    if not (8 * p <= m <= MAX_MEMORY_KIB):
        raise ValueError("paramètre Argon2id m hors limites")
    if not (1 <= p <= MAX_PARALLELISM):
        raise ValueError("paramètre Argon2id p hors limites")


def cle_maitresse(mot_de_passe: str, sel: bytes) -> bytes:
    """Dérive 32 octets avec Argon2id."""
    if len(sel) < 8:
        raise ValueError("le sel doit contenir au moins 8 octets")
    return hash_secret_raw(
        secret=mot_de_passe.encode(),
        salt=sel,
        time_cost=T,
        memory_cost=M,
        parallelism=P,
        hash_len=32,
        type=Type.ID,
    )


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """Dérive une sous-clé dédiée avec HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"coffre-v1|" + usage,
    ).derive(maitresse)


def chiffrer(mot_de_passe: str, nom: str, donnees: bytes) -> bytes:
    sel = os.urandom(16)
    nonce = os.urandom(12)
    entete = MAGIC + struct.pack(">III", T, M, P) + sel + nonce
    cle_enc = sous_cle(cle_maitresse(mot_de_passe, sel), b"enc")
    ad = entete + nom.encode()
    return entete + AESGCM(cle_enc).encrypt(nonce, donnees, ad)


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    if len(blob) < HEADER_LEN or blob[:4] != MAGIC:
        raise ValueError("format inconnu ou tronqué")

    t, m, p = struct.unpack(">III", blob[4:16])
    _verifier_parametres(t, m, p)
    sel = blob[16:32]
    nonce = blob[32:44]
    cle = hash_secret_raw(
        secret=mot_de_passe.encode(),
        salt=sel,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=32,
        type=Type.ID,
    )
    cle_enc = sous_cle(cle, b"enc")
    ad = blob[:HEADER_LEN] + nom.encode()
    return AESGCM(cle_enc).decrypt(nonce, blob[HEADER_LEN:], ad)


def rechiffrer(
    ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes
) -> bytes:
    """Change le mot de passe sans modifier le contenu déchiffré."""
    return chiffrer(nouveau_mdp, nom, dechiffrer(ancien_mdp, nom, blob))
