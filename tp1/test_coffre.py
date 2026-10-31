import secrets
import struct

import pytest
from cryptography.exceptions import InvalidTag

from tp1.coffre import (
    HEADER_LEN,
    MAGIC,
    dechiffrer,
    chiffrer,
    rechiffrer,
)


NOM = "facture.txt"
DONNEES = b"Montant: 100 EUR"


@pytest.fixture
def mot_de_passe():
    return secrets.token_urlsafe(32)


def test_aller_retour(mot_de_passe):
    assert dechiffrer(
        mot_de_passe, NOM, chiffrer(mot_de_passe, NOM, DONNEES)
    ) == DONNEES


def test_chiffrement_probabiliste(mot_de_passe):
    blob1 = chiffrer(mot_de_passe, NOM, DONNEES)
    blob2 = chiffrer(mot_de_passe, NOM, DONNEES)
    assert blob1 != blob2
    assert dechiffrer(mot_de_passe, NOM, blob1) == DONNEES
    assert dechiffrer(mot_de_passe, NOM, blob2) == DONNEES


def test_mauvais_mot_de_passe(mot_de_passe):
    with pytest.raises(InvalidTag):
        dechiffrer(
            secrets.token_urlsafe(32),
            NOM,
            chiffrer(mot_de_passe, NOM, DONNEES),
        )


def test_octet_modifie(mot_de_passe):
    blob = bytearray(chiffrer(mot_de_passe, NOM, DONNEES))
    blob[HEADER_LEN + 1] ^= 1
    with pytest.raises(InvalidTag):
        dechiffrer(mot_de_passe, NOM, bytes(blob))


def test_fichier_renomme(mot_de_passe):
    with pytest.raises(InvalidTag):
        dechiffrer(
            mot_de_passe, "autre_nom.txt", chiffrer(mot_de_passe, NOM, DONNEES)
        )


def test_entete_modifiee(mot_de_passe):
    blob = bytearray(chiffrer(mot_de_passe, NOM, DONNEES))
    blob[16] ^= 1
    with pytest.raises(InvalidTag):
        dechiffrer(mot_de_passe, NOM, bytes(blob))


def test_parametres_argon2id_hors_limites(mot_de_passe):
    blob = chiffrer(mot_de_passe, NOM, DONNEES)
    entete = MAGIC + struct.pack(">III", 1, 2**31, 1) + blob[16:HEADER_LEN]
    with pytest.raises(ValueError, match="hors limites"):
        dechiffrer(mot_de_passe, NOM, entete + blob[HEADER_LEN:])


def test_rechiffrer():
    ancien_mdp = secrets.token_urlsafe(32)
    nouveau_mdp = secrets.token_urlsafe(32)
    blob = chiffrer(ancien_mdp, NOM, DONNEES)
    nouveau = rechiffrer(ancien_mdp, nouveau_mdp, NOM, blob)
    with pytest.raises(InvalidTag):
        dechiffrer(ancien_mdp, NOM, nouveau)
    assert dechiffrer(nouveau_mdp, NOM, nouveau) == DONNEES
