# Travaux pratiques - Ingénierie de la cryptographie

Dépôt de travail organisé selon la progression du cours et des consignes : chiffrement authentifié, infrastructure de certification, puis déploiement TLS avec authentification mutuelle.

## Prérequis

- Linux (machine, machine virtuelle ou conteneur)
- Python 3.10 ou plus récent
- OpenSSL 3.x
- nginx pour le TP3
- Bibliothèques Python : `cryptography`, `argon2-cffi`, `pytest`
- `nmap` et Wireshark pour les vérifications et l’observation facultatives du TP3

Préparer l’environnement Python :

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
openssl version
```

La version affichée par OpenSSL doit commencer par `3.`. nginx est nécessaire uniquement pour la mise en service réelle du TP3.

## Parcours

| Ordre | Dossier | Sujet | Livrables et vérification |
|---|---|---|---|
| 1 | [tp1/](tp1/) | Argon2id, HKDF-SHA256, AES-256-GCM et format versionné | Module, tests et [compte rendu](tp1/compte-rendu.md) |
| 2 | [tp2/](tp2/) | AC racine/intermédiaire, certificats, validation et révocation | Configurations, scripts et [compte rendu](tp2/compte-rendu.md) |
| 3 | [tp3/](tp3/) | nginx TLS/mTLS, supervision et renouvellement | Configuration, scripts et [compte rendu](tp3/compte-rendu.md) |

Les étapes sont cumulatives : le TP3 réutilise l’infrastructure produite par le TP2.

## Démarrage rapide

### TP1 - tests

```bash
python -m pytest tp1 -v
```

### TP2 - construire l’IGC de laboratoire

Le script place les clés privées, certificats et bases de l’autorité dans `~/ec1-pki` par défaut, jamais dans l’arbre du dépôt. Un autre répertoire vide peut être passé en argument :

```bash
bash tp2/pki.sh
# ou : bash tp2/pki.sh /chemin/vers/un/nouveau-dossier-vide
```

Le script refuse d’écraser un répertoire de sortie non vide. Il construit les autorités, émet les certificats, vérifie les cas attendus, révoque Alice et émet le certificat client de Bob nécessaire au TP3.

### TP3 - supervision et déploiement

```bash
python tp3/surveiller.py ~/ec1-pki
```

La configuration nginx et le renouvellement sont fournis comme livrables ; leur installation réelle requiert les droits adaptés et une configuration locale du laboratoire. Voir [tp3/README.md](tp3/README.md) avant toute installation.

## Sécurité et périmètre

- Ne jamais verser de clé privée, mot de passe, capture contenant des secrets ou état de l’AC dans Git.
- Le TP2 et le TP3 sont destinés à un laboratoire local, notamment aux noms sous `tp.local`.
- Les fichiers PDF fournis pour le cours sont des documents de référence locaux et ne sont pas inclus dans le dépôt.
- Cette réalisation est pédagogique ; elle ne constitue pas une PKI ni un service TLS de production.

## Arborescence

```text
.
├── README.md
├── requirements.txt
├── tp1/
│   ├── coffre.py
│   ├── test_coffre.py
│   └── compte-rendu.md
├── tp2/
│   ├── racine.cnf
│   ├── inter.cnf
│   ├── pki.sh
│   ├── emettre_client.sh
│   └── compte-rendu.md
└── tp3/
    ├── nginx.conf
    ├── renouveler.sh
    ├── surveiller.py
    ├── test_surveiller.py
    ├── README.md
    └── compte-rendu.md
```
