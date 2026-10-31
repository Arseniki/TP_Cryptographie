# TP3 - TLS, mTLS et exploitation

## Configuration

`nginx.conf` est le bloc serveur à intégrer dans un contexte `http` nginx. Il suppose que les certificats publics et la chaîne sont installés sous `/etc/nginx/tls` et que la clé privée du serveur est protégée en lecture. Le serveur présente son certificat et l’intermédiaire, jamais la racine ; les clients présentent un certificat émis par l’AC et les révocations sont vérifiées avec la concaténation des CRL.

Pour préparer le laboratoire, après le TP2 :

```bash
cat ~/ec1-pki/serveur.crt ~/ec1-pki/inter/inter.crt > /tmp/serveur_chaine.crt
sudo install -d -m 750 /etc/nginx/tls
sudo install -m 600 ~/ec1-pki/serveur.key /etc/nginx/tls/serveur.key
sudo install -m 644 /tmp/serveur_chaine.crt \
  ~/ec1-pki/racine/racine.crt ~/ec1-pki/crls.pem /etc/nginx/tls/
```

Ajouter `127.0.0.1 www.tp.local` au fichier `/etc/hosts`, intégrer le bloc `nginx.conf` à la configuration nginx, puis lancer `sudo nginx -t` avant `sudo systemctl reload nginx`.

Tester Bob :

```bash
openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -verify_hostname www.tp.local -CAfile ~/ec1-pki/racine/racine.crt \
  -cert ~/ec1-pki/bob.crt -key ~/ec1-pki/bob.key \
  -cert_chain ~/ec1-pki/inter/inter.crt -brief
curl --cacert ~/ec1-pki/racine/racine.crt \
  --cert ~/ec1-pki/bob.crt --key ~/ec1-pki/bob.key \
  https://www.tp.local/
```

Contrôler le refus sans certificat et avec Alice révoquée :

```bash
openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -CAfile ~/ec1-pki/racine/racine.crt -brief
openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -CAfile ~/ec1-pki/racine/racine.crt \
  -cert ~/ec1-pki/alice.crt -key ~/ec1-pki/alice.key \
  -cert_chain ~/ec1-pki/inter/inter.crt -brief
```

Le serveur doit refuser ces deux connexions. Vérifier aussi le refus de TLS 1.1 avec `openssl s_client -connect www.tp.local:443 -tls1_1 -brief`, puis inventorier les suites TLS 1.2 avec `nmap --script ssl-enum-ciphers -p 443 www.tp.local`. Pour observer TLS, relever version, suite, groupe d’échange et résultat de validation avec `openssl s_client`; Wireshark permet d’identifier ClientHello et ServerHello. En TLS 1.3, les messages postérieurs à ServerHello, dont le certificat serveur, sont chiffrés.

## Supervision

```bash
python tp3/surveiller.py ~/ec1-pki
echo $?
```

Le code de sortie est `0` (OK), `1` (au moins une échéance sous 30 jours) ou `2` (au moins une échéance sous 7 jours ou une erreur). Le script parcourt récursivement les certificats PEM `.pem`, `.crt` et `.cer`.

## Renouvellement automatisé

`renouveler.sh` ne fait rien si le certificat expire dans plus de 30 jours. Sinon, il génère une nouvelle clé et CSR, obtient une signature de l’intermédiaire, vérifie chaîne, nom et révocation avant déploiement, sauvegarde les fichiers existants (certificat, clé, racine et CRL), teste nginx et recharge le service. En cas d’échec de test ou de rechargement, il restaure la sauvegarde. Exécution réelle à planifier en tant que root pour accéder à nginx et au dossier de déploiement :

```cron
0 3 * * * EC1_PKI_DIR=/home/UTILISATEUR/ec1-pki EC1_TLS_DIR=/etc/nginx/tls /chemin/vers/tp3/renouveler.sh
```

Valider la tâche dans un environnement de laboratoire avant de l’activer. Pour vérifier le seuil de supervision demandé, créer un certificat de test valable cinq jours dans un dossier temporaire puis lancer `surveiller.py` sur ce dossier.
