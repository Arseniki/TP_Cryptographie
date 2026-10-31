# TP2 - Infrastructure de gestion de clés

## Réalisation et vérifications

`pki.sh` construit une racine P-384 valable dix ans, un intermédiaire P-256 valable cinq ans, puis les certificats serveur et client. Il valide le nom DNS et l’usage client, vérifie le rejet d’un mauvais nom et d’un certificat `www.example.com`, révoque Alice pour compromission, publie les deux CRL et émet Bob pour le TP3. Les artefacts sont générés hors dépôt dans `~/ec1-pki`.

La racine et le sujet de la racine sont identiques parce que le certificat est auto-signé. La chaîne vérifie les signatures, les périodes de validité, les usages et les contraintes de nom. L’AC peut signer `www.example.com` car la signature seule ne vérifie pas les contraintes ; la validation de la chaîne applique `nameConstraints` et refuse ce nom.

## Extensions essentielles

| Extension | Rôle |
|---|---|
| `basicConstraints=critical,CA:TRUE,pathlen:0` | Autorise l’intermédiaire à certifier des feuilles, mais pas d’autre AC. |
| `keyUsage=critical,keyCertSign,cRLSign` | Limite la clé d’AC à la signature de certificats et de CRL. |
| `nameConstraints=critical,...tp.local` | Restreint les identités permises au domaine du laboratoire. |
| `extendedKeyUsage=serverAuth` / `clientAuth` | Distingue les usages TLS serveur et client. |
| `subjectAltName` | Porte l’identité vérifiée par les clients modernes ; le CN ne remplace pas le SAN. |
| `subjectKeyIdentifier` / `authorityKeyIdentifier` | Identifie respectivement la clé du sujet et celle de l’émetteur. |
| `copy_extensions` | Transmet le SAN de la CSR pour le serveur ; les usages restent définis par l’AC. |

## Questions

1. **Pourquoi garder la racine hors ligne ?** Elle est l’ancre de confiance : sa compromission invaliderait toute la PKI. Si l’intermédiaire fuit, le révoquer, publier la CRL, en créer un nouveau et réémettre les certificats. Si la racine fuit, reconstruire une nouvelle ancre et redéployer la confiance.
2. **À quoi sert `pathlen:0` ?** À empêcher l’intermédiaire de signer une autre AC ; sans cette limite, une délégation non prévue pourrait créer une chaîne supplémentaire.
3. **Pourquoi le serveur génère-t-il sa clé ?** La clé privée ne quitte pas son détenteur ; seule la CSR est transmise à l’AC.
4. **CN ou SAN ?** Les clients modernes vérifient le SAN.
5. **Limites des CRL ?** Elles peuvent être volumineuses et leur fraîcheur dépend de la fréquence de publication. OCSP fournit un état en ligne mais ajoute dépendance, disponibilité et confidentialité de requête. Des certificats courts réduisent la fenêtre de révocation sans la supprimer.
6. **Politique minimale (10 points).**
   1. Accepter uniquement les demandes d’un responsable identifié.
   2. Vérifier l’identité et le contrôle du nom demandé.
   3. Faire générer la clé privée par son détenteur.
   4. Limiter les certificats aux noms `tp.local`.
   5. N’accorder que l’usage TLS nécessaire.
   6. Limiter les feuilles à 90 jours.
   7. Garder la racine hors ligne et limiter l’intermédiaire à cinq ans.
   8. Publier les CRL et révoquer immédiatement toute clé compromise.
   9. Renouveler avant expiration et vérifier chaque chaîne.
   10. Journaliser les opérations et protéger les clés par permissions strictes et sauvegardes chiffrées.

## Limite

Les fichiers de base de l’autorité et les clés générés sont des données locales de laboratoire : ils ne doivent pas être ajoutés au dépôt.
