# TP1 - Coffre chiffré

## Réalisation

Le format `CFR1` contient les paramètres Argon2id, un sel aléatoire de 16 octets, un nonce de 12 octets, puis le résultat AES-GCM et son étiquette. Argon2id dérive une clé maîtresse ; HKDF-SHA256 sépare les usages. AES-256-GCM authentifie comme données associées l’en-tête complet et le nom du fichier. Les paramètres relus dans l’en-tête sont bornés avant toute dérivation afin qu’un fichier hostile ne puisse demander des ressources arbitraires.

Les tests vérifient le retour exact, l’aléa, l’échec avec un mauvais mot de passe, l’altération, le renommage, l’authentification de l’en-tête et le changement de mot de passe.

## Questions

1. **Pourquoi le sel est-il public ?** Il individualise chaque dérivation et freine les tables précalculées ; le secret est le mot de passe.
2. **Pourquoi le nonce aléatoire est-il acceptable ici ?** Chaque fichier a un sel et donc une clé dérivée distincts ; les collisions de nonce entre clés différentes ne réutilisent pas le couple clé-nonce.
3. **Pourquoi authentifier le nom ?** Cela empêche de rattacher un fichier chiffré à un autre nom sans détection.
4. **Pourquoi authentifier l’en-tête ?** Toute modification du sel, du nonce ou des paramètres est détectée. Les bornes de paramètres protègent en plus contre une demande de calcul/mémoire excessive avant l’authentification.
5. **Pourquoi une erreur générique ?** Distinguer mauvais mot de passe et fichier altéré fournirait un oracle exploitable ; l’interface doit exposer un seul échec de déchiffrement.

## Mesure et limite

Les paramètres sont `t=3`, `m=65536 Kio`, `p=4`, conformément au point de départ du sujet. La mesure locale de la dérivation est de 0,269 s ; le temps dépend du matériel et `t` et `m` peuvent être ajustés pour viser environ 0,5 s. Ce prototype pédagogique ne remplace pas un gestionnaire de mots de passe ni un système de sauvegarde.
