# TP3 — Canal sécurisé et gestion des certificats

## Résultats attendus

TLS 1.2 et 1.3 sont activés ; nginx demande un certificat client, vérifie la chaîne et applique les CRL. Bob est accepté, l’absence de certificat et Alice révoquée sont refusés. La configuration désactive les tickets de session non renouvelés et impose HSTS. La configuration complète est dans [nginx.conf](nginx.conf), la supervision dans [surveiller.py](surveiller.py) et le renouvellement dans [renouveler.sh](renouveler.sh).

## Questions

1. **Pourquoi ne pas envoyer la racine ?** Le client la possède déjà comme ancre de confiance ; l’envoyer n’ajoute pas de confiance et augmente inutilement la chaîne.
2. **Pourquoi désactiver les tickets ?** Si leur clé n’est pas renouvelée, un ticket volé peut prolonger une session et affaiblir la maîtrise des clés de reprise.
3. **Que garantit HSTS ?** Après réception de la politique, le navigateur utilise HTTPS pour le domaine et évite le retour opportuniste à HTTP, notamment lors d’une attaque de rétrogradation.
4. **Certificats publics plus courts ?** Une émission manuelle augmente le risque d’interruption ; il faut automatiser émission, déploiement, contrôle et alertes.
5. **Pourquoi une chaîne incomplète fonctionne chez certains clients ?** Certains disposent déjà de l’intermédiaire en cache ou savent le récupérer ; les autres ne peuvent pas construire la chaîne jusqu’à leur ancre.
6. **Fuite de clé serveur.** Isoler le service, révoquer le certificat et publier les CRL, générer une nouvelle clé sur le serveur, faire émettre et vérifier un nouveau certificat, déployer avec sauvegarde, recharger nginx, puis examiner les journaux et informer les parties concernées.

## Vérifications d’exploitation

Ne pas considérer un certificat valide comme suffisant : vérifier le nom, l’usage, la chaîne et la révocation. Tester la configuration nginx avant rechargement. Le script de renouvellement conserve les anciennes versions et vérifie la chaîne avant installation ; la tâche planifiée doit fonctionner avec les privilèges requis et faire l’objet d’un essai préalable en laboratoire.
