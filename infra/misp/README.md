# Dossier infra/misp

Ce dossier decrit le deploiement MISP en conteneurs et sa configuration TI.

## Ce que fait ce dossier

- Lance MISP (interface + API) pour la threat intelligence.
- Lance les dependances base de donnees et cache.

## Fichiers

- docker-compose.yaml
  - redis: cache rapide pour MISP.
  - db (MariaDB): persistance des evenements et attributs MISP.
  - misp: application MISP exposee sur le port 8080.
  - Parametres memoire limites pour rester compatible lab.

- config/default.json
  - Liste de feeds OSINT preconfigures.
  - Sert a alimenter MISP en IoC externes.

## Utilite dans le workflow SOC

- Cortex peut interroger MISP pour enrichir les observables.
- Shuffle peut exploiter le resultat MISP pour prioriser ou publier un IoC.

## Bonnes pratiques

- Changer les mots de passe par defaut avant usage durable.
- Verifier que BASEURL pointe vers l adresse reelle du lab.
- Controler la frequence de sync des feeds pour eviter la surcharge.

## Etapes et commandes

Vos conteneurs `misp-core`, `misp-db` et `misp-redis` sont deja demarres.
Ne les reinstallez pas. Suivez le
[guide de reprise](../../docs/MON_PROJET_ETAPE_PAR_ETAPE.md).

```sh
docker logs --tail=100 misp-core
docker logs --tail=50 misp-db
```

Acces interface:
- URL observee: `http://192.168.99.15:8080` (laboratoire isole).

Le Compose utilise maintenant `MISP_DB_ROOT_PASSWORD` et `MISP_DB_PASSWORD`,
sans mot de passe de demonstration dans le YAML. Pour une installation
existante, reprenez les valeurs reellement actives depuis votre stockage
prive, sans les partager. Modifier l'environnement ne change pas les mots de
passe dans une base MariaDB deja initialisee : une rotation doit modifier la
base et les clients de facon coordonnee.

Pour valider cet exemple uniquement, depuis la racine :

```sh
docker compose --env-file .env -f infra/misp/docker-compose.yaml config --quiet
```

Avant un lancement, confirmez le projet Compose et les volumes d'origine.
Les variables factices `CHANGE_ME` ne sont pas des secrets utilisables.
