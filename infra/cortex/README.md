# Dossier infra/cortex

Ce dossier contient la stack Cortex et son moteur de stockage.

## Ce que fait ce dossier

- Lance Cortex pour executer les analyzers sur les observables.
- Lance un Elasticsearch dedie a Cortex.

## Fichier principal

- docker-compose.yml
  - Service cortex-es: Elasticsearch single-node pour index Cortex.
  - Service cortex: API Cortex exposee sur le port 9001.
  - Monte /opt/cortex/jobs dans /tmp/cortex-jobs pour execution des jobs.
  - Monte le socket Docker pour executer certains analyzers containerises.

## Utilite dans le workflow SOC

- Recoit les observables transmis depuis TheHive/Shuffle.
- Lance les analyzers (VirusTotal, AbuseIPDB, MISP, etc.).
- Retourne des resultats structurees pour enrichir le case.

## Points de vigilance

- Verifier que /opt/cortex/jobs existe sur l hote.
- Verifier que le socket Docker est accessible.
- Surveiller RAM (Elasticsearch + Cortex peuvent etre gourmands).

## Etapes et commandes

Votre Cortex tourne deja sous `cortex-cortex-1`, avec
`cortex-cortex-es-1`. Ne recreez pas ces services avec un nouveau nom de projet
ou des volumes vides. Retrouvez d'abord le Compose d'origine selon le
[guide de reprise](../../docs/MON_PROJET_ETAPE_PAR_ETAPE.md).

Pour verifier sans recreer :

```sh
docker logs --tail=100 cortex-cortex-1
docker logs --tail=50 cortex-cortex-es-1
```

Interface : `http://192.168.99.15:9001`, laboratoire isole uniquement.
L'acces au socket Docker donne des privileges eleves ; ne le rendez pas
accessible a des utilisateurs ou workflows non fiables.

Pour une installation neuve uniquement, depuis la racine :

```sh
docker compose -f infra/cortex/docker-compose.yml config --quiet
```

Verifiez ensuite chemins de jobs, images et prerequis avant tout lancement.
