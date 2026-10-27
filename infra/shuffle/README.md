# Dossier infra/shuffle

Ce dossier contient la stack Shuffle et un script de synthesis des resultats analyzers.

## Ce que fait ce dossier

- Heberge l orchestrateur SOAR Shuffle.
- Permet d automatiser le traitement post-alerte TheHive.

## Fichiers

- docker-compose.yaml
  - frontend: interface web Shuffle (port 3001).
  - backend: moteur API et execution des workflows.
  - orborus: gestion des executions d apps/actions.
  - shuffle-opensearch: stockage interne des donnees Shuffle.

- results_dynamic.py
  - Script de consolidation des retours Cortex.
  - Parse AbuseIPDB, MISP et VirusTotal.
  - Calcule une severite simplifiee (LOW/MEDIUM/HIGH).
  - Construit un resume court exploitable pour notification (ex: Telegram).

## Utilite dans le workflow SOC

- Recoit les alertes TheHive.
- Lance enrichissements Cortex.
- Ajoute un resume decisionnel pour l analyste.

## Points de vigilance

- Verifier les variables OpenSearch et mots de passe.
- Verifier les volumes mounts (shuffle-apps, shuffle-files).
- Surveiller memoire de shuffle-opensearch.

## Etapes et commandes

Vos quatre conteneurs Shuffle sont deja demarres. Ne recreez pas les volumes
ou repertoires `shuffle-database`, `shuffle-apps` et `shuffle-files` ailleurs.
Le [guide de reprise](../../docs/MON_PROJET_ETAPE_PAR_ETAPE.md) explique
comment retrouver les chemins d'origine et raccorder Wazuh.

```sh
docker logs --tail=100 shuffle-backend
docker logs --tail=50 shuffle-orborus
```

Acces interface:
- URL observee : `http://192.168.99.15:3001` (laboratoire isole).
- Le backend 5001 et OpenSearch 9200 ne sont pas publies sur l'hote.

Le mot de passe de demonstration est remplace dans le Compose par
`SHUFFLE_OPENSEARCH_PASSWORD`. Reprenez la valeur active pour un deploiement
existant. Cela n'active pas la securite OpenSearch : cet exemple conserve
`plugins.security.disabled=true` et exige un reseau interne de confiance.
Une authentification/TLS OpenSearch serait une migration distincte.

Depuis la racine, pour valider l'exemple sans l'appliquer :

```sh
docker compose --env-file .env -f infra/shuffle/docker-compose.yaml config --quiet
```

Note: results_dynamic.py est prevu pour un contexte Shuffle (variables dynamiques) et pas pour une execution locale directe.
