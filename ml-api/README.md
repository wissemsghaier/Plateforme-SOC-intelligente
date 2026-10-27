# API ML

L'API attend un modèle créé à partir d'alertes labellisées. Les colonnes numériques
du CSV d'entraînement sont listées dans `app/features.py`. L'entraînement crée un
ensemble XGBoost/Random Forest, un détecteur Isolation Forest (sur les seuls
exemples `benign`) et conserve un split de test pour le rapport.

## Export, étiquetage et entraînement

Sur un hôte autorisé à joindre l'indexer, configurez les variables
`WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` et, si nécessaire,
`WAZUH_INDEXER_CA_CERT`. Le compte doit être en lecture seule. Exportez un lot
limité à une période récente :

```sh
docker compose run --rm ml-export
```

Créez `labels.csv` à partir de `data/labels-template.csv` et attribuez
manuellement une étiquette connue à chaque `alert_id` :

```sh
cp ml-api/data/labels-template.csv ml-api/data/labels.csv
```

Ne marquez pas une alerte
comme malveillante uniquement parce que le modèle l'a dit. Construisez le jeu de
variables :

```sh
docker compose run --rm ml-train python -m app.prepare_dataset \
  --alerts /app/data/alerts.jsonl \
  --labels /app/data/labels.csv \
  --output /app/data/dataset_features.csv
```

L'export est limité à 10 000 alertes par exécution. Le script de préparation
n'utilise que les alertes explicitement présentes dans le fichier de labels.
Conservez l'export brut hors du dépôt : il peut contenir des données
sensibles. Vérifiez les labels avec un analyste avant l'entraînement.

## Entraînement

Le fichier d'entraînement comporte les colonnes de variables et `label`. Labels
acceptés : `benign`, `attaque_reseau`, `malware` et `active_directory`. Au moins
quatre exemples par classe sont requis pour le split train/test ; davantage
d'exemples, collectés sur des périodes différentes, sont nécessaires pour une
évaluation sérieuse.

Exécutez :

```sh
docker compose run --rm ml-train
```

Ne considérez pas les métriques du split aléatoire comme preuve de généralisation.
Gardez également des scénarios/jours entiers à part pour l'évaluation.

## Appel

`POST /analyze` exige l'en-tête `X-API-Token`. Un exemple de requête est dans
`docs/CONNEXIONS.md`. `/cluster` accepte une liste d'alertes pour HDBSCAN ; chaque
indice de cluster `-1` indique un point isolé.

Le score de risque fourni est une formule initiale à valider, pas un seuil de
décision calibré. Les contre-mesures sont de simples recommandations textuelles.
