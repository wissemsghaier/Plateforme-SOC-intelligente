# README — ML local de 0 à `model_loaded:true`

Ce guide explique, de manière pratique, comment rendre l'API ML opérationnelle
en local puis comment refaire un cycle d'apprentissage seul.

Objectif de fin :

```sh
curl --fail-with-body http://192.168.99.15:8001/health
```

Réponse attendue :

```json
{"status":"ok","model_loaded":true,"token_configured":true}
```

---

## 1) Comprendre `/health` (très important)

Le endpoint `/health` ne teste pas la précision du modèle. Il vérifie l'état
technique minimal :

- `status: "ok"` : l'API tourne.
- `model_loaded: true` : le fichier modèle existe bien dans `/app/models/`.
- `token_configured: true` : `ML_API_TOKEN` est défini et valide (secret réel,
  longueur minimale).

Si `model_loaded:false`, il faut entraîner le modèle.
Si `token_configured:false`, il faut corriger `.env` puis redémarrer `ml-api`.

---

## 2) Prérequis

Depuis la racine du projet, vérifier :

```sh
docker compose config --quiet
docker compose ps
```

Le service `ml-api` doit être lancé. Les jobs `ml-export` et `ml-train` sont des
services outils (exécutés à la demande avec `docker compose run --rm ...`).

---

## 3) Comment fonctionne `ml-export`

Commande :

```sh
docker compose run --rm -e EXPORT_HOURS=1 ml-export
```

Ce qu'elle fait :

1. démarre un conteneur temporaire `ml-export` ;
2. lit les variables Wazuh (`WAZUH_INDEXER_URL`, user, mot de passe, CA TLS) ;
3. interroge l'index `wazuh-alerts-*` sur la fenêtre `now-1h` ;
4. récupère jusqu'à 10 000 alertes ;
5. écrit le résultat dans `ml-api/data/alerts.jsonl`.

`--rm` supprime le conteneur après exécution ; le fichier exporté reste dans
`ml-api/data/` (volume monté).

---

## 4) Règles spécifiques ou toutes les alertes ?

Les deux approches sont possibles.

- **Approche simple (recommandée débutant)** : exporter tout sur 1h/2h, puis
  choisir les alertes utiles dans `labels.csv`.
- **Approche ciblée** : ne garder que certaines familles de règles.

Dans les deux cas, le modèle apprend uniquement ce qui est dans `labels.csv`.

---

## 5) Procédure complète (cycle standard)

### Étape A — Exporter les alertes

```sh
docker compose run --rm -e EXPORT_HOURS=2 ml-export
wc -l ml-api/data/alerts.jsonl
```

Utilité : récupérer des données fraîches de laboratoire.

### Étape B — Inspecter rapidement les types d'alertes

```sh
python3 - <<'PY'
import json, collections
from pathlib import Path
p = Path("ml-api/data/alerts.jsonl")
c = collections.Counter()
with p.open(encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        rec = json.loads(line)
        rule = (rec.get("alert") or {}).get("rule") or {}
        rid = str(rule.get("id", "?"))
        desc = str(rule.get("description", "")).strip()
        c[(rid, desc)] += 1
for (rid, desc), n in c.most_common(20):
    print(f"{n:5d} | rule.id={rid} | {desc}")
PY
```

Utilité : voir quelles règles dominent l'export.

### Étape C — Préparer les labels manuels

Fichier : `ml-api/data/labels.csv`

Format strict :

```csv
alert_id,label
<id1>,benign
<id2>,attaque_reseau
...
```

Utilité : fournir la vérité terrain au modèle.

### Étape D — Construire le dataset de features

```sh
docker compose run --rm ml-train python -m app.prepare_dataset \
  --alerts /app/data/alerts.jsonl \
  --labels /app/data/labels.csv \
  --output /app/data/dataset_features.csv
```

Puis :

```sh
wc -l ml-api/data/dataset_features.csv
head -n 5 ml-api/data/dataset_features.csv
```

Utilité : convertir JSON + labels en tableau exploitable pour l'apprentissage.

### Étape E — Entraîner le modèle

```sh
docker compose run --rm ml-train
```

Utilité : générer `ml-api/models/models.joblib`.

### Étape F — Recharger l'API ML et valider

```sh
docker compose restart ml-api
curl --fail-with-body http://192.168.99.15:8001/health
```

Utilité : charger le nouveau modèle en production locale.

---

## 6) Cas pratique : "je n'ai que 20 alertes"

C'est acceptable pour apprendre le pipeline, mais pas pour une performance
stable. Viser au moins :

- apprentissage rapide : 10 `benign` + 10 `attaque_reseau` ;
- base plus sérieuse : 50 + 50 ;
- mieux : 100 + 100, variés (heures, sources, types d'alertes).

---

## 7) Pourquoi le modèle peut se tromper

Causes fréquentes :

- données trop homogènes (même règle répétée) ;
- classes déséquilibrées ;
- labels bruités (erreurs humaines) ;
- enrichissement toujours à zéro (`misp_hits`, `vt_malicious`).

Bonnes pratiques :

- garder un garde-fou métier (exemple : `rule_level >= 10` => priorité minimale
  HIGH côté workflow) ;
- réentraîner régulièrement avec de nouveaux cas validés.

---

## 8) Test API `/analyze` (rappel)

`/analyze` exige l'en-tête `X-API-Token` (pas `Authorization`).

Exemple minimal :

```sh
curl -X POST "http://192.168.99.15:8001/analyze" \
  -H "Content-Type: application/json" \
  -H "X-API-Token: <ML_API_TOKEN>" \
  -d '{
    "alert": {
      "timestamp": "2026-11-04T12:00:00Z",
      "rule": {"id": "5712", "level": 10, "firedtimes": 3},
      "agent": {"id": "000", "name": "ubuntu-cible"},
      "data": {"srcip": "10.10.10.20"}
    },
    "enrichment": {"misp_hits": 0, "vt_malicious": 0}
  }'
```

---

## 9) Checklist rapide (à refaire à chaque cycle)

1. `ml-export` (fenêtre de temps adaptée)
2. mise à jour `labels.csv`
3. `prepare_dataset`
4. `ml-train`
5. `restart ml-api`
6. test `/health` puis `/analyze`

Si cette checklist passe, le pipeline ML local est sain.
