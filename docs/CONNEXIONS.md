# Connexions entre composants

Le serveur SOC est `192.168.99.15/24` (interface `ens18`). Pour joindre les
API Python depuis le réseau SOC, `SOC_BIND_IP=192.168.99.15` est déjà défini
dans `.env.example` et utilisé par défaut dans Compose. Limitez les accès au
pare-feu. Pour des tests uniquement locaux sur l'hôte Docker, choisissez
`SOC_BIND_IP=127.0.0.1` dans `.env`.

Sur ce serveur, les ports prévus sont :

| Composant | Adresse |
|---|---|
| Wazuh Dashboard | `https://192.168.99.15` (443) |
| Wazuh Indexer | `https://192.168.99.15:9200` |
| TheHive | `http://192.168.99.15:9000` |
| Cortex | `http://192.168.99.15:9001` |
| Shuffle | `http://192.168.99.15:3001` |
| MISP | `http://192.168.99.15:8080` |

Ces ports sont déjà publiés dans votre relevé Docker. Le backend Shuffle 5001,
les indexeurs TheHive/Cortex/Shuffle, MariaDB et Redis restent internes.
Tenzir ne publie aucun port hôte dans ce relevé ; aucun pipeline n'est configuré
par le projet. Le Compose racine installe seulement les API Python.
Gardez les bases et
indexeurs sur les réseaux internes Docker. Les URL HTTP sont réservées au
laboratoire isolé ; configurez TLS pour les accès partagés.

Depuis un conteneur, `localhost` désigne ce même conteneur. Un nom Docker
n'est utilisable que si le conteneur appelant partage le réseau approprié.
Sinon, utilisez l'adresse hôte publiée et autorisée par le pare-feu. Ne confondez
pas l'indexer Wazuh exposé sur 9200 avec les trois autres moteurs de recherche.
Pour les montages persistants et le webhook Wazuh, suivez le
[guide adapté aux conteneurs existants](MON_PROJET_ETAPE_PAR_ETAPE.md).

## API ML — `POST /analyze`

URL dans Shuffle : `http://192.168.99.15:8001/analyze`

En-têtes :

```text
Content-Type: application/json
X-API-Token: <ML_API_TOKEN>
```

Corps minimal :

```json
{
  "alert": {
    "timestamp": "2026-10-19T09:00:00Z",
    "rule": {"id": "5712", "level": 10, "firedtimes": 5},
    "agent": {"name": "ubuntu-cible", "os": {"name": "Ubuntu"}},
    "data": {"srcip": "10.10.10.20"}
  },
  "enrichment": {"vt_malicious": 0, "misp_hits": 0}
}
```

La réponse inclut la classe prédite, la confiance, un score de risque de travail,
les variables SHAP principales, le score d'anomalie et un conseil non exécutable.
Le score est indicatif et doit être calibré sur vos propres alertes.

## API de réponse — `POST /respond`

URL : `https://192.168.99.15:8000/respond` une fois TLS configuré devant l'API.
En-tête : `X-API-Token: <SOC_API_TOKEN>`.

```json
{
  "host": "192.168.56.40",
  "action": "disable_user",
  "param": "testsoc",
  "approved_by": "analyste1",
  "case_id": "T-001"
}
```

Valeurs d'action admises : `isolate`, `kill_process`, `disable_user`. L'hôte doit
figurer dans `WINRM_ALLOWED_HOSTS`; les noms d'utilisateur/processus sont validés
avant de construire le script PowerShell et doivent également figurer dans
`WINRM_ALLOWED_USERS` ou `WINRM_ALLOWED_PROCESSES`. Le compte de service WinRM
ne peut pas être désactivé. L'API répond par erreur si
`WINRM_ENABLED` n'est pas vrai. Pour isoler une machine, testez avec précaution :
la règle Windows bloque les connexions sortantes et peut interrompre vos propres
communications de gestion.

## Copilot — `POST /ask`

URL : `http://192.168.99.15:8002/ask`
En-tête : `X-API-Token: <COPILOT_API_TOKEN>`.

```json
{"question": "Résume les alertes importantes de la dernière heure.",
 "agent": "ubuntu-cible", "minutes": 60, "min_level": 5}
```

Le Copilot consulte les alertes Wazuh puis le serveur Ollama local. Il cite les
identifiants de règles disponibles et traite les champs des alertes comme des
données non fiables. N'exposez pas cette API publiquement.
