# Plateforme SOC intelligente — fichiers de démarrage

Ce dossier contient une base de projet inspirée de `Guide_SOC_Intelligent_FINAL.pdf`.
Le guide PDF reste la référence pour créer les VM et configurer pfSense, Wazuh,
Suricata, les agents et les outils externes.

> **Important :** ces fichiers ne configurent pas automatiquement les VM.
> Ils fournissent les services applicatifs du SOC et des fragments de configuration
> à intégrer prudemment. Toutes les simulations doivent rester dans un laboratoire
> isolé que vous êtes autorisé à utiliser.

**Vos conteneurs sont déjà démarrés sur UBUNTU-SRV1 :** commencez par
[Mon projet étape par étape](docs/MON_PROJET_ETAPE_PAR_ETAPE.md).
Ce guide reprend les 15 conteneurs communiqués, sans réinstaller Wazuh,
TheHive, Cortex, MISP, Shuffle ou Tenzir et sans remplacer leurs volumes.

Le [guide débutant](docs/GUIDE_DEBUTANT_PAS_A_PAS.md) reste une référence pour
une installation neuve. Ne rejouez pas ses phases d'installation sur ce serveur.

## 1. Ce que contient le projet

| Dossier/fichier | Rôle |
|---|---|
| `ml-api/` | API de classification, score de risque, anomalie, SHAP et regroupement |
| `response-api/` | API FastAPI de réponse Windows, authentifiée et limitée aux actions autorisées |
| `copilot-api/` | Assistant de consultation des alertes Wazuh, avec Ollama local |
| `infra/wazuh/` | Fragments manager, configurations de référence agents, décodeurs et règles modulaires |
| `infra/network/` | Plan d'adressage et règles pfSense de laboratoire |
| `docker-compose.yml` | Lancement des trois services applicatifs Python |
| `.env.example` | Exemple de paramètres ; ne contient aucune clé active |

Les Compose de `infra/` décrivent les outils externes, pas leur configuration
active garantie. Retrouvez les Compose et montages d'origine avec `docker inspect`
avant de les utiliser : un nouveau projet peut créer des volumes vides.
Tenzir est conservé tel quel ; aucun pipeline Tenzir n'est livré ici.

## 2. Architecture et adresses du laboratoire

Plan adapté au serveur SOC sur `ens18`, à l'adresse `192.168.99.15/24`
(masque `255.255.255.0`). Ce plan remplace l'ancien adressage SOC du PDF :

| Zone | Réseau | Machines |
|---|---|---|
| Attaque | `10.10.10.0/24` | Kali `10.10.10.20`, pfSense `10.10.10.1` |
| Cibles | `192.168.56.0/24` | pfSense `192.168.56.1`, Ubuntu `.30`, Windows `.40` |
| SOC | `192.168.99.0/24` | SOC `192.168.99.15`, interface pfSense/passerelle à confirmer |

Wazuh, TheHive et Cortex sont installés sur ce même serveur SOC. Les réseaux
des cibles et de Kali restent inchangés. La sortie `ifconfig` ne donne pas la
passerelle : vérifiez-la avec `ip route show default` et contrôlez le routage
pfSense avant de modifier la configuration réseau. N'utilisez pas arbitrairement
`192.168.99.1` comme passerelle.

Adaptez les adresses si votre réseau diffère. Kali ne doit pas pouvoir joindre
directement le réseau SOC. Les ports 8000/8001/8002 des services Python doivent
être autorisés seulement depuis les composants qui en ont besoin.

## 3. Préparer les services Python

Prérequis : Docker Engine et Docker Compose sur le serveur Ubuntu SOC. Depuis ce
dossier :

1. Copiez `.env.example` vers `.env`.
2. Créez trois tokens API distincts d'au moins 32 caractères aléatoires
   (`ML_API_TOKEN`, `SOC_API_TOKEN`, `COPILOT_API_TOKEN`).
   Sous Linux : `openssl rand -hex 32`. Renseignez les identifiants réels pour
   les dépendances utilisées. Les variables optionnelles TheHive/MISP/Shuffle
   en fin de fichier doivent reprendre les secrets **déjà actifs** si vous
   utilisez leurs Compose : ne les régénérez pas pour un outil existant.
   Ne réutilisez pas les exemples du PDF et ne placez jamais `.env` dans Git.
3. Sur le serveur Ubuntu, réglez `SOC_UID` et `SOC_GID` avec les résultats de
   `id -u` et `id -g` de votre compte. Vérifiez `SOC_BIND_IP`.
   `SOC_BIND_IP=192.168.99.15` est déjà configuré pour que Shuffle puisse
   joindre les API. Limitez les accès au pare-feu avant de les démarrer.
   Pour un test uniquement local, utilisez `SOC_BIND_IP=127.0.0.1`.
4. Définissez `WINRM_ALLOWED_HOSTS` à l'adresse Windows de laboratoire uniquement.
   Gardez `WINRM_ENABLED=false` tant que WinRM sécurisé n'est pas configuré.
   Chaque conteneur reçoit uniquement les variables dont il a besoin.
5. Démarrez les services :

   ```sh
   docker compose config --quiet
   docker compose up --build -d
   docker compose ps
   ```

6. Vérifiez leur état :

   ```sh
   curl http://192.168.99.15:8001/health
   curl http://192.168.99.15:8000/health
   curl http://192.168.99.15:8002/health
   ```

   L'adresse `192.168.99.15` doit être attribuée à l'hôte Ubuntu qui exécute
   Docker. Si vous choisissez `SOC_BIND_IP=127.0.0.1`, utilisez cette adresse
   dans les commandes de vérification.

Swagger est disponible sur `/docs` pour chaque API pendant le développement.
Ne publiez pas ces interfaces sur Internet.

## 4. Entraîner l'API ML avec vos alertes

Le modèle ne peut pas être entraîné correctement à partir d'exemples inventés.
Configurez un compte Wazuh Indexer en lecture seule dans `.env`, puis exportez des
alertes réelles de votre laboratoire. Le service ponctuel `ml-export` reçoit ces
seuls identifiants :

```sh
docker compose run --rm ml-export
```

Anonymisez l'export si nécessaire, fabriquez les variables décrites dans
`ml-api/README.md`, puis étiquetez-les
`benign`, `attaque_reseau`, `malware` ou `active_directory`.

Il faut plusieurs exemples **étiquetés** par classe, incluant des événements bénins.
Le script refuse de produire un modèle si le CSV ou les classes sont incorrects.
N'utilisez pas le jeu d'entraînement pour annoncer une précision de production.

Créez la feuille de labels et complétez-la avec les identifiants exacts de
l'export, sans modifier l'en-tête :

```sh
cp ml-api/data/labels-template.csv ml-api/data/labels.csv
```

Une fois le fichier `ml-api/data/labels.csv` complété :

```sh
docker compose run --rm ml-train python -m app.prepare_dataset \
  --alerts /app/data/alerts.jsonl \
  --labels /app/data/labels.csv \
  --output /app/data/dataset_features.csv
docker compose run --rm ml-train
docker compose restart ml-api
```

L'API ML renvoie une erreur explicite tant qu'aucun modèle entraîné n'est présent.
Les conseils de contre-mesure sont des propositions pour l'analyste ; ils ne
déclenchent aucune action.

## 5. Connexions à configurer après installation

1. **Wazuh → Shuffle** : créez un déclencheur Webhook dans Shuffle et ajoutez le
   fragment `infra/wazuh/shuffle-integration.xml` à la configuration du manager.
2. **Shuffle → API ML** : appelez `POST /analyze` sur le port 8001 avec l'en-tête
   `X-API-Token` et un corps contenant `alert` et `enrichment`.
3. **Shuffle → TheHive** : créez le case seulement après avoir validé le résultat
   du modèle et les observables.
4. **Analyste → API de réponse** : après validation humaine explicite, appelez
   `POST /respond` sur le port 8000. L'API refuse les hôtes non autorisés, les
   actions non autorisées, les paramètres mal formés, un token absent et une
   approbation vide.
5. **Copilot** : l'API sur le port 8002 lit Wazuh et demande une synthèse au
   serveur Ollama configuré. Elle est en lecture seule et ne répond pas à partir
   de logs si l'indexer ou le modèle local ne sont pas accessibles.

Les exemples de connexion et formats HTTP sont dans `docs/CONNEXIONS.md`.

## 6. Ordre de réalisation conseillé

Sur votre installation existante, suivez plutôt le
[parcours de vérification et de raccordement](docs/MON_PROJET_ETAPE_PAR_ETAPE.md).
La liste ci-dessous concerne un nouveau laboratoire.

1. Créer les VM et les réseaux, changer les mots de passe par défaut et prendre
   des snapshots.
2. Installer Wazuh Manager, indexer et dashboard ; connecter Ubuntu et Windows.
3. Valider les alertes avant d'ajouter d'autres composants.
4. Installer Suricata et ClamAV, puis vérifier la remontée de leurs alertes.
5. Installer TheHive/Cortex, puis MISP et Shuffle en suivant les guides officiels.
6. Démarrer les API de ce dossier ; entraîner le modèle sur les données du labo.
7. Tester le Copilot en lecture seule.
8. Configurer WinRM en HTTPS et tester les contrôles de l'API de réponse sans
   action de production. N'activer le chemin WinRM qu'après revue et approbation.
9. Jouer les scénarios du PDF uniquement contre les VM isolées, mesurer les
   résultats et documenter les faux positifs.

## 7. Vérification locale

Les tests unitaires ne contactent ni Wazuh, ni Ollama, ni une cible WinRM. Pour
les exécuter localement, installez d'abord les dépendances de l'API de réponse
(FastAPI/Pydantic sont nécessaires aux tests) :

```sh
python -m venv .venv
```

Sous Windows PowerShell :

```powershell
.\.venv\Scripts\python.exe -m pip install -r response-api\requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Sur Ubuntu/Linux :

```sh
.venv/bin/python -m pip install -r response-api/requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Chaque service possède aussi son propre fichier `requirements.txt`. Voir
`docs/SECURITE.md` avant d'exposer un port ou d'activer une réponse automatique.

Les contrôles Wazuh seuls n'utilisent que la bibliothèque standard Python :

```sh
python -m unittest discover -s tests -p test_wazuh_config.py -v
```

Ils vérifient la syntaxe des XML/configurations agents, l'unicité des IDs du
jeu modulaire et l'extraction des champs Suricata TCP/ICMP. Ils ne remplacent
pas `wazuh-analysisd -t`, `wazuh-logtest` et la vérification d'une vraie alerte
sur le manager Docker.
