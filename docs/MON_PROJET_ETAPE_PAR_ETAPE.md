# Mon projet SOC : continuer avec mes conteneurs existants

Ce guide est adapté à la sortie `docker ps` fournie pour **UBUNTU-SRV1**.
Il ne réinstalle pas votre SOC. Faites **une étape à la fois**, vérifiez son
résultat et arrêtez-vous à la première erreur. Les commandes Bash sont à
exécuter sur Ubuntu, pas dans PowerShell.

L'adresse `192.168.99.15` provient du plan du projet : confirmez-la avec
`ip -br address`. La sortie `docker ps` seule ne permet pas de confirmer l'IP,
les montages, les mots de passe, les réseaux ou la santé applicative.

## 1. Ce qui existe déjà et ce qui reste à faire

| Composant | Conteneur observé | Version/image observée | Accès hôte |
|---|---|---|---|
| Wazuh Manager | `single-node-wazuh.manager-1` | `wazuh/wazuh-manager:4.9.0` | TCP 1514/1515, UDP 514, TCP 55000 |
| Wazuh Indexer | `single-node-wazuh.indexer-1` | `wazuh/wazuh-indexer:4.9.0` | HTTPS 9200 |
| Wazuh Dashboard | `single-node-wazuh.dashboard-1` | `wazuh/wazuh-dashboard:4.9.0` | HTTPS 443 vers 5601 |
| TheHive | `thehive` | `strangebee/thehive:5.2` | HTTP 9000 |
| Index TheHive | `thehive-elasticsearch` | Elasticsearch 7.17.12 | Interne |
| Cortex | `cortex-cortex-1` | `thehiveproject/cortex:latest` | HTTP 9001 |
| Index Cortex | `cortex-cortex-es-1` | Elasticsearch 7.17.13 | Interne |
| MISP | `misp-core` | `coolacid/misp-docker:core-latest` | HTTP 8080 |
| Base MISP | `misp-db` | MariaDB 10.11 | Interne |
| Cache MISP | `misp-redis` | Redis 7-alpine | Interne |
| Shuffle interface | `shuffle-frontend` | `ghcr.io/shuffle/shuffle-frontend:latest` | HTTP 3001 |
| Shuffle backend | `shuffle-backend` | `ghcr.io/shuffle/shuffle-backend:latest` | Interne 5001 |
| Shuffle exécuteur | `shuffle-orborus` | `ghcr.io/shuffle/shuffle-orborus:latest` | Interne |
| Index Shuffle | `shuffle-opensearch` | OpenSearch 2.14.0 | Interne |
| Tenzir | `tenzir-node` | `tenzir/tenzir:main` | Aucun port hôte publié |

**15 conteneurs sont démarrés dans votre relevé.** Cela ne prouve pas encore que
leurs intégrations fonctionnent. Les trois API Python et Ollama n'y apparaissent
pas ; Ollama peut toutefois être installé comme service de l'hôte.

Ne lancez pas `docker compose down -v`, `docker volume prune` ou une
réinstallation. Ne faites pas de `pull` des images `latest`/`main` pendant cette
mise au point : ces tags sont mobiles. Notez les images/digests actuellement
utilisés avant de planifier séparément une mise à niveau.

Objectif final :

```text
Agents Linux/Windows + pfSense/Suricata + ClamAV
                       |
                       v
                     Wazuh ---> Shuffle ---> enrichissement MISP/Cortex
                                   |                    |
                                   +--> API ML          +--> TheHive

Analyste ---> Copilot API ---> Wazuh Indexer + Ollama local
Analyste ---> API de réponse Windows (désactivée au départ)
Tenzir : conservé, raccordement facultatif à définir après cette chaîne
```

Tenzir est déjà présent mais aucun pipeline Tenzir n'est livré dans ce projet.
N'inventez pas une connexion automatique avec Wazuh et ne publiez pas son API
pour terminer les premières étapes.

## 2. Vérifier Ubuntu et conserver l'inventaire

**Où : Ubuntu SOC, session administrateur.**

```sh
hostname
ip -br address
ip route show default
free -h
df -h /
timedatectl
docker compose version
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
docker stats --no-stream
```

Vérifiez la passerelle réelle, la RAM et le disque ; ne supposez pas que
`192.168.99.1` est votre passerelle. Conservez les segments du
[plan pfSense](../infra/network/pfsense-rules.md). Les cibles prévues sont
Ubuntu `192.168.56.30`, Windows `192.168.56.40`, à confirmer sur vos VM.

**Validation :** les 15 conteneurs attendus sont présents ; aucune saturation
mémoire/disque n'empêche de poursuivre. Pas de mise à jour globale de l'hôte
pendant cette procédure.

## 3. Retrouver les vrais fichiers Compose et les volumes

Vous étiez dans `/opt/soc-lab/config/wazuh/decoders`. Ce répertoire du serveur
n'est pas nécessairement celui du projet Windows, qui utilise `infra/wazuh`.
**Ne renommez pas votre arborescence existante.**

```sh
MANAGER=single-node-wazuh.manager-1
docker inspect "$MANAGER" --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}'
docker inspect "$MANAGER" --format '{{ index .Config.Labels "com.docker.compose.project.config_files" }}'
docker inspect "$MANAGER" --format '{{range .Mounts}}{{println .Type .Source "->" .Destination}}{{end}}'
docker inspect "$MANAGER" --format '{{.Image}}'
```

Refaites la recherche des labels/montages pour `thehive`, `cortex-cortex-1`,
`misp-core`, `shuffle-backend` et `tenzir-node`. Si les labels sont absents,
retrouvez la commande de déploiement d'origine avant de recréer un service.
Les chemins retournés sont ceux du serveur Ubuntu.

Un fichier de ce projet n'est **pas** automatiquement le fichier utilisé par
un conteneur déjà lancé. Ne lancez pas les Compose de `infra/` au hasard :
un autre nom de projet peut créer des volumes vides ou provoquer des conflits
de noms/ports. Préservez les projets, volumes et chemins d'origine.

### Sauvegarde avant toute modification

Prenez un snapshot cohérent des VM avec votre hyperviseur et préparez les
sauvegardes applicatives des bases avant toute migration. La copie suivante
protège la configuration Wazuh, **pas** les données de tous les outils.

```sh
umask 077
BACKUP="/opt/soc-backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP/wazuh-etc"
docker cp "$MANAGER":/var/ossec/etc/. "$BACKUP/wazuh-etc/"
docker ps --no-trunc > "$BACKUP/docker-ps.txt"
```

Copiez aussi les fichiers Compose réellement identifiés et leurs fichiers de
configuration dans cette sauvegarde privée. Ils peuvent contenir des secrets :
ne partagez pas un `docker inspect` complet, un `.env` ou une sortie Compose
résolue. Notez la valeur de `BACKUP` pour une session SSH ultérieure.

**Validation :** sauvegarde lisible et montages identifiés avant de poursuivre.

## 4. Vérifier Wazuh dans Docker, sans systemctl sur l'hôte

```sh
docker exec "$MANAGER" /var/ossec/bin/wazuh-control status
docker exec "$MANAGER" /var/ossec/bin/wazuh-analysisd -t
docker exec "$MANAGER" tail -n 50 /var/ossec/logs/ossec.log
docker logs --tail=50 single-node-wazuh.indexer-1
docker logs --tail=50 single-node-wazuh.dashboard-1
docker exec "$MANAGER" /var/ossec/bin/agent_control -l
```

Dans le navigateur : `https://192.168.99.15`. Vérifiez le certificat et utilisez
vos identifiants actuels. Gardez Manager, Indexer et Dashboard en **4.9.0**
pendant cette correction ; une migration sera une opération séparée.

`systemctl status wazuh-manager` sur Ubuntu SOC ne décrit pas ce manager Docker.
En revanche, `systemctl status wazuh-agent` reste correct **sur la cible Linux**
si son agent est installé comme service.

**Validation :** Dashboard utilisable, processus manager actifs, test de
configuration réussi. Un conteneur `Up` seul ne suffit pas.

## 5. Copier les corrections sans écraser /opt/soc-lab

**Où : Windows PowerShell.** Exemple avec le compte Ubuntu `soc` ; remplacez-le
par votre compte existant. Vérifiez l'empreinte SSH depuis la console avant de
l'accepter. Copiez vers un dossier **nouveau**, pas vers la configuration active.
Ne transférez pas un éventuel `.env` privé.

```powershell
ssh soc@192.168.99.15 "mkdir -p /home/soc/soc-projet-corrige"
scp -r "C:\Users\wissem-sghaier\Documents\Plateforme SOC intelligente\infra" soc@192.168.99.15:/home/soc/soc-projet-corrige/
```

**Retour sur Ubuntu SOC :**

```sh
cd /home/soc/soc-projet-corrige
ls infra/wazuh/decoders
ls infra/wazuh/rules/linux
ls infra/wazuh/rules/windows
```

Votre session actuelle est `root` : vous pouvez y utiliser le dossier ci-dessus
après transfert, sans activer la connexion SSH root. Si vous changez de session,
redéfinissez `MANAGER` et le chemin `BACKUP`.

## 6. Corriger décodeurs et règles avec persistance

Le décodeur Suricata fourni avait une balise `<regex>` tronquée. Le fichier
[corrigé](../infra/wazuh/decoders/pfsense_suricata_wanlab_decoder.xml) traite les
alertes textuelles **IPv4** `WAN LAB` SID 1000201 à 1000205, avec ports TCP/UDP
ou sans ports pour ICMP. Ce n'est pas un décodeur universel EVE JSON/IPv6.

### 6.1 Examiner avant de copier

```sh
docker exec "$MANAGER" sh -c 'ls -l /var/ossec/etc/decoders; ls -l /var/ossec/etc/rules'
docker exec "$MANAGER" sh -c 'grep -R "<rule id=" /var/ossec/etc/rules'
```

Comparez avec vos fichiers actifs et sauvegardez toute personnalisation.
Utilisez **les règles modulaires OU le monolithe**
`local_rules_phase4.xml`, jamais les deux : ils réutilisent des identifiants.
Ne remplacez pas votre `local_rules.xml` par celui du projet : il peut contenir
vos règles existantes. Vérifiez également les doublons avec d'autres règles
personnalisées du serveur.

### 6.2 Choisir la bonne destination

À partir des montages de l'étape 3 :

- **Bind mount d'un dossier ou fichier** : modifiez d'abord le fichier source
  sur l'hôte, par exemple sous `/opt/soc-lab/config/wazuh`, uniquement si
  `docker inspect` confirme ce chemin. Conservez les noms chargés par Wazuh.
  Pour un fichier monté individuellement, une copie dans le conteneur peut
  échouer ; modifiez sa source et recréez avec le Compose d'origine si nécessaire.
- **Volume nommé couvrant `/var/ossec/etc` ou ses sous-dossiers** : les copies
  ciblées ci-dessous persistent dans ce volume. Vérifiez les permissions.
- **Aucun montage couvrant la destination** : arrêtez-vous et ajoutez une
  persistance dans le Compose d'origine avant de déployer. Ne montez pas un
  dossier vide sur tout `/var/ossec/etc` : cela masquerait la configuration.

Pour le cas **volume nommé**, depuis le dossier des corrections, après accord
sur les fichiers à remplacer :

```sh
docker cp infra/wazuh/decoders/. "$MANAGER":/var/ossec/etc/decoders/
```

Puis, seulement si le jeu modulaire a été choisi et les doublons éliminés :

```sh
(
  set -e
  for file in infra/wazuh/rules/linux/*.xml infra/wazuh/rules/windows/*.xml; do
    docker cp "$file" "$MANAGER":/var/ossec/etc/rules/
  done
)
```

Si une copie échoue, ne poursuivez pas. Ces commandes ne suppriment pas les
anciens fichiers : retirez du répertoire chargé uniquement les anciennes
variantes identifiées comme doublons, après sauvegarde. N'y laissez pas un
ancien fichier `.xml` renommé comme sauvegarde.

### 6.3 Valider avant de redémarrer

```sh
docker exec "$MANAGER" /var/ossec/bin/wazuh-analysisd -t
docker exec -it "$MANAGER" /var/ossec/bin/wazuh-logtest
```

Collez d'abord un vrai événement reçu de pfSense. Pour un test de décodage
seulement, cet exemple synthétique doit donner SID `1000202`, source
`10.10.10.20`, destination `192.168.56.30`, port destination `22` et règle
`110202` avec le jeu fourni :

```text
Oct 27 14:00:00 pfsense suricata[123]: [1:1000202:1] WAN LAB - SSH test [Classification: Misc activity] [Priority: 2] {TCP} 10.10.10.20:45000 -> 192.168.56.30:22
```

Testez aussi un vrai ICMP sans ports et un log ClamAV si vous les utilisez.
Quittez avec `Ctrl+D`. Un test synthétique ne prouve pas la collecte réseau
et ne doit pas servir de jeu d'entraînement ML.

Seulement après réussite :

```sh
docker restart "$MANAGER"
docker exec "$MANAGER" /var/ossec/bin/wazuh-control status
docker exec "$MANAGER" tail -n 80 /var/ossec/logs/ossec.log
```

**Retour arrière :** si la validation échoue, ne redémarrez pas. Restaurez
chaque fichier remplacé depuis la sauvegarde, à sa source persistante ; retirez
seulement les nouveaux fichiers introduits par cette étape. Revalidez avant
redémarrage. Restaurer les anciens fichiers sans retirer les nouveaux peut
laisser des règles en conflit. N'effacez pas le volume.

**Validation :** pas d'erreur de chargement, champs et règles attendus dans
`wazuh-logtest`, puis une vraie alerte visible dans le Dashboard.

## 7. Raccorder pfSense, Linux, Windows et ClamAV

### pfSense / Suricata

UDP **514 est déjà publié** par le manager. Vérifiez le bloc `<remote>` actif
avant d'en ajouter un. Le fragment
[manager-syslog.xml](../infra/wazuh/manager-syslog.xml) doit être fusionné dans
`<ossec_config>` du manager, en remplaçant son marqueur par l'adresse source
réellement utilisée par pfSense. N'utilisez pas `0.0.0.0/0`.

Modifiez la source persistante de `ossec.conf` identifiée à l'étape 3. Ne
remplacez jamais tout ce fichier par un fragment. Contrôlez avec
`wazuh-analysisd -t`, redémarrez le manager puis vérifiez les logs.
Dans pfSense, configurez l'envoi syslog vers `192.168.99.15:514` en UDP et
autorisez seulement cette source au pare-feu. Le format envoyé doit correspondre
au décodeur : syslog texte et EVE JSON ne sont pas interchangeables.

### Ubuntu cible

Installez un agent compatible avec le manager via l'assistant Dashboard
seulement s'il manque. Sur **la cible**, pas sur UBUNTU-SRV1 :

```sh
sudo systemctl status wazuh-agent --no-pager
sudo tail -n 50 /var/ossec/logs/ossec.log
```

Sauvegardez sa configuration et fusionnez seulement les blocs utiles de
[linux/ossec.conf](../infra/wazuh/linux/ossec.conf). C'est une référence complète,
pas un fragment à coller en entier. Adaptez profil OS, nom d'agent, chemins
existants et enrôlement ; ne remplacez pas les paramètres d'un agent déjà actif.
Les journaux auditd, Suricata et ClamAV n'existent que si ces outils sont
configurés sur cette machine. Évitez les doubles collectes `syslog`/`kern`/`ufw`.

Une fois `/home` surveillé et l'agent redémarré :

```sh
touch ~/soc-test-fim.txt
echo "test de laboratoire" >> ~/soc-test-fim.txt
```

Retrouvez l'événement `syscheck`, puis supprimez uniquement ce fichier de test.
Pour ClamAV, confirmez la production de `/var/log/clamav/scan.log` et testez
avec la procédure EICAR officielle dans votre labo, sans logiciel malveillant.

### Windows cible

Gardez le manager `192.168.99.15`. Sauvegardez et fusionnez les sections utiles
de [windows/ossec.conf](../infra/wazuh/windows/ossec.conf), puis contrôlez :

```powershell
Restart-Service WazuhSvc
Get-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
```

Sysmon doit être installé séparément. Les événements firewall 5152/5156/5157
nécessitent une politique d'audit adaptée et peuvent être volumineux.

**Validation :** agents `Active` et vrais événements des sources prévues.

## 8. Vérifier TheHive, Cortex et MISP déjà démarrés

Ouvrez depuis un poste autorisé du laboratoire :

| Outil | URL |
|---|---|
| TheHive | `http://192.168.99.15:9000` |
| Cortex | `http://192.168.99.15:9001` |
| MISP | `http://192.168.99.15:8080` |
| Shuffle | `http://192.168.99.15:3001` |

HTTP est réservé au laboratoire isolé ; utilisez TLS pour un réseau partagé.
Changez les identifiants initiaux dans chaque application et créez des comptes
d'intégration dédiés. Changer une variable MariaDB dans Compose **ne modifie
pas** le mot de passe d'une base déjà initialisée.

Les exemples Compose locaux n'intègrent plus de mots de passe de démonstration :
ils demandent `THEHIVE_SECRET`, `MISP_DB_ROOT_PASSWORD`, `MISP_DB_PASSWORD` et
`SHUFFLE_OPENSEARCH_PASSWORD` selon l'outil. Pour un outil existant, reprenez
les valeurs actives dans un fichier privé ; ne changez pas son secret applicatif
ou ses identifiants de base au hasard. Les API racines n'utilisent pas ces
variables. Ces exemples ne sont pas un ordre de redéploiement : les montages,
le réseau externe `soc-net` de TheHive et les prérequis de chaque version doivent
correspondre à votre installation d'origine.

1. TheHive : créer une organisation et un incident de test.
2. Cortex : créer l'organisation/le compte nécessaire et sa clé API.
3. Relier TheHive à Cortex dans la configuration de la version 5.2 utilisée.
   Une configuration `--no-config-cortex` dans Compose ne crée pas cette liaison :
   elle reste à configurer explicitement.
4. Utiliser une URL accessible depuis TheHive : nom Docker seulement si réseau
   commun confirmé, sinon adresse hôte 9001 autorisée. `localhost` ne désigne
   jamais l'autre conteneur. Ne fusionnez pas tous les réseaux internes.
5. Configurer un analyseur autorisé, puis examiner son résultat dans TheHive.
6. Dans MISP, créer une clé dédiée et rechercher un indicateur de laboratoire.
   Ne pas importer tous les feeds d'un coup.

VirusTotal et certains analyseurs contactent des tiers : ne leur envoyez pas
de fichiers, journaux ou indicateurs confidentiels.

**Validation :** incident créé, analyse Cortex terminée, recherche MISP réussie.

## 9. Relier Wazuh à Shuffle avant le ML

1. Dans Shuffle existant, créer un workflow de test et un déclencheur Webhook.
2. Copier son URL exacte. Elle est secrète ; ne pas la mettre dans le rapport.
3. Fusionner [shuffle-integration.xml](../infra/wazuh/shuffle-integration.xml)
   dans la source persistante de `ossec.conf` du manager ; remplacer l'URL
   d'exemple, sans dupliquer une intégration existante.
4. Valider `wazuh-analysisd -t`, redémarrer le manager et contrôler ses logs.
5. Démarrer le déclencheur et produire une vraie alerte autorisée de niveau
   au moins 5. `wazuh-logtest` seul n'envoie pas de webhook.
6. Vérifier le JSON reçu et mapper ses champs vers un incident/une alerte
   TheHive. Utiliser l'identifiant Wazuh comme référence de déduplication et
   vérifier qu'un même événement ne crée pas plusieurs incidents.
7. Ajouter MISP/Cortex progressivement, avec les clés dans le coffre Shuffle.

Le backend Shuffle **5001 n'est pas publié sur l'hôte** dans votre relevé.
Utilisez l'URL fournie par l'interface sur 3001 ; n'ajoutez pas un port 5001
public pour contourner un problème de routage.

**Validation :** une vraie alerte arrive dans Shuffle et peut devenir un
incident TheHive, sans dépendre d'un modèle ML ni déclencher de réponse Windows.

## 10. Préparer uniquement les API Python du projet

Transférez vers le **même dossier nouveau** les éléments suivants depuis
Windows PowerShell, sans copier de `.env` privé :

```powershell
scp "C:\Users\wissem-sghaier\Documents\Plateforme SOC intelligente\docker-compose.yml" "C:\Users\wissem-sghaier\Documents\Plateforme SOC intelligente\.env.example" soc@192.168.99.15:/home/soc/soc-projet-corrige/
scp -r "C:\Users\wissem-sghaier\Documents\Plateforme SOC intelligente\ml-api" "C:\Users\wissem-sghaier\Documents\Plateforme SOC intelligente\response-api" "C:\Users\wissem-sghaier\Documents\Plateforme SOC intelligente\copilot-api" soc@192.168.99.15:/home/soc/soc-projet-corrige/
```

Sur Ubuntu SOC :

```sh
cd /home/soc/soc-projet-corrige
cp -n .env.example .env
chmod 600 .env
id -u soc
id -g soc
nano .env
```

Utilisez les UID/GID du compte propriétaire des dossiers ML, pas ceux de root
simplement parce que la session actuelle est root. Vérifiez :

```sh
ls -ld ml-api/data ml-api/models
```

Si les fichiers ont été transférés sous root, attribuez seulement ces deux
dossiers de travail au compte choisi ; ne faites pas de `chmod 777`.

| Variable | Valeur à définir |
|---|---|
| `SOC_BIND_IP` | `192.168.99.15` si confirmée |
| `SOC_UID`, `SOC_GID` | UID/GID du propriétaire des dossiers ML |
| `ML_API_TOKEN`, `SOC_API_TOKEN`, `COPILOT_API_TOKEN` | Trois secrets distincts, `openssl rand -hex 32` |
| `WAZUH_INDEXER_URL` | URL HTTPS avec nom/IP présent dans le SAN du certificat |
| `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` | Compte réel, limité à la lecture des alertes |
| `WAZUH_INDEXER_VERIFY_TLS` | `true` |
| `WAZUH_INDEXER_CA_CERT` | `/app/certs/wazuh-indexer-ca.pem` |
| `WINRM_ENABLED` | `false` |
| `OLLAMA_URL`, `OLLAMA_MODEL` | À compléter après validation d'Ollama |

Placez uniquement la **CA publique** de l'indexer dans
`infra/certs/wazuh-indexer-ca.pem`, jamais sa clé privée. Si le certificat
ne couvre pas l'IP, utilisez un DNS couvert et résolu depuis les conteneurs,
ou renouvelez le certificat. Ne désactivez pas TLS.

Avant le lancement, filtrez 8000/8001/8002 pour les seuls clients autorisés.
Les ports Docker peuvent contourner certaines règles UFW : testez réellement
les accès depuis un poste autorisé et un poste interdit.

Depuis ce dossier, le Compose racine démarre **uniquement les API** :

```sh
docker compose config --quiet
docker compose up --build -d ml-api response-api copilot-api
docker compose ps
curl --fail-with-body http://192.168.99.15:8000/health
curl --fail-with-body http://192.168.99.15:8001/health
curl --fail-with-body http://192.168.99.15:8002/health
```

Vérifiez `token_configured` et les autres champs renvoyés ; `model_loaded: false`
est attendu avant entraînement. `/health` ne teste pas toutes les dépendances.
En cas d'erreur :

```sh
docker compose logs --tail=100 ml-api response-api copilot-api
```

**Validation :** API stables ; les 15 conteneurs précédents sont toujours présents.

## 11. Exporter, étiqueter et entraîner le ML

Toujours depuis le dossier des API :

```sh
docker compose run --rm ml-export
wc -l ml-api/data/alerts.jsonl
cp -n ml-api/data/labels-template.csv ml-api/data/labels.csv
nano ml-api/data/labels.csv
```

L'export doit contenir de vraies alertes. Gardez l'en-tête `alert_id,label`,
retirez les lignes d'exemple et utilisez les identifiants exacts exportés.
Labels : `benign`, `attaque_reseau`, `malware`, `active_directory`.
Minimum technique : deux classes dont `benign`, quatre exemples par classe
présente. Cela ne démontre pas une bonne précision : gardez d'autres journées
et scénarios pour l'évaluation. Ne confondez pas activité Windows et attaque AD.

```sh
docker compose run --rm ml-train python -m app.prepare_dataset \
  --alerts /app/data/alerts.jsonl \
  --labels /app/data/labels.csv \
  --output /app/data/dataset_features.csv
docker compose run --rm ml-train
docker compose restart ml-api
curl --fail-with-body http://192.168.99.15:8001/health
```

Dans Shuffle, appelez `POST http://192.168.99.15:8001/analyze` avec
`X-API-Token` et le corps JSON décrit dans [CONNEXIONS.md](CONNEXIONS.md).
Mappez l'alerte réelle dans `alert`, pas le webhook entier sans vérifier sa
structure. Une erreur ML doit conduire à un traitement manuel explicite,
pas à une fausse classification bénigne.

**Validation :** modèle présent, requête authentifiée réussie et résultat
compréhensible sur des alertes distinctes de l'entraînement.

## 12. Ajouter Ollama et le Copilot en lecture seule

Vérifiez d'abord si Ollama existe déjà sur l'hôte. Sinon, utilisez sa
[documentation officielle](https://docs.ollama.com/) et choisissez un modèle
adapté à la mémoire restante. Aucun conteneur Ollama n'est fourni ici.

L'API Copilot en conteneur doit pouvoir joindre Ollama sur l'adresse configurée.
`127.0.0.1` dans le conteneur ne désigne pas le serveur Ubuntu. Limitez l'écoute
et le pare-feu aux clients nécessaires ; n'exposez pas 11434 à Internet.

Renseignez `OLLAMA_URL` et `OLLAMA_MODEL` dans `.env`, puis :

```sh
docker compose up -d copilot-api
```

Testez une requête authentifiée `POST /ask` avec le format de
[CONNEXIONS.md](CONNEXIONS.md). Comparez les règles, agents et horodatages
cités avec le Dashboard. Un redémarrage seul ne recharge pas les nouvelles
variables : utilisez Compose pour recréer le service concerné.

**Validation :** synthèse fondée sur Wazuh ; erreur explicite si une dépendance
est indisponible.

## 13. Réponse Windows : dernière étape, facultative

Laissez `WINRM_ENABLED=false` tant que HTTPS 5986, certificats, listes
d'hôtes/utilisateurs/processus et approbation humaine ne sont pas validés.
Suivez [SECURITE.md](SECURITE.md). Ne laissez pas un workflow déclencher
automatiquement un isolement sur la seule décision du ML.

## 14. Ma feuille de progression

- [ ] IP, passerelle, ressources et segmentation confirmées.
- [ ] Projets Compose, montages et sauvegardes identifiés.
- [ ] Wazuh Docker vérifié sans réinstallation.
- [ ] Décodeurs/règles validés et persistants, sans doublons.
- [ ] Agents et vraies alertes Linux/Windows/pfSense/ClamAV validés.
- [ ] Incident TheHive, analyse Cortex et recherche MISP réussis.
- [ ] Une alerte réelle passe de Wazuh à Shuffle puis TheHive.
- [ ] API Python accessibles uniquement aux clients autorisés.
- [ ] ML entraîné sur données réelles et évalué séparément.
- [ ] Copilot testé en lecture seule.
- [ ] Tenzir conservé ; éventuel pipeline documenté séparément.
- [ ] WinRM désactivé tant que non validé.
- [ ] Aucun secret dans les captures ou le rapport.

Pour chaque étape : noter machine, commande/action, résultat attendu, résultat
observé et preuve sans secrets. Les procédures locales ont été préparées dans
ce projet ; les vérifications Docker ci-dessus restent à exécuter sur votre
serveur Ubuntu.
