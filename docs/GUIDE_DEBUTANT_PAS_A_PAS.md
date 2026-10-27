# Construire le laboratoire SOC intelligent — guide débutant pas à pas

Ce guide explique comment mettre en place le projet du début à la fin, même si
vous débutez en cybersécurité. Lisez et terminez une phase à la fois. À la fin de
chaque phase, vérifiez les résultats avant de continuer.

**Pour votre serveur UBUNTU-SRV1 déjà équipé de 15 conteneurs :** suivez
[Mon projet étape par étape](MON_PROJET_ETAPE_PAR_ETAPE.md). Ce document
décrit une installation neuve ; les commandes `systemctl wazuh-manager`
ci-dessous concernent une installation native, pas votre manager Docker.
Ne réinstallez pas Wazuh ni les autres outils déjà démarrés.

Le laboratoire sert à apprendre et à tester **sur vos propres machines virtuelles**.
Ne lancez jamais de scan, de test ou d'action de réponse contre une machine ou un
réseau que vous ne possédez pas ou pour lequel vous n'avez pas reçu d'autorisation.

## 1. Que va-t-on construire ?

Un SOC est un centre de supervision de sécurité. Dans ce laboratoire :

1. Kali produit du trafic de test vers des machines cibles isolées.
2. pfSense sépare les réseaux et Suricata observe le trafic.
3. Les agents Wazuh et les autres outils produisent des journaux et des alertes.
4. Wazuh reçoit les événements et les affiche dans son tableau de bord.
5. Shuffle automatise des étapes d'enrichissement et de création d'incidents.
6. Cortex et MISP fournissent des renseignements complémentaires sur les indicateurs.
7. L'API ML classe des alertes de laboratoire après avoir été entraînée sur des
   exemples étiquetés.
8. TheHive permet à l'analyste de suivre les incidents.
9. Le Copilot aide à expliquer les alertes, sans prendre de décision à la place
   de l'analyste.
10. Une API de réponse peut effectuer une action sur Windows, mais seulement après
    une configuration sécurisée et une approbation humaine. Elle reste désactivée
    pendant les premières phases.

**Important :** les fichiers de ce dépôt fournissent les API Python, des
fragments Wazuh et des consignes. Ils n'installent pas automatiquement pfSense,
Wazuh, Suricata, Windows, Shuffle, TheHive, Cortex ou MISP.

## 2. Ordre de réalisation

| Étape | Résultat attendu | Peut-on continuer si elle échoue ? |
|---|---|---|
| A. Préparer l'hôte et les VM | Machines démarrées, réseau de labo isolé | Non |
| B. Configurer pfSense | Les segments sont séparés et testés | Non |
| C. Installer Wazuh | Le dashboard est accessible | Non |
| D. Connecter les agents | Ubuntu et Windows sont actifs dans Wazuh | Non |
| E. Tester les journaux | Les événements de base apparaissent | Non |
| F. Ajouter Suricata et ClamAV | Une alerte réseau et un test antivirus remontent | Non |
| G. Ajouter TheHive, Cortex, MISP et Shuffle | Une alerte peut devenir un incident enrichi | Non |
| H. Lancer les API du projet | Les API sont accessibles sur le réseau SOC | Non |
| I. Préparer et évaluer le ML | Le modèle s'entraîne sur des données étiquetées | Non |
| J. Installer le Copilot | Une question reçoit une réponse fondée sur Wazuh | Non |
| K. Démonstration | Un scénario de laboratoire est documenté de bout en bout | — |

N'installez pas tous les composants le premier jour. Un ordre réaliste sur plusieurs
semaines est fourni à la fin.

## 3. Phase A — Préparer l'ordinateur et les réseaux virtuels

### A1. Vérifier les ressources de l'ordinateur

Le serveur SOC est le composant le plus lourd : le guide PDF recommande environ
6–8 vCPU, 16–24 Go de RAM et 150 Go de disque. Les autres VM peuvent demander au
total plus de mémoire que l'ordinateur n'en possède.

Si l'ordinateur a moins de 32 Go de RAM :

- démarrez d'abord le SOC avec Wazuh seul, Ubuntu cible et Kali ;
- éteignez les VM inutilisées ;
- ajoutez Windows, puis les outils de gestion d'incidents et les API ;
- ne réduisez pas tellement la mémoire de Wazuh que le système se bloque.

Installez un hyperviseur, par exemple VirtualBox ou VMware Workstation, depuis son
site officiel. Activez la virtualisation dans le BIOS/UEFI si elle ne l'est pas.
Ne changez pas les réglages du système hôte si vous ne savez pas à quoi ils servent.

### A2. Créer les réseaux VirtualBox

Dans **VirtualBox → Outils → Réseau → Réseaux NAT / Réseaux internes** (le nom des
menus varie selon la version), créez trois réseaux internes portant exactement
les noms suivants :

- `net-attaque`
- `net-cibles`
- `net-soc`

Ils sont distincts du réseau Internet et du réseau de votre domicile/école. Le
pare-feu pfSense fera le routage entre eux. Lors de l'installation des VM, un
adaptateur NAT temporaire peut être ajouté pour télécharger les mises à jour.
Retirez-le ou désactivez-le une fois les installations terminées, pour ne pas
contourner la segmentation du labo.

### A3. Préparer les VM

| VM | Système | Ressources de départ | Carte(s) réseau |
|---|---|---:|---|
| pfSense | pfSense CE | 2 vCPU, 2–4 Go, 20 Go | WAN NAT + `net-cibles` + `net-attaque` + `net-soc` |
| SOC | Ubuntu Server LTS | 6–8 vCPU, 16–24 Go, 150 Go | `net-soc` |
| Cible Linux | Ubuntu Server LTS | 2 vCPU, 2 Go, 25 Go | `net-cibles` |
| Cible Windows | Windows 10/11 de labo | 2–4 vCPU, 4–8 Go, 60 Go | `net-cibles` |
| Attaquant de test | Kali Linux | 2 vCPU, 2–4 Go, 30 Go | `net-attaque` |

Vérifiez les droits de licence et les besoins du logiciel que vous installez.
Ne mettez pas de documents, comptes ou mots de passe personnels sur les VM.

### A4. Noter le plan réseau

Utilisez ce plan, ou notez votre propre plan avant de continuer :

| Segment | Adresse du réseau | Équipement | Adresse |
|---|---|---|---|
| Attaque | `10.10.10.0/24` | pfSense OPT1 / Kali | `10.10.10.1` / `10.10.10.20` |
| Cibles | `192.168.56.0/24` | pfSense LAN / Ubuntu / Windows | `.1` / `.30` / `.40` |
| SOC | `192.168.99.0/24` | pfSense OPT2 / serveur SOC | À confirmer / `192.168.99.15` |

`/24` signifie que les adresses du même segment vont généralement de `.1` à `.254`.
La passerelle d'une machine est l'adresse de pfSense dans son segment. Les
adresses doivent être uniques. Gardez ce tableau à portée de main : de nombreuses
erreurs du début viennent d'une adresse ou d'une passerelle incorrecte.

Le serveur SOC actuel utilise `ens18` et `192.168.99.15/24`. Ce plan remplace
l'adressage SOC du PDF. La passerelle n'est pas donnée par `ifconfig` :
vérifiez `ip route show default` et l'adresse réelle de pfSense côté SOC.
Ne supposez pas qu'il s'agit de `192.168.99.1`. Ne déplacez pas les cibles et
Kali dans ce même sous-réseau : leur trafic pourrait alors contourner pfSense.

**À vérifier avant de continuer :**

- chaque VM démarre ;
- chaque adaptateur est relié au bon réseau nommé ;
- le serveur SOC et les cibles n'ont pas d'adaptateur « pont » vers le réseau réel ;
- un snapshot de VM propre est pris avant les changements.

## 4. Phase B — Installer et configurer pfSense

### B1. Installer

Téléchargez l'image d'installation de pfSense depuis le site de Netgate. Pendant
l'installation, attribuez les quatre interfaces virtuelles à WAN, LAN, OPT1 et
OPT2. Les noms comme `em0`/`em1` dépendent de l'hyperviseur ; ne supposez pas
l'ordre sans le vérifier dans la console pfSense.

Configurez :

- WAN : adaptateur NAT, adresse attribuée par DHCP ;
- LAN : `192.168.56.1/24` ;
- OPT1 : `10.10.10.1/24` ;
- OPT2 : adresse disponible dans `192.168.99.0/24`, à confirmer selon votre
  réseau (distincte du serveur SOC `192.168.99.15` et des autres équipements).

L'interface web d'administration se trouve normalement à
`https://192.168.56.1` depuis une machine du LAN. Changez immédiatement le mot de
passe initial. N'exposez pas cette interface à Kali ou à Internet.

### B2. Créer des règles minimales

Les règles de référence sont dans [le plan réseau pfSense](../infra/network/pfsense-rules.md).
Dans pfSense, les règles se configurent sur l'interface d'où arrive le trafic.
Respectez l'ordre des règles : une règle autorisant tout placée au-dessus d'un
blocage peut rendre ce dernier inutile.

Au minimum :

- Kali peut joindre les machines cibles autorisées ;
- Kali ne peut **pas** joindre `192.168.99.0/24` ;
- les agents des cibles peuvent contacter le SOC sur TCP 1514 (événements) et
  TCP 1515 (enrôlement, selon la configuration Wazuh) ;
- le SOC ne peut atteindre WinRM que vers la cible explicitement autorisée, et
  seulement quand vous aurez configuré WinRM sécurisé ;
- l'accès entrant depuis WAN reste bloqué.

Ne copiez pas une règle sans contrôler l'interface, la source, la destination et
le port.

**Vérification :** une fois les VM reliées et leurs IP attribuées, Kali doit
pouvoir joindre une cible de test mais ne doit pas atteindre le SOC. La règle de
blocage du SOC est un contrôle essentiel, pas une étape facultative.

## 5. Phase C — Installer le serveur SOC et Wazuh

### C1. Installer Ubuntu Server sur le SOC

Installez une version LTS d'Ubuntu Server, activez SSH si souhaité, puis attribuez
l'adresse statique `192.168.99.15/24` avec la passerelle SOC réelle, à confirmer
avec `ip route show default` et la configuration pfSense. L'interface observée
est `ens18` ; vérifiez-la avec `ip a` avant toute modification. Réservez cette
adresse ou excluez-la du DHCP pour éviter un conflit.

Sur la console Ubuntu :

```sh
ip a
ip route
sudo apt update
sudo apt -y upgrade
sudo apt -y install curl wget gnupg unzip net-tools vim chrony openssh-server
sudo timedatectl set-timezone Europe/Rome
sudo systemctl enable --now chrony ssh
```

La même date/heure doit être configurée sur toutes les VM. Une horloge décalée
rend les alertes difficiles à corréler.

### C2. Installer Wazuh

Wazuh est le SIEM : il centralise les événements et les présente à l'analyste.
Utilisez la procédure d'installation « all-in-one » de la documentation officielle
Wazuh qui correspond à la version que vous installez. Les commandes exactes et
versions changent ; le PDF contient un exemple, mais vérifiez la documentation
officielle avant de l'exécuter.

À la fin de l'installation, notez le mot de passe du compte administrateur dans
un gestionnaire de mots de passe, pas dans un fichier partagé. Connectez-vous au
Dashboard en HTTPS, vérifiez le certificat, puis changez les identifiants initiaux.

Sur le SOC, contrôlez les services :

```sh
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
sudo ss -tulpen | grep -E '1514|1515|55000|9200|443'
sudo tail -n 30 /var/ossec/logs/ossec.log
```

Les trois services doivent être `active (running)`. Dans le plan standard :
Dashboard HTTPS 443, Indexer 9200, Manager événements 1514, enrôlement 1515 et
API Wazuh 55000. N'ouvrez pas tous ces ports sur tous les réseaux.

### C3. Ajouter la réception syslog

Quand Wazuh fonctionne, sauvegardez d'abord la configuration du manager :

```sh
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
```

Intégrez le contenu de
[manager-syslog.xml](../infra/wazuh/manager-syslog.xml) dans le bloc racine
`<ossec_config>` de `/var/ossec/etc/ossec.conf`. Vérifiez que l'adresse autorisée
correspond à l'interface de pfSense qui enverra les événements ; l'exemple du
fichier doit être adapté à votre réseau.

Validez la configuration avant le redémarrage :

```sh
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

Ne recopiez pas le fragment comme un deuxième fichier XML autonome dans le
répertoire sans vérifier le mécanisme de configuration de votre version.

**À vérifier avant de continuer :**

- le Dashboard Wazuh s'ouvre depuis votre poste d'administration ;
- Manager, Indexer et Dashboard sont actifs ;
- les ports requis sont en écoute ;
- un snapshot « Wazuh installé » est pris.

## 6. Phase D — Connecter les machines surveillées

### D1. Agent Ubuntu cible

Depuis Ubuntu cible, configurez le dépôt et installez l'agent Wazuh avec la
procédure officielle qui correspond à la version du manager. Associez l'agent au
manager `192.168.99.15`, utilisez un nom lisible, par exemple `ubuntu-cible`, puis
activez le service.

```sh
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent
```

Dans le Dashboard, ouvrez la liste des agents. Attendez l'état `Active`. Si l'agent
ne se connecte pas, vérifiez la route et l'autorisation pfSense avant de réinstaller.
Consultez aussi `/var/ossec/logs/ossec.log` sur l'agent.

Après avoir sauvegardé le fichier de configuration de l'agent, fusionnez les
sections utiles de [linux/ossec.conf](../infra/wazuh/linux/ossec.conf) dans son bloc
`<ossec_config>`. Cela configure la surveillance de l'intégrité de quelques
répertoires et l'envoi des journaux d'authentification et de ClamAV. Ne surveillez
pas tout le disque d'un coup : cela peut produire beaucoup de bruit et consommer
des ressources.

### D2. Agent Windows et Sysmon

Sur Windows :

1. Téléchargez l'agent Windows Wazuh depuis le site officiel et fournissez
   `192.168.99.15` comme adresse du manager.
2. Dans le Dashboard, vérifiez que `windows-cible` devient `Active`.
3. Téléchargez Sysmon depuis Microsoft Sysinternals.
4. Installez Sysmon dans le labo, avec une configuration reconnue et comprise.
5. Sauvegardez le fichier de configuration de l'agent Windows, puis fusionnez
   les sections utiles de [windows/ossec.conf](../infra/wazuh/windows/ossec.conf)
   pour collecter notamment les événements Sysmon. Ces fichiers sont des
   configurations complètes de référence, pas des fragments à coller en entier.
   La collecte du canal PowerShell Operational, si souhaitée, se configure séparément.
6. Redémarrez le service agent et contrôlez l'état dans Wazuh.

Ne donnez pas à l'agent plus de privilèges que nécessaire. Les journaux Windows
Security et PowerShell peuvent contenir des données sensibles ; protégez l'accès
au Dashboard.

**À vérifier avant de continuer :**

- `ubuntu-cible` et `windows-cible` sont tous deux `Active` ;
- l'heure des agents correspond à celle du SOC ;
- une modification anodine d'un fichier de test Ubuntu ou un événement Windows
  apparaît dans les événements Wazuh.

## 7. Phase E — Tester Wazuh avant les autres outils

Pour commencer, privilégiez les tests non destructifs :

### Test Linux : intégrité d'un fichier

Créez un fichier temporaire dans votre dossier personnel, qui est surveillé par
la configuration fournie :

```sh
touch ~/soc-test-fim.txt
echo "test de laboratoire" >> ~/soc-test-fim.txt
```

Regardez les événements `syscheck` de l'agent Linux dans Wazuh. Supprimez ensuite
le fichier de test :

```sh
rm ~/soc-test-fim.txt
```

### Test Windows : journalisation

Ouvrez une session sur la VM, puis consultez les journaux Windows et le Dashboard
Wazuh pour l'activité de connexion. Pour les événements Sysmon, ouvrez
**Observateur d'événements → Journaux des applications et services →
Microsoft → Windows → Sysmon → Operational**. Vérifiez ensuite que le même canal
est collecté dans Wazuh.

### Test réseau local

Seulement quand pfSense et ses règles sont vérifiés, utilisez un test de découverte
léger **vers une IP de cible de votre propre labo uniquement** et observez
Suricata/Wazuh. Gardez les scans larges ou les tests à volume élevé pour plus tard,
et seulement dans le réseau isolé.

Pour chaque essai, consignez dans un journal :

| Date/heure | VM source | Action autorisée | Résultat attendu | Résultat observé | Capture |
|---|---|---|---|---|---|
| Exemple | Ubuntu cible | Créer le fichier temporaire | Alerte FIM | À compléter | `capture-01.png` |

Ne passez pas à la phase suivante tant que vous ne savez pas trouver l'événement
dans Wazuh.

## 8. Phase F — Ajouter Suricata et ClamAV

### F1. Suricata sur pfSense

Dans l'interface pfSense, installez le paquet Suricata depuis le gestionnaire de
paquets. Activez des règles de détection maintenues, choisissez l'interface qui
voit le trafic Kali → cibles, activez les logs EVE JSON et commencez en mode
**IDS (détection seulement)**. Ne passez pas en mode IPS/blocage au début.

Configurez l'envoi syslog vers Wazuh et autorisez seulement le bon équipement
source dans `manager-syslog.xml` ainsi que dans pfSense. L'adresse source peut
dépendre de l'interface pfSense utilisée pour envoyer les journaux.

Vérifiez successivement :

1. Suricata fonctionne et affiche des événements dans sa propre page d'alertes.
2. Le SOC reçoit le trafic syslog sur UDP 514.
3. Les événements Suricata sont visibles dans Wazuh et associés au bon hôte.

Si une étape échoue, ne poursuivez pas vers Shuffle : vérifiez d'abord le réseau,
la source syslog, le format du journal et les règles du pare-feu.

### F2. ClamAV sur Ubuntu cible

Installez ClamAV depuis les dépôts Ubuntu et mettez à jour ses signatures en
suivant sa documentation. Le guide PDF propose aussi une analyse de répertoires et
la surveillance du journal `/var/log/clamav/scan.log` par Wazuh.

Commandes de base sur la VM Ubuntu cible :

```sh
sudo apt update
sudo apt install -y clamav clamav-daemon
sudo systemctl enable --now clamav-freshclam clamav-daemon
sudo systemctl status clamav-freshclam clamav-daemon
clamscan --version
```

Attendez que le service de mise à jour des signatures ait terminé avant de lancer
un scan. Le guide PDF explique comment programmer des scans et envoyer leur
journal à Wazuh ; vérifiez le chemin du journal réellement utilisé par votre
version de ClamAV avant de copier cette configuration.

Le fichier de test **EICAR** est une chaîne de test standard conçue pour être
détectée par des antivirus ; ce n'est pas un logiciel malveillant réel. Utilisez-le
uniquement comme test antivirus sur la VM Ubuntu de laboratoire, et supprimez-le
après le test. Confirmez que ClamAV le détecte et que le journal correspondant
remonte dans Wazuh.

**À vérifier avant de continuer :**

- au moins un événement réseau de test est visible dans Suricata ;
- un événement Suricata est visible dans Wazuh ;
- le test EICAR apparaît dans les journaux ClamAV et Wazuh.

## 9. Phase G — Ajouter la gestion des incidents et l'automatisation

Ces outils ajoutent des services à la VM SOC et peuvent demander beaucoup de
mémoire. Installez-les seulement après la validation de Wazuh.

### G1. Installer Docker sur Ubuntu SOC

Suivez la documentation officielle Docker pour Ubuntu et installez Docker Engine
et le plugin Docker Compose. Puis vérifiez :

```sh
docker --version
docker compose version
sudo sysctl -w vm.max_map_count=262144
```

Si vous ajoutez votre compte au groupe `docker`, sachez que l'accès à Docker donne
des privilèges élevés sur la VM. Utilisez un compte administrateur de laboratoire.

### G2. TheHive et Cortex

TheHive sert à suivre les incidents ; Cortex exécute des analyseurs sur des
indicateurs. Les exigences de base de données, index et images changent selon
leurs versions. Utilisez la composition Docker officielle actuelle, pas un ancien
exemple copié sans vérification. Gardez le moteur de recherche interne au réseau
Docker et évitez les conflits avec Wazuh sur 443/9200.

Sur le serveur `192.168.99.15`, réservez le port hôte 9000 pour TheHive et
9001 pour Cortex dans leurs déploiements respectifs. N'exposez pas leurs bases
ou indexeurs sur le port 9200 déjà utilisé par Wazuh. Le fichier Compose de ce
projet démarre uniquement les API Python, pas TheHive ni Cortex.

Après le démarrage :

- changez les identifiants initiaux ;
- créez une organisation de laboratoire et des comptes distincts ;
- générez des clés API dédiées et stockez-les dans un coffre ;
- créez un incident de test et vérifiez qu'il est visible ;
- exécutez un analyseur uniquement après avoir vérifié sa configuration.

### G3. MISP

Suivez la procédure officielle MISP et modifiez les mots de passe initiaux. Créez
une clé d'API dédiée aux intégrations. Commencez par rechercher des indicateurs
déjà connus ; n'importez pas de flux inconnus sans comprendre leur origine.

VirusTotal est facultatif. La recherche peut transmettre des données à un service
externe. Ne téléversez jamais de fichiers confidentiels ; préférez un hash et
vérifiez les conditions d'utilisation et quotas du fournisseur.

### G4. Shuffle

Installez Shuffle depuis sa documentation officielle et créez un compte
d'administration dédié. Commencez avec un flux minimal :

1. Déclencheur Webhook de test.
2. Nœud qui journalise ou affiche l'alerte reçue.
3. Plus tard, appel vers Cortex/MISP.
4. Plus tard, création d'un incident TheHive.
5. Demande d'approbation humaine avant toute action de réponse.

Ce n'est qu'après le test du webhook que vous intégrerez
[shuffle-integration.xml](../infra/wazuh/shuffle-integration.xml) au manager
Wazuh. Remplacez impérativement le marqueur de webhook par l'URL secrète de votre
propre instance. Ne publiez pas l'URL dans un rapport ou une capture d'écran.

**À vérifier avant de continuer :** une alerte contrôlée arrive dans Shuffle,
puis peut être ajoutée manuellement dans TheHive. Ne déclenchez pas encore d'action
sur une machine.

## 10. Phase H — Démarrer les API Python de ce projet

Les API de ce dépôt tournent sur le serveur SOC Ubuntu. Le fichier Compose est
conçu pour être exécuté sous Linux avec Docker ; Docker n'est pas nécessaire sur
votre ordinateur Windows pour suivre ces étapes.

### H1. Copier le projet vers le SOC

Depuis PowerShell sur le poste où se trouve ce dossier, copiez-le vers la VM SOC
avec OpenSSH (remplacez les deux occurrences de `soc` par le nom réel de votre
compte Ubuntu si celui-ci est différent) :

```powershell
scp -r "C:\Users\wissem-sghaier\Documents\Plateforme SOC intelligente" soc@192.168.99.15:/home/soc/soc-projet
```

Vous devrez peut-être accepter l'empreinte SSH du serveur la première fois.
Vérifiez-la auprès de la console de la VM avant de l'accepter. Sinon, transférez
le dossier par un moyen local sécurisé. Ne copiez pas de fichier `.env` déjà
rempli ou de secret personnel.

Sur le SOC :

```sh
cd /home/soc/soc-projet
cp .env.example .env
chmod 600 .env
id -u
id -g
```

### H2. Configurer les variables

Éditez `.env` avec un éditeur de texte :

```sh
nano .env
```

Remplacez toutes les valeurs `CHANGE_ME` :

- `ML_API_TOKEN`, `SOC_API_TOKEN`, `COPILOT_API_TOKEN` : trois secrets distincts,
  générés par exemple avec `openssl rand -hex 32` ;
- `WAZUH_INDEXER_PASS` : compte indexer en lecture seule, créé pour les API ;
- `WINRM_PASS` : laissez vide/placeholder tant que WinRM n'est pas configuré ;
- `OLLAMA_MODEL` : le nom exact d'un modèle que vous aurez installé localement.

Les variables optionnelles TheHive/MISP/Shuffle en fin de fichier ne sont pas
utilisées par le Compose racine. Si vous utilisez leurs Compose séparés,
reprenez les secrets déjà actifs pour une installation existante : ne les
remplacez pas par de nouveaux secrets sans procédure de rotation.

Configurez aussi `SOC_UID` et `SOC_GID` avec les valeurs affichées par `id -u` et
`id -g` sur votre compte Ubuntu. `SOC_BIND_IP=192.168.99.15` est déjà configuré
pour joindre les API depuis Shuffle. Avant de démarrer les services, créez des
règles de pare-feu limitées aux clients nécessaires. Pour des tests uniquement
locaux, remplacez cette valeur par `SOC_BIND_IP=127.0.0.1`.

Ne partagez jamais `.env`, une capture avec les secrets ou la sortie complète
d'une commande de configuration. Docker peut afficher des variables lors de
l'affichage de la configuration.

### H3. Vérifier et démarrer

```sh
docker compose config --quiet
docker compose up --build -d
docker compose ps
docker compose logs --tail=50
```

Le champ `STATUS` des trois API doit indiquer qu'elles sont en cours d'exécution.
Vérifiez les contrôles de santé :

```sh
curl http://192.168.99.15:8000/health
curl http://192.168.99.15:8001/health
curl http://192.168.99.15:8002/health
```

L'API ML peut répondre `model_loaded: false` tant que vous n'avez pas entraîné de
modèle : c'est normal. Si un conteneur redémarre ou sort, regardez ses logs avant
de continuer :

```sh
docker compose logs --tail=100 response-api
docker compose logs --tail=100 ml-api
docker compose logs --tail=100 copilot-api
```

## 11. Phase I — Construire les données et entraîner l'API ML

Le machine learning n'est pas magique. Il faut des exemples collectés et
étiquetés correctement. Le projet **ne fournit pas de faux modèle entraîné**.

### I1. Créer un compte de lecture seule pour l'indexer

Dans Wazuh Indexer, créez ou demandez un compte qui ne peut que consulter les
alertes nécessaires. N'utilisez pas le compte `admin` pour le Copilot ou
l'exporteur. Placez l'utilisateur, son mot de passe et le certificat CA public de
l'indexer dans `.env` et `infra/certs/`, en suivant
[les consignes de sécurité](SECURITE.md). Gardez la vérification TLS activée.

### I2. Exporter un petit lot

Depuis le dossier du projet sur le SOC, lancez l'export ponctuel :

```sh
docker compose run --rm ml-export
```

L'export est limité à une période de 24 h par défaut et à 10 000 alertes. Il crée
`ml-api/data/alerts.jsonl`. Si la commande échoue, vérifiez l'adresse, le compte
lecture seule, la période et le certificat CA. Ne désactivez pas TLS pour
contourner une erreur de certificat.

Les alertes brutes peuvent contenir des noms, des adresses IP et d'autres données
sensibles. Gardez-les sur la VM SOC, protégez les sauvegardes et anonymisez les
informations si vous devez montrer des exemples.

### I3. Étiqueter des événements connus

Copiez le modèle de labels :

```sh
cp ml-api/data/labels-template.csv ml-api/data/labels.csv
nano ml-api/data/labels.csv
```

Pour chaque ligne, saisissez l'identifiant exact d'une alerte exportée et son
label vérifié :

- `benign` : activité normale confirmée ;
- `attaque_reseau` : activité réseau de test identifiée ;
- `malware` : événement ClamAV/EICAR de test identifié ;
- `active_directory` : activité Windows/identité de test identifiée.

Chaque label doit être examiné par une personne ; ne classez pas une alerte sur la
seule base du score ML. Le pipeline actuel extrait un nombre restreint de variables
(niveau et fréquence de règle, heure, type d'agent, enrichissements disponibles).
Il ne prétend pas remplacer une analyse réseau complète.

### I4. Préparer les variables et entraîner

Il faut au moins quatre exemples par classe pour que le script effectue son split
de démonstration ; en pratique, collectez davantage d'exemples de plusieurs jours,
avec du trafic normal et plusieurs scénarios. Puis :

Les commandes suivantes s'exécutent dans le terminal Bash d'Ubuntu SOC :

```sh
docker compose run --rm ml-train python -m app.prepare_dataset \
  --alerts /app/data/alerts.jsonl \
  --labels /app/data/labels.csv \
  --output /app/data/dataset_features.csv
```

Entraînez ensuite :

```sh
docker compose run --rm ml-train
docker compose restart ml-api
docker compose logs --tail=50 ml-api
```

Le rapport de classification s'affiche lors de l'entraînement. Notez précision,
rappel et nombre d'exemples de chaque classe. Un score élevé sur un petit jeu
d'essai ne prouve pas que le modèle reconnaîtra une attaque inconnue : gardez des
journées de test séparées de celles utilisées pour entraîner.

Testez l'API depuis le SOC en appelant `/docs` ou `POST /analyze`, avec l'en-tête
`X-API-Token`. L'exemple JSON est dans
[CONNEXIONS.md](CONNEXIONS.md). Une réponse contient catégorie, confiance, score
indicatif, explications et score d'anomalie. Les recommandations ne déclenchent
pas d'action.

Voici un test en ligne de commande après l'entraînement. Le token est demandé sans
être affiché à l'écran ; ne le collez pas dans un rapport :

Les commandes utilisent l'adresse configurée `192.168.99.15`. Si vous avez
choisi `SOC_BIND_IP=127.0.0.1` pour des tests uniquement locaux, remplacez
`192.168.99.15` par `127.0.0.1` dans les commandes de vérification et de test.

```sh
read -rsp "Token ML API : " ML_TOKEN; echo
curl -sS -X POST http://192.168.99.15:8001/analyze \
  -H "X-API-Token: ${ML_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"alert":{"timestamp":"2026-10-19T09:00:00Z","rule":{"id":"5712","level":10,"firedtimes":5},"agent":{"name":"ubuntu-cible","os":{"name":"Ubuntu"}},"data":{"srcip":"10.10.10.20"}},"enrichment":{"vt_malicious":0,"misp_hits":0}}'
unset ML_TOKEN
```

## 12. Phase J — Installer et tester le SOC Copilot

Le Copilot lit les alertes Wazuh et demande une explication à Ollama. Ollama doit
être installé sur le SOC ou sur une autre machine privée accessible depuis le SOC.
Choisissez un modèle compatible avec les ressources mémoire disponibles et
suivez la documentation officielle d'Ollama pour l'installation et le
téléchargement du modèle.

Dans `.env`, renseignez :

- `OLLAMA_URL` : adresse privée de l'API Ollama, par exemple
  `http://192.168.99.15:11434/api/chat` si elle tourne sur l'hôte SOC ; son
  adresse d'écoute et le pare-feu doivent autoriser les conteneurs nécessaires
  sans l'exposer à Internet ;
- `OLLAMA_MODEL` : nom du modèle effectivement installé ;
- compte Indexer en lecture seule et certificat CA valides.

Si Ollama est installé sur l'hôte et l'API Copilot dans Docker, `127.0.0.1` depuis
le conteneur désigne le conteneur lui-même, pas l'hôte. Utilisez une adresse de
passerelle Docker ou un nom/réseau Docker configuré correctement et privé. Testez
la connectivité depuis le conteneur avant de conclure que le modèle est en panne.

Appelez `POST /ask` depuis le SOC en transmettant le token
`COPILOT_API_TOKEN`. Demandez par exemple un résumé d'alertes et vérifiez que la
réponse cite des identifiants de règle et des heures. Si aucune alerte ne
correspond, le Copilot doit le dire. Il est en lecture seule et ne doit jamais
exécuter une action suggérée par le modèle.

## 13. Phase K — Garder l'API de réponse désactivée, puis la tester prudemment

Pour les premières démonstrations, conservez `WINRM_ENABLED=false`. Vous pouvez
quand même vérifier l'API de santé et ses protections.

N'activez une connexion qu'après avoir compris les risques et configuré :

1. WinRM **HTTPS uniquement**, port 5986, certificat serveur vérifié ;
2. accès réseau depuis SOC limité à la cible Windows de laboratoire ;
3. compte de service distinct, droits minimum, secret non partagé ;
4. listes d'hôtes et d'actions/paramètres autorisés ;
5. mécanisme d'approbation humaine dans Shuffle ;
6. capture des journaux et possibilité de revenir sur l'action.

Les paramètres `WINRM_ALLOWED_HOSTS`, `WINRM_ALLOWED_USERS` et
`WINRM_ALLOWED_PROCESSES` doivent être explicitement renseignés. N'ajoutez pas un
compte administrateur général dans une liste. Gardez le compte utilisé pour
WinRM hors de la liste des comptes désactivables.

Une action d'isolement réseau peut interrompre les connexions et rendre la VM
difficile à gérer. Commencez par les tests unitaires et la validation de refus
(`401`, `403`, `422`, `503`) ; n'envoyez une action réelle qu'à une VM de test,
après validation d'un analyste. Ne désactivez jamais un compte ou processus
important sur une machine utilisée par quelqu'un.

## 14. Construire le flux de bout en bout dans Shuffle

Ajoutez les nœuds graduellement, et testez chacun avant d'ajouter le suivant :

1. **Webhook** — reçoit une alerte Wazuh de laboratoire.
2. **Extraction** — récupère l'agent, la règle et les indicateurs présents.
3. **Enrichissement facultatif** — requête Cortex/MISP en respectant les limites
   et la confidentialité.
4. **API ML** — envoie `alert` et `enrichment` à `POST /analyze`.
5. **TheHive** — crée une alerte ou un case avec les données utiles et la source.
6. **Approbation humaine** — demande explicitement l'accord d'un analyste avant
   toute réponse.
7. **API de réponse** — facultative, dernière étape, seulement avec HTTPS, listes
   autorisées et approbation explicite.

Au début, faites en sorte que Shuffle s'arrête après la création de l'incident.
Ne liez pas directement une sortie LLM ou un score ML à une commande Windows.
L'analyste consulte le contexte et prend la décision finale.

## 15. Démonstration finale et rapport

Pour la démonstration, choisissez un scénario sans effet destructif, réalisé
uniquement sur les VM autorisées. Par exemple, création d'un fichier temporaire
sur Ubuntu surveillé ou test EICAR reconnu par ClamAV. Présentez :

1. le schéma des trois réseaux ;
2. l'événement source dans le journal de la VM ;
3. la règle/alerte correspondante dans Wazuh ;
4. l'enrichissement (si disponible) ;
5. le workflow Shuffle ;
6. l'incident créé dans TheHive ;
7. l'explication Copilot, avec ses sources ;
8. les résultats et limites dans votre journal de tests.

Mesurez au minimum :

- nombre de tests exécutés et nombre détecté ;
- délai entre l'action de laboratoire et l'alerte ;
- délai jusqu'à l'incident ;
- faux positifs constatés ;
- exemples manquants et améliorations prévues.

N'annoncez pas de « précision de 99 % » sans jeu de test indépendant et suffisamment
représentatif. Décrivez les limites du laboratoire et des données.

## 16. Dépannage débutant

| Symptôme | Première vérification |
|---|---|
| Une VM ne démarre pas | RAM disponible, virtualisation BIOS/UEFI, disque libre |
| Pas d'accès au Dashboard | IP statique, masque, passerelle, état des trois services Wazuh |
| Agent `Disconnected` | Adresse manager, routage, règles pfSense TCP 1514/1515, heure système |
| Pas d'alerte FIM | Chemin dans `<syscheck>`, service agent, délai de scan, journal agent |
| Pas de Suricata dans Wazuh | Interface Suricata, syslog source, UDP 514, IP autorisée dans manager |
| Compose ne démarre pas | `docker compose ps`, puis `docker compose logs --tail=100 <service>` |
| `model_loaded: false` | Entraîner le modèle ; contrôler le fichier dans `ml-api/models/` |
| Erreur certificat Indexer | Vérifier CA et nom DNS/IP du certificat ; ne pas désactiver TLS |
| Copilot ne répond pas | Accès indexer, modèle Ollama installé, URL joignable depuis conteneur |
| WinRM refusé | Il peut être désactivé volontairement ; vérifier HTTPS/5986 et listes autorisées |
| Machine SOC lente | Arrêter les outils non nécessaires, ajouter RAM/disque, avancer par phases |

Quand une commande échoue, copiez le message d'erreur dans votre carnet en
retirant d'abord les mots de passe, tokens, clés API, adresses publiques et
données personnelles.

## 17. Planning suggéré

| Semaine | Travail |
|---|---|
| 1 | Hyperviseur, réseaux, pfSense, VM SOC, Wazuh |
| 2 | Agents, Sysmon, logs Linux/Windows, premières alertes |
| 3 | Suricata, ClamAV, scénarios de test non destructifs et journal |
| 4 | TheHive, Cortex, MISP, puis Shuffle |
| 5 | Export, étiquetage et évaluation des données ML |
| 6 | API ML, Copilot local et démonstration |
| Après validation | Étude séparée et prudente d'une réponse Windows via WinRM HTTPS |

## 18. Glossaire très simple

| Terme | Explication |
|---|---|
| Alerte | Événement que l'outil juge utile à examiner |
| Agent | Petit programme Wazuh installé sur une machine surveillée |
| IDS | Outil qui observe le trafic et signale des comportements suspects |
| IOC | Indicateur comme une adresse IP, un domaine ou un hash de fichier |
| SIEM | Outil central qui reçoit et recherche les journaux ; ici Wazuh |
| SOAR | Outil qui enchaîne des étapes d'analyse/automatisation ; ici Shuffle |
| Case | Dossier d'incident suivi dans TheHive |
| API | Interface utilisée par deux programmes pour échanger des données |
| Token | Secret servant à authentifier un appel à une API |
| TLS/HTTPS | Chiffrement et vérification de l'identité d'un service sur le réseau |
| FIM | Détection d'ajouts/modifications de fichiers |
| Modèle ML | Programme statistique appris à partir d'exemples étiquetés |
| RAG | Technique où un modèle reçoit des alertes pertinentes avant de répondre |
| Snapshot | Point de restauration d'une VM avant un changement |

## 19. Références

- [Guide SOC fourni avec le projet](../Guide_SOC_Intelligent_FINAL.pdf) — architecture,
  dimensionnement et exemples de configuration.
- [README du projet](../README.md) — commandes de lancement des API du dépôt.
- [Préparation de l'infrastructure](INSTALLATION_INFRA.md) et
  [consignes de sécurité](SECURITE.md).
- Consultez aussi les documentations officielles de VirtualBox/VMware, Netgate
  (pfSense), Wazuh, Suricata, ClamAV, Microsoft Sysmon, Docker, TheHive, Cortex,
  MISP, Shuffle, FastAPI et Ollama. Les installations et versions évoluent.
