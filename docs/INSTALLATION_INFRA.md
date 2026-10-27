# Préparation de l'infrastructure

Ce document résume les fichiers à intégrer et les étapes à réaliser **dans les VM**.
Il ne remplace pas l'assistant d'installation officiel des éditeurs ni le PDF.

**UBUNTU-SRV1 possède déjà les conteneurs Wazuh, TheHive, Cortex, MISP, Shuffle
et Tenzir.** Pour ce serveur, utilisez le
[guide de reprise pas à pas](MON_PROJET_ETAPE_PAR_ETAPE.md) plutôt que de
réinstaller. Les indications d'installation ci-dessous concernent un nouveau
laboratoire. Les fichiers `infra/` ne remplacent pas automatiquement ceux de
`/opt/soc-lab/config` sur votre serveur.

## Réseaux et VM

Le serveur Wazuh, TheHive et Cortex utilise `192.168.99.15/24` sur `ens18`
(masque `255.255.255.0`, réseau SOC `192.168.99.0/24`). Cette adresse remplace
celle du serveur SOC dans le PDF. Gardez les cibles en `192.168.56.0/24` et
Kali en `10.10.10.0/24` tant qu'un autre plan segmenté n'a pas été défini.
Vérifiez la passerelle avec `ip route show default` : elle n'est pas indiquée
par `ifconfig` et l'adresse de l'interface pfSense SOC doit être confirmée.

Créez les réseaux VirtualBox `net-attaque`, `net-cibles` et `net-soc`.
Réservez une interface WAN NAT pour pfSense et trois interfaces pour les segments
LAN/OPT1/OPT2. Exemple de ressources recommandées dans le guide :

| VM | vCPU | RAM | Disque |
|---|---:|---:|---:|
| SOC | 6–8 | 16–24 Go (12 Go minimum) | 150 Go |
| pfSense + Suricata | 2 | 2–4 Go | 20 Go |
| Ubuntu cible | 2 | 2 Go | 25 Go |
| Windows cible | 2–4 | 4–8 Go | 60 Go |
| Kali | 2 | 2–4 Go | 30 Go |

En dessous de 32 Go de mémoire, ajoutez les composants progressivement comme dans
le chapitre 3 du PDF. Synchronisez l'heure des VM et prenez des snapshots avant les
changements importants.

## pfSense

Appliquez les règles décrites dans `infra/network/pfsense-rules.md`. Commencez avec
Suricata en IDS (alerte seulement), jamais en mode blocage tant que les faux positifs
ne sont pas évalués. Envoyez EVE JSON vers Wazuh seulement après avoir confirmé
l'adresse source autorisée et le transport syslog.

## Wazuh

Installez Manager, Indexer et Dashboard avec la procédure officielle Wazuh
compatible avec la version du système. Sauvegardez `ossec.conf` avant d'ajouter les
fragments de `infra/wazuh/`. Validez la syntaxe et redémarrez le manager après
chaque modification.

Pour le manager Docker existant, la validation est
`docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t`.
Modifiez la source persistante identifiée par les montages Docker et redémarrez
seulement ce conteneur après réussite, pas un service Wazuh systemd sur l'hôte.

Utilisez `192.168.99.15` comme adresse du manager lors de l'enrôlement des
agents. Après un changement d'adresse sur une installation existante, mettez
également à jour l'adresse du manager dans la configuration des agents et les
destinations syslog. Vérifiez les adresses d'écoute des services Wazuh et les
certificats : le certificat de l'indexer doit couvrir `192.168.99.15` dans ses
SAN, ou les URL doivent utiliser un nom DNS couvert qui résout vers cette IP.
Ne désactivez pas TLS pour contourner une erreur de certificat.

Installez l'agent Linux sur Ubuntu et l'agent Windows + Sysmon sur Windows en
suivant le PDF. Le fragment Windows active la collecte du journal Sysmon. Le
fragment Linux surveille quelques emplacements : ajustez-les pour éviter de
collecter inutilement les répertoires très volumineux.

## Outils SOAR et gestion d'incidents

Installez Docker selon la documentation de chaque projet. TheHive/Cortex, MISP et
Shuffle fournissent des compositions et prérequis qui changent selon les versions :
utilisez leurs fichiers officiels compatibles, conservez les données dans des
volumes, modifiez immédiatement les secrets initiaux et ne publiez pas les bases
de données/indexeurs.

Conflits de ports à éviter sur la VM SOC : Wazuh Dashboard utilise souvent 443,
Wazuh Indexer 9200. Le guide réserve notamment 9000 (TheHive), 9001 (Cortex),
8080 (MISP, tel que publié actuellement) et 3001 (Shuffle). Vérifiez les ports réellement configurés avant le
lancement.

## Contrôle avant connexion des API

- Wazuh voit les agents attendus en état actif.
- Les alertes Linux, Windows et Suricata sont visibles avec un horodatage correct.
- Shuffle reçoit un webhook de test.
- TheHive et Cortex sont accessibles sur les ports internes choisis.
- Les règles pfSense interdisent à Kali l'accès au SOC.
- Chaque composant a un mot de passe/compte dédié et les secrets ont été remplacés.
- Pour le Copilot et l'export ML, placez uniquement le certificat CA public de
  l'indexer dans `infra/certs/` et réglez `WAZUH_INDEXER_CA_CERT` sur son chemin
  conteneur (`/app/certs/...`). Ne désactivez pas la vérification TLS.
- Pour les réponses Windows, WinRM doit écouter en HTTPS sur 5986 avec un
  certificat reconnu ; placez au besoin sa CA publique dans `infra/certs/` et
  réglez `WINRM_CA_CERT` sur son chemin conteneur.
