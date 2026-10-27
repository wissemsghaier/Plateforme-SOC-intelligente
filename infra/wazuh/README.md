# Configuration Wazuh du laboratoire

Le manager existant est `single-node-wazuh.manager-1` en version 4.9.0.
Ce dossier local `infra/wazuh` n'est pas automatiquement le dossier
`/opt/soc-lab/config/wazuh` du serveur.

## Fichiers

- [decoders/](decoders/) : decodeurs ClamAV et Suricata WAN LAB texte IPv4.
- [rules/](rules/) : regles modulaires Linux et Windows.
- [local_rules_phase4.xml](local_rules_phase4.xml) : ancien jeu monolithique ;
  ne pas le charger avec les regles modulaires, dont il reutilise des IDs.
- [linux/ossec.conf](linux/ossec.conf) et [windows/ossec.conf](windows/ossec.conf) :
  configurations completes de reference des agents ; fusionner seulement les
  sections utiles sans ecraser leur configuration active.
- [manager-syslog.xml](manager-syslog.xml) : fragment manager UDP 514 ;
  remplacer l'IP source factice avant usage.
- [shuffle-integration.xml](shuffle-integration.xml) : fragment manager
  d'integration Shuffle ; remplacer l'URL par le webhook reel, qui est secret.

## Deploiement

Suivre les etapes 3 a 9 du
[guide adapte aux conteneurs existants](../../docs/MON_PROJET_ETAPE_PAR_ETAPE.md).
Il explique sauvegarde, montages persistants, doublons, tests et retour arriere.
Aucun script `apply_phase4_wazuh_docker.sh` n'est fourni dans ce projet.

Sur Ubuntu SOC :

```sh
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

Le premier test valide le chargement Wazuh, le second verifie un evenement et
les champs/regles reconnus. Une verification XML locale ne remplace pas ces
tests sur votre version du manager.
