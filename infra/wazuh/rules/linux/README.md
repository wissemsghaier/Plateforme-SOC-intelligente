# Dossier infra/wazuh/rules/linux

Ce dossier contient les regles Linux custom de PHASE4.

## Fichiers et role

- 001-linux-ufw.xml
  - Detection UFW TCP/ICMP.
  - Correlation scan de ports et flood ICMP.

- 003-linux-auditd.xml
  - Detection basee sur auditd (auth echec, exec, identity, config change).

- 004-linux-auth.xml
  - Detection SSH failed/success.
  - Correlation brute-force SSH.
  - Activite sudo et su.

- 005-linux-syslog.xml
  - Detection incidents systeme (services failed, OOM killer).

- 006-linux-cron.xml
  - Detection activite cron root, repetition anormale et echec execution.

- [010-linux-pfsense_suricata_wanlab_rules.xml](./010-linux-pfsense_suricata_wanlab_rules.xml)
  - Detection des signatures Suricata WAN LAB 1000201 a 1000205.
  - La regle de base filtre le champ decode `suricata_sid`, sans imposer
    un decodeur custom nomme `pfsense-suricata-wanlab`.
  - Le decodeur actif doit extraire `suricata_sid`; les logs JSON EVE utilisant
    `alert.signature_id` ne correspondent pas directement a ces regles.
  - Avant redemarrage, valider avec
    `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t`.
    Utiliser ensuite `wazuh-logtest` avec un vrai log pour verifier le decodage
    et la regle declenchee.

## Utilite SOC

- Couvre les vecteurs Linux frequents d un lab:
  - reconnaissance reseau,
  - brute-force,
  - deni de service,
  - persistence et usage privilegies,
  - incidents disponibilite.

## Etapes et commandes

Suivre le [deploiement persistant](../../../../docs/MON_PROJET_ETAPE_PAR_ETAPE.md)
avec sauvegarde et verification des IDs. Les scripts de simulation et
`validate_phase4_rule_ids.py` ne sont pas fournis dans ce projet.

Sur Ubuntu SOC :

```sh
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

Utiliser un vrai evenement de chaque source attendue, puis confirmer une alerte
reelle dans le Dashboard. Ne pas lancer de simulation contre un reseau partage.
