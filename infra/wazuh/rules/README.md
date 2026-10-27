# Dossier infra/wazuh/rules

Ce dossier contient les regles Wazuh custom en format modularise.

## Ce que fait ce dossier

- Separe les regles par OS pour faciliter maintenance.
- Fournit les fichiers a integrer au manager apres sauvegarde et comparaison.

## Fichiers

- local_rules.xml
  - Contient une regle silencieuse locale (point d extension).
  - Sert de base valide pour eviter fichier local vide.

- linux/
  - Regles de detection Linux (UFW, auditd, auth, syslog, cron).

- windows/
  - Regles de detection Windows (firewall, Sysmon).

## Convention

- Les prefixes numeriques de fichiers facilitent l ordre de lecture.
- Chaque rule id doit rester unique dans toute la pile custom.

## Etapes et commandes

Verifier les IDs de regles presentes:

```bash
grep -Rho '<rule id="[0-9]\+"' infra/wazuh/rules | sort | uniq -d
```

Cette commande affiche les IDs dupliques dans ce dossier. Comparez aussi les
IDs avec les fichiers actifs du manager. Ne chargez pas le monolithe legacy
avec ce jeu modulaire et ne remplacez pas votre `local_rules.xml` existant.

Pour le deploiement persistant et la validation Docker, suivez
[l'etape 6 du guide](../../../docs/MON_PROJET_ETAPE_PAR_ETAPE.md#6-corriger-décodeurs-et-règles-avec-persistance).
