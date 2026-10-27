# Dossier infra/wazuh/rules/windows

Ce dossier contient les regles Windows custom de PHASE4.

## Fichiers et role

- 002-windows-firewall.xml
  - Detection Windows Filtering Platform (events 5152/5156/5157).
  - Correlations scan TCP et flood ICMP.
  - Detection brute-force logon (event 4625 + correlation).

- 007-windows_sysmon.xml
  - Detection comportements process et reseau Sysmon:
    - PowerShell et PowerShell encode,
    - LOLBins (mshta, rundll32),
    - acces LSASS,
    - creation service,
    - remote admin tools,
    - patterns reseau repetitifs (possible C2).

## Utilite SOC

- Couvre execution, defense evasion, lateral movement, credential access et C2.
- Offre un niveau detection plus riche que les seuls events firewall.

## Important

- Ces regles supposent que les events firewall/Sysmon sont bien collectes par l agent.
- Toute modification doit etre revalidee avec des evenements Windows reels.

## Etapes et commandes

Suivre le [guide de deploiement persistant](../../../../docs/MON_PROJET_ETAPE_PAR_ETAPE.md).
Les scripts de simulation et de validation historiques ne sont pas fournis.
Sur Ubuntu SOC :

```sh
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
```

Verifier ensuite les evenements dans Wazuh et leur correspondance avec le
journal Windows. Les correlations doivent etre testees avec plusieurs
evenements de meme source dans la fenetre de temps prevue.
