# Dossier infra/wazuh/windows

Ce dossier contient la configuration de reference de l agent Wazuh Windows.

## Fichier

- ossec.conf
  - Configure l envoi au manager Wazuh.
  - Collecte Application, Security et System event channels.
  - Security query conserve les evenements 5152/5156/5157 (firewall), utiles aux regles PHASE4.
  - Active modules syscheck, sca, syscollector, rootcheck.

## Utilite

- Permet la detection Windows firewall, brute force logon, et scenarios Sysmon.
- Evite de filtrer des events critiques pour la correlation.

## Etapes et commandes

Sur l agent Windows (PowerShell admin), sauvegarder avant toute modification :

```powershell
$backup = "C:\Program Files (x86)\ossec-agent\ossec.conf.$(Get-Date -Format yyyyMMdd-HHmmss).bak"
Copy-Item "C:\Program Files (x86)\ossec-agent\ossec.conf" $backup
```

Fusionner seulement les sections utiles de [ossec.conf](ossec.conf).
Conserver l'enrolement et les chemins de l'agent actif. Installer Sysmon et
configurer l'audit firewall separement ; declarer un canal ne produit pas ses
evenements. Puis :

```powershell
Restart-Service WazuhSvc
Get-Service WazuhSvc
```

Verification des derniers logs agent:

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 100
```
