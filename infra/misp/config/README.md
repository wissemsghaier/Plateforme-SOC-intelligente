# Dossier infra/misp/config

Ce dossier contient les presets de configuration MISP importables.

## Fichier

- default.json
  - Contient une liste de feeds threat intelligence.
  - Exemple: CIRCL, Botvrij, Phishtank, listes IP compromisees, noeuds Tor.

## Utilite

- Donne une base TI immediate apres deploiement MISP.
- Evite une configuration manuelle longue feed par feed.

## Recommandation

- Adapter les feeds aux besoins reels du SOC.
- Desactiver les feeds non utiles pour limiter bruit et volume.

## Etapes et commandes

Verifier que le preset est present:

```bash
ls -l infra/misp/config/default.json
```

PowerShell:

```powershell
Get-Item infra\misp\config\default.json
```

Apres demarrage MISP, utiliser ce preset pour alimenter les feeds TI selon vos besoins.
