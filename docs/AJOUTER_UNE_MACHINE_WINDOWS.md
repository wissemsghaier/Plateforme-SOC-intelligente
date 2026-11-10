# Ajouter une machine Windows (WinRM + response-api + Shuffle)

Ce guide explique comment ajouter une nouvelle machine Windows cible au workflow
de réponse automatisée (`response-api`) déjà en place.

Exemple utilisé : nouvelle machine `192.168.99.20`.

---

## 1) Objectif

Après cette procédure, l'API de réponse doit pouvoir exécuter une action sur la
nouvelle machine via :

- `POST /respond` sur `http://192.168.99.15:8000/respond`
- WinRM **HTTPS** sur le port `5986`

---

## 2) Prérequis

- Le service `response-api` est opérationnel.
- La machine Windows cible est joignable depuis le serveur SOC.
- Vous avez un compte WinRM autorisé (ex. `wissem\svc_soc`).

Fichiers/répertoires concernés :

- [docker-compose.yml](../docker-compose.yml)
- [response-api/app.py](../response-api/app.py)
- `/.env` sur le serveur SOC (copie locale de `.env.example`)
- [infra/certs/](../infra/certs/)

---

## 3) Sur la machine Windows cible (PowerShell Administrateur)

### 3.1 Créer un certificat WinRM avec SAN IP

> Adaptez le DNS Name et l'IP si nécessaire.

```powershell
$cert = New-SelfSignedCertificate `
  -CertStoreLocation "Cert:\LocalMachine\My" `
  -Subject "CN=windows-lab02" `
  -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
  -NotAfter (Get-Date).AddYears(2) `
  -TextExtension @("2.5.29.17={text}DNS=windows-lab02&IPAddress=192.168.99.19")

$thumb = $cert.Thumbprint
$thumb
```

### 3.2 Créer/mettre à jour le listener WinRM HTTPS (5986)

```powershell
Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -like "*Transport=HTTPS*" } | Remove-Item -Recurse -Force
New-Item -Path WSMan:\Localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $thumb -Force
winrm enumerate winrm/config/Listener
```

### 3.3 Ouvrir le firewall Windows

```powershell
New-NetFirewallRule -DisplayName "WinRM HTTPS 5986" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
```

### 3.4 Exporter le certificat public

```powershell
New-Item -ItemType Directory -Force C:\Temp | Out-Null
Export-Certificate -Cert "Cert:\LocalMachine\My\$thumb" -FilePath "C:\Temp\windows-winrm-19.cer"
```

---

## 4) Sur le serveur SOC Ubuntu

### 4.1 Copier le certificat exporté

Copiez `C:\Temp\windows-winrm-20.cer` vers :

- `/opt/Plateforme-SOC-intelligente/infra/certs/windows-winrm-19.cer`

### 4.2 Convertir en PEM

```bash
cd /opt/Plateforme-SOC-intelligente/infra/certs
openssl x509 -inform DER -in windows-winrm-20.cer -out windows-winrm-20.pem
```

### 4.3 Vérifier le SAN

```bash
openssl x509 -in /opt/Plateforme-SOC-intelligente/infra/certs/windows-winrm-19.pem -noout -text | grep -A2 "Subject Alternative Name"
```

Attendu :

- `IP Address:192.168.99.20`

---

## 5) Construire/mettre à jour le bundle des certificats WinRM

Si vous avez déjà une autre machine (ex. `192.168.99.18`), créez un bundle :

```bash
cd /opt/Plateforme-SOC-intelligente/infra/certs
cat windows-winrm-ca.pem windows-winrm-19.pem > windows-winrm-bundle.pem
```

Le bundle permet à `response-api` de valider plusieurs machines avec un seul
fichier de confiance.

---

## 6) Mettre à jour `.env` (serveur SOC)

Éditez `/opt/Plateforme-SOC-intelligente/.env` :

```env
WINRM_ENABLED=true
WINRM_ALLOWED_HOSTS=192.168.99.18,192.168.99.20
WINRM_PORT=5986
WINRM_CA_CERT=/app/certs/windows-winrm-bundle.pem
```

Gardez `WINRM_USER` et `WINRM_PASS` valides.

---

## 7) Redémarrer `response-api`

```bash
cd /opt/Plateforme-SOC-intelligente
docker compose up -d response-api
docker compose restart response-api
```

Vérifier :

```bash
curl --fail-with-body http://192.168.99.15:8000/health
```

---

## 8) Tester la nouvelle machine via l'API

```bash
TOKEN='<SOC_API_TOKEN>'
curl --fail-with-body -s -X POST http://192.168.99.15:8000/respond \
  -H "X-API-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host":"192.168.99.19","action":"isolate","approved_by":"analyste1","case_id":"T-002"}'
```

Attendu : réponse avec `"status":"completed"` et `result.status = 0`.

---

## 9) Liaison Shuffle (important)

Dans le workflow Shuffle, ne mettez pas une IP fixe.

Le nœud `build_response_payload` doit remplir `payload.host` dynamiquement
selon l'alerte (machine cible).

Exemple de flux :

1. `build_response_payload`
2. `should_trigger_response`
3. si `trigger_response=true` -> `call_response_api`
4. `log_response_result`

---

## 10) Dépannage rapide

- `Hôte non autorisé` -> ajouter l'IP dans `WINRM_ALLOWED_HOSTS`.
- `Seul WinRM sur HTTPS (port 5986)` -> vérifier `WINRM_PORT=5986`.
- `certificat CA introuvable` -> vérifier chemin `WINRM_CA_CERT` et montage
  de [infra/certs/](../infra/certs/).
- `IP address mismatch` -> le certificat de la machine ne contient pas
  l'IP cible dans le SAN.
- `commande distante a échoué` -> vérifier droits du compte WinRM sur Windows.

---

## 11) Sécurité

- Ne mettez pas de secrets réels dans [`.env.example`](../.env.example).
- Après les tests, changez les secrets exposés (`SOC_API_TOKEN`, `WINRM_PASS`)
  puis redémarrez `response-api`.

