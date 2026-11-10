# Ajouter une machine Linux à la réponse automatisée

Ce guide décrit la préparation minimale pour exécuter `POST /respond/linux`
depuis `response-api`.

## 1) Préparer l'accès SSH sur la machine Linux cible

Sur la cible Linux (exemple `192.168.99.30`) :

1. Créer un compte de service dédié (exemple `socsvc`).
2. Autoriser l'authentification (mot de passe fort ou clé SSH).
3. Installer/activer OpenSSH server.
4. Restreindre l'accès SSH au serveur SOC.
5. Donner les droits sudo nécessaires aux actions autorisées.

Exemple sudoers (adapter à votre politique) :

```text
socsvc ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/nft, /usr/sbin/usermod, /usr/bin/pkill, /bin/bash
```

## 2) Construire le fichier known_hosts côté SOC

Depuis le serveur SOC :

```bash
mkdir -p /opt/Plateforme-SOC-intelligente/infra/certs
ssh-keyscan -H 192.168.99.30 >> /opt/Plateforme-SOC-intelligente/infra/certs/linux_known_hosts
```

## 3) Configurer `.env` côté SOC

Éditer `/opt/Plateforme-SOC-intelligente/.env` :

```env
LINUX_SSH_ENABLED=true
LINUX_SSH_ALLOWED_HOSTS=192.168.99.30
LINUX_SSH_PORT=22
LINUX_SSH_USER=socsvc
LINUX_SSH_PASS=CHANGE_ME_LINUX_SSH_PASSWORD
LINUX_SSH_KEY_PATH=
LINUX_SSH_KNOWN_HOSTS=/app/certs/linux_known_hosts
LINUX_SSH_USE_SUDO=true
LINUX_SSH_ALLOWED_USERS=testsoc
LINUX_SSH_ALLOWED_PROCESSES=nginx,apache2
```

> Utiliser `LINUX_SSH_KEY_PATH` à la place de `LINUX_SSH_PASS` si vous préférez
> l'authentification par clé.

## 4) Redémarrer `response-api`

```bash
cd /opt/Plateforme-SOC-intelligente
docker compose up -d --build response-api
docker compose restart response-api
```

## 5) Tester `POST /respond/linux`

```bash
TOKEN='<SOC_API_TOKEN>'
curl --fail-with-body -s -X POST http://192.168.99.15:8000/respond/linux \
  -H "X-API-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host":"192.168.99.19","action":"isolate","approved_by":"analyste1","case_id":"T-003"}'
```

Attendu : `"status":"completed"` et `result.status = 0`.

## 6) Liaison Shuffle

Dans le workflow Shuffle :

1. `build_response_payload` (détermine host/action/approved_by)
2. `should_trigger_response`
3. si Linux : `call_response_api_linux` vers `/respond/linux`
4. `log_response_result`

