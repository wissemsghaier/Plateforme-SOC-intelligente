# Plan de réseau et règles pfSense de laboratoire

Les règles sont des exemples à créer et vérifier dans l'interface pfSense. Gardez
la politique WAN entrante par défaut (bloquée) et ne copiez pas une règle sans
vérifier son interface, sa direction et ses adresses.

Le serveur SOC (Wazuh, TheHive, Cortex) est `192.168.99.15/24` sur `ens18`.
L'adresse de l'interface pfSense dans `192.168.99.0/24` reste à confirmer ;
ne supposez pas qu'elle vaut `.1`. Ce segment doit rester isolé des cibles et
de Kali : du trafic entre machines d'un même sous-réseau peut contourner pfSense.

| Interface | Action | Source | Destination | Port/protocole | Objet |
|---|---|---|---|---|---|
| OPT1 (attaque) | Pass | `10.10.10.0/24` | `192.168.56.0/24` | Selon les tests | Permettre les tests Kali contre les cibles |
| OPT1 (attaque) | Block | `10.10.10.0/24` | `192.168.99.0/24` | Tous | Empêcher Kali d'atteindre le SOC |
| LAN (cibles) | Pass | `192.168.56.0/24` | `192.168.99.15` | TCP 1514, 1515 | Agents vers Wazuh |
| LAN (cibles) | Pass | `192.168.56.1` | `192.168.99.15` | UDP 514 | Syslog pfSense/Suricata vers Wazuh |
| OPT2 (SOC) | Pass, ciblé | `192.168.99.15` | `192.168.56.40` | TCP 5986 | WinRM HTTPS vers Windows, seulement si approuvé |

L'ordre des règles est important : testez explicitement que le trafic attaque → SOC
est bloqué. Si le serveur SOC exécute aussi Shuffle, n'autorisez pas globalement
tout le réseau SOC vers toutes les cibles.

Un adaptateur NAT temporaire peut servir au téléchargement de paquets. Désactivez-le
ensuite pour conserver l'isolation du laboratoire.
