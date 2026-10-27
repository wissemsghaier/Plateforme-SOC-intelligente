# Certificats de confiance

Placez ici uniquement les certificats CA publics nécessaires à la vérification TLS
du Wazuh Indexer. Les conteneurs Copilot et export ML montent ce dossier en lecture
seule sous `/app/certs`.

Ne placez jamais de clé privée, de certificat client privé ou de secret dans ce
dossier. Les certificats publics ajoutés ici peuvent être partagés avec le projet
si cela est approprié pour votre environnement.
