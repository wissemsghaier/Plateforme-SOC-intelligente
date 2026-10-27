# Sécurité et limites opérationnelles

- Laboratoire isolé : les réseaux d'attaque, de cibles et SOC doivent être
  segmentés. Bloquez l'accès de Kali au réseau SOC.
- Secrets : générez des tokens distincts, protégez `.env` avec des permissions
  strictes et utilisez un coffre de secrets sur un déploiement partagé.
- API de réponse : `WINRM_ENABLED=false` par défaut ; liste d'hôtes autorisés
  obligatoire ; listes distinctes d'utilisateurs et de processus autorisés ;
  authentification par token ; action et paramètres validés ;
  approbation humaine requise. Les journaux des conteneurs sont la piste d'audit.
- Accès API : les API ML, de réponse et Copilot exigent chacune un token secret
  distinct. Ne partagez pas le token d'une API avec une autre.
- WinRM : configurez HTTPS (5986) avec un certificat vérifié et un compte dédié
  limité aux tâches nécessaires. N'utilisez pas Basic/non chiffré hors labo.
  L'API refuse les connexions WinRM sur le port HTTP 5985. Si la CA n'est pas
  déjà approuvée par le système du conteneur, fournissez son certificat public
  via `WINRM_CA_CERT`.
- Réseau : gardez les ports API sur l'interface SOC uniquement. Ne publiez jamais
  Docker, l'indexer, Wazuh, TheHive ou Ollama sur Internet.
- Indexer : le Copilot doit utiliser un compte en lecture seule et une autorité
  TLS fiable. La vérification TLS ne doit pas être désactivée.
- RAG : les journaux peuvent contenir des instructions malveillantes. Le modèle
  n'a pas de fonction d'exécution et ses réponses ne doivent jamais déclencher
  directement une action de réponse.
- Données : anonymisez les identifiants personnels avant d'utiliser un LLM externe.
  La configuration fournie utilise Ollama local et ne met pas en place de service
  externe.
- Machine learning : les artefacts Joblib ne doivent provenir que de cette source
  et de données maîtrisées. Les scores ne remplacent pas l'analyse humaine.
- Validation : testez en environnement de laboratoire et vérifiez les versions
  actuelles dans les documentations officielles avant de déployer.
