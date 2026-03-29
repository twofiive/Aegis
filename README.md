# Aegis

### Intégration du modèle

#### Création du flux de logs falco

- Lancer l'application

```bash
python app.py
```

- Lancer ngrok dans un autre terminal

```bash
ngrok http 5000
```

- Récupérer l'URL créé et ajouter dans le fichier secops-values.yaml dans le dossier falco dans le cluster. Par exemple :

```yaml
falcosidekick:
  config:
    webhook:
      address: "https://aedf-88-177-104-235.ngrok-free.app/api/webhook"
      method: "POST"
```
