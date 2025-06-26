# Parser CERT-FR RSS – Documentation & Fonctionnalités

## Présentation du projet

Ce projet automatise la récupération, l'analyse et l'export des alertes de sécurité publiées par le CERT-FR via leur flux RSS. Il permet de centraliser et de structurer ces alertes pour une intégration facile dans des outils de supervision comme Splunk, ou pour un usage autonome.

---

## Pourquoi ce projet ?

- **Automatiser la veille sécurité** : plus besoin de surveiller manuellement le site du CERT-FR.
- **Centraliser l'information** : toutes les alertes pertinentes sont extraites, formatées et stockées dans un fichier JSON.
- **Faciliter l'intégration** : la sortie du script est compatible avec Splunk ou tout autre SIEM acceptant du JSON.
- **S'adapter à tous les environnements** : gestion du proxy, configuration souple, robustesse en production.

---

## Fonctionnalités principales

- **Téléchargement automatique** du flux RSS des alertes CERT-FR.
- **Parsing intelligent** : extraction des alertes de l'année en cours, récupération des détails de chaque alerte.
- **Extraction structurée** des sections importantes (risques, description, etc.) depuis la page de chaque alerte.
- **Détection des nouveautés** : comparaison avec l'historique pour ne traiter que les nouvelles alertes.
- **Export JSON** : chaque nouvelle alerte est affichée en JSON (pour Splunk) et ajoutée à l'historique.
- **Gestion du proxy** : configuration simple pour s'adapter à tous les réseaux d'entreprise.
- **Robustesse** : gestion des erreurs réseau, des problèmes d'encodage, et des cas particuliers du flux RSS.

---

## Structure du projet

```
parserPython/
├── main.py                       # Script de test/développement (usage local)
├── requirements.txt              # Dépendances Python
├── README.md                     # Documentation du projet
├── data/
│   └── tmp.json                  # Historique des alertes déjà traitées
├── local/
│   └── (inputs.conf)             # Fichier de configuration (à créer)
├── TA_certfr_parser/
│   ├── bin/
│   │   └── main_build-in.py      # Script principal pour la production/Splunk
│   ├── data/
│   │   └── tmp.json              # Historique utilisé par le script principal
│   └── local/
│       ├── inputs.conf           # Fichier de configuration réseau
│       └── props.conf            # (optionnel, pour Splunk)
```

---

## Fonctionnement du script principal (`main_build-in.py`)

1. **Lecture de la configuration**  
   Le script lit `inputs.conf` pour récupérer l'URL du flux RSS et, si besoin, le proxy réseau.
2. **Téléchargement du flux RSS**  
   Le flux est récupéré (en passant par le proxy si configuré).
3. **Parsing et extraction**  
   - Les alertes de l'année en cours sont extraites.
   - Pour chaque alerte, la page détaillée est téléchargée et les sections importantes sont extraites.
4. **Comparaison avec l'historique**  
   - Les nouvelles alertes (non présentes dans `tmp.json`) sont identifiées.
5. **Export et mise à jour**  
   - Les nouvelles alertes sont affichées en JSON (pour Splunk ou autre).
   - L'historique (`tmp.json`) est mis à jour pour éviter les doublons lors des prochains lancements.

---

## Gestion du proxy

### 1. Quand configurer un proxy ?
- **Obligatoire** si votre serveur/machine n'a pas d'accès direct à Internet (cas fréquent en entreprise ou en production).
- **Facultatif** si vous avez un accès Internet direct (vous pouvez alors laisser la valeur vide).

### 2. Où configurer le proxy ?
- Le proxy se configure dans le fichier :  
  `TA_certfr_parser/local/inputs.conf`

### 3. Format attendu dans le fichier de configuration
Dans la section `[network]` du fichier `inputs.conf`, ajoutez ou modifiez la ligne :

```ini
[network]
proxy = http://monproxy.mondomaine.com:8080
```
- Remplacez l'URL par celle de votre proxy.
- **Le schéma (`http://` ou `https://`) est obligatoire.**
- Si le proxy nécessite une authentification :
  ```ini
  proxy = http://user:password@monproxy.mondomaine.com:8080
  ```

### 4. Que faire si aucun proxy n'est requis ?
- Laissez la ligne vide ou commentez-la :
  ```ini
  proxy =
  ```


### 5. Cas particuliers
- Si votre proxy n'accepte que certains protocoles (HTTP/HTTPS), adaptez le schéma.
- Si vous changez de réseau (ex : passage du bureau à la maison), pensez à adapter ou vider la configuration du proxy.

### 6. Résumé
- **Toujours** mettre à jour `inputs.conf` selon votre environnement réseau.
- **Ne jamais** coder en dur le proxy dans le script : utilisez la configuration.

**Astuce** :  
Après modification du proxy, relancez le script pour prendre en compte la nouvelle configuration.

---

## Différence entre `main.py` et `main_build-in.py`

- **main.py** : script de test/développement, pour usage local, moins robuste, chemins relatifs à la racine.
- **main_build-in.py** : script de production, configuration avancée, gestion du proxy, adapté à l'intégration Splunk, chemins dynamiques.

---

## Utilisation

1. **Installer les dépendances**  
   ```bash
   pip install -r requirements.txt
   ```
2. **Configurer le proxy si besoin**  
   Modifier `TA_certfr_parser/local/inputs.conf`.
3. **Lancer le script principal**  
   ```bash
   python3 TA_certfr_parser/bin/main_build-in.py
   ```
