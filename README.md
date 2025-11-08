# 🛡️ Cloud Compliance Tool

> **Plateforme révolutionnaire d'audit de conformité NIS2 & SecNumCloud pour infrastructures cloud**

Une solution open-source professionnelle pour auditer automatiquement la conformité de vos architectures cloud avec les référentiels **NIS2** (Directive européenne) et **SecNumCloud** (ANSSI).

---

## 🌟 Fonctionnalités Principales

### ✅ Multi-Framework
- **NIS2** - Directive Network and Information Systems (EU 2022/2555)
- **SecNumCloud** - Référentiel ANSSI v3.2
- **Extensible** - Support futur pour ISO 27001, RGPD, HDS, PCI-DSS

### ☁️ Multi-Cloud & Multi-Platform
- **AWS** - Amazon Web Services (15+ types de ressources)
- **Azure** - Microsoft Azure (10+ types de ressources) ✅
- **GCP** - Google Cloud Platform (9+ types de ressources) ✅
- **Kubernetes** - Clusters K8s (17+ types de ressources) ✅
- **OVH, Scaleway** - Support prévu

### 🔍 Découverte Automatique
- Scan complet de votre infrastructure multi-cloud
- **50+ types de ressources** au total (AWS, Azure, GCP, K8s)
- Cartographie interactive de l'architecture
- Support des environnements hybrides (cloud + on-premise via K8s)
- Analyse des dépendances entre ressources

### 📊 Analyse de Conformité
- Évaluation automatique contre 10+ règles NIS2
- Vérification de 6+ exigences SecNumCloud
- Scoring de conformité en temps réel
- Priorisation des risques (critique/élevé/moyen/faible)

### 📈 Dashboard Interactif
- Vue d'ensemble de la conformité globale
- Graphiques de progression par framework
- Alertes sur les non-conformités critiques
- Interface moderne et intuitive

### 🎯 Remédiation Guidée
- Recommandations détaillées pour chaque non-conformité
- Étapes de correction documentées
- Références aux standards officiels
- Preuves de conformité

---

## 🚀 Démarrage Rapide

### Prérequis

- **Docker** >= 20.10
- **Docker Compose** >= 2.0
- **Git**

### Installation en 3 étapes

```bash
# 1. Cloner le repository
git clone https://github.com/votre-org/cloud-compliance-tool.git
cd cloud-compliance-tool

# 2. Lancer l'application avec Docker Compose
cd docker
docker-compose up -d

# 3. Accéder à l'interface
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# Documentation API: http://localhost:8000/docs
```

**C'est tout !** L'application est prête à utiliser.

---

## 📋 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (React)                         │
│  - Dashboard interactif                                     │
│  - Visualisation d'architecture                            │
│  - Rapports de conformité                                  │
└─────────────────────────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              API BACKEND (FastAPI)                          │
│  - Endpoints REST                                           │
│  - Authentification JWT                                     │
│  - Documentation OpenAPI                                    │
└─────────────────────────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│           MOTEUR DE CONFORMITÉ                              │
│  - Scanner Multi-Cloud (AWS, Azure, GCP)                    │
│  - Moteur de Règles Extensible                             │
│  - Évaluation NIS2 & SecNumCloud                           │
└─────────────────────────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│         BASE DE DONNÉES (PostgreSQL)                        │
│  - Audits et historique                                     │
│  - Résultats de conformité                                 │
│  - Inventaire des ressources cloud                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 📖 Guide d'Utilisation

### 1. Configuration des Credentials Cloud

Pour scanner votre infrastructure AWS réelle, configurez vos credentials :

```bash
# Créer un fichier .env dans le dossier backend
cd backend
cp .env.example .env

# Éditer .env et ajouter vos credentials AWS
AWS_ACCESS_KEY_ID=votre-access-key
AWS_SECRET_ACCESS_KEY=votre-secret-key
AWS_REGION=eu-west-1
```

**Note de sécurité** : Utilisez un utilisateur IAM avec des permissions en lecture seule.

### 2. Lancer un Audit

1. Accédez à l'interface web : `http://localhost:3000`
2. Cliquez sur **"Lancer un Audit"**
3. Sélectionnez :
   - **Référentiel** : NIS2 ou SecNumCloud
   - **Provider** : AWS
   - **Région** : eu-west-1, eu-west-3, ou eu-central-1
4. Cliquez sur **"Démarrer l'Audit"**

### 3. Consulter les Résultats

L'audit s'exécute automatiquement et affiche :
- **Score global de conformité** (0-100%)
- **Détails par framework** (NIS2, SecNumCloud)
- **Liste des non-conformités** avec recommandations
- **Ressources analysées** par type

### 4. Visualiser l'Architecture

1. Allez dans **"Architecture"**
2. Cliquez sur **"Lancer le Scan"**
3. Explorez vos ressources cloud par catégorie :
   - EC2 instances
   - S3 buckets
   - IAM users/roles
   - RDS databases
   - VPC, Security Groups
   - CloudTrail, KMS, Lambda, etc.

---

## 🔒 Règles de Conformité

### NIS2 (Directive EU 2022/2555)

| Article | Catégorie | Vérifications |
|---------|-----------|---------------|
| **Article 21** | Gestion des Risques Cyber | Journalisation, Chiffrement, MFA, Segmentation réseau |
| **Article 22** | Réponse aux Incidents | Détection, Alertes, Surveillance |
| **Article 23** | Continuité d'Activité | Sauvegardes, Plan de reprise |

**Total : 6 règles implémentées**

### SecNumCloud (ANSSI v3.2)

| Exigence | Description | Vérifications |
|----------|-------------|---------------|
| **Protection des données** | Chiffrement au repos AES-256 | S3, EBS, RDS, Snapshots |
| **Gestion des accès** | Authentification forte (MFA) | Utilisateurs IAM |
| **Traçabilité** | Journalisation complète | CloudTrail multi-régions |
| **Isolation** | Segmentation réseau | VPC, Security Groups |
| **Sauvegarde** | Rétention >= 7 jours | RDS Backups |
| **Souveraineté** | Données en UE | Régions européennes |

**Total : 6 règles implémentées**

---

## 📡 API Endpoints

### Scanner Cloud
```http
POST /api/v1/cloud-accounts/scan
  ?provider=aws&region=eu-west-1
```

### Lancer un Audit
```http
POST /api/v1/audits/run
  ?framework=NIS2&provider=aws&region=eu-west-1
```

### Vue d'ensemble Conformité
```http
GET /api/v1/stats/compliance-overview
  ?provider=aws&region=eu-west-1
```

### Lister les Frameworks
```http
GET /api/v1/compliance/frameworks
```

### Documentation complète
Accédez à la documentation Swagger : `http://localhost:8000/docs`

---

## 🛠️ Développement

### Structure du Projet

```
cloud-compliance-tool/
├── backend/                # Backend FastAPI
│   ├── app.py             # Application principale
│   ├── models.py          # Modèles SQLAlchemy
│   ├── config.py          # Configuration
│   ├── database.py        # Connexion DB
│   ├── scanners/          # Scanners cloud
│   │   └── aws_scanner.py # Scanner AWS
│   ├── compliance/        # Moteur de conformité
│   │   └── engine.py      # Évaluation des règles
│   └── compliance_rules/  # Définitions des règles
│       ├── NIS2/          # Règles NIS2
│       └── SecNumCloud/   # Règles SecNumCloud
├── frontend/              # Frontend React
│   ├── src/
│   │   ├── App.js         # Application principale
│   │   └── components/    # Composants React
│   │       ├── Dashboard.js
│   │       ├── AuditRunner.js
│   │       ├── ArchitectureView.js
│   │       └── Reports.js
├── docker/                # Configuration Docker
│   └── docker-compose.yml
└── README.md
```

### Lancer en Mode Développement

**Backend :**
```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --reload
```

**Frontend :**
```bash
cd frontend
npm install
npm start
```

### Ajouter une Nouvelle Règle de Conformité

1. Créer un fichier JSON dans `backend/compliance_rules/{framework}/`

```json
{
  "id": "NIS2_Article_XX",
  "framework": "NIS2",
  "category": "Catégorie",
  "title": "Titre de la règle",
  "description": "Description détaillée",
  "severity": "critical",
  "remediation": ["Étape 1", "Étape 2"],
  "references": ["URL officielle"],
  "cloud_providers": ["aws", "azure"],
  "resource_types": ["EC2Instance", "S3Bucket"],
  "checks": [
    {
      "type": "property",
      "property": "metadata.encrypted",
      "operator": "is_true",
      "description": "Vérifier le chiffrement"
    }
  ]
}
```

2. Redémarrer le backend - la règle est chargée automatiquement

---

## 🧪 Tests

### Backend
```bash
cd backend
pytest
```

### Frontend
```bash
cd frontend
npm test
```

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Voici comment contribuer :

1. Fork le projet
2. Créez une branche (`git checkout -b feature/AmazingFeature`)
3. Committez vos changements (`git commit -m 'Add AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

### Priorités de Développement

- [ ] Support Azure et GCP
- [ ] Génération de rapports PDF/Excel
- [ ] IA pour détection d'anomalies
- [ ] Intégration CI/CD
- [ ] Authentification SSO
- [ ] Support ISO 27001, RGPD, HDS

---

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---

## 📞 Support

- **Documentation** : [Wiki du projet](https://github.com/votre-org/cloud-compliance-tool/wiki)
- **Issues** : [GitHub Issues](https://github.com/votre-org/cloud-compliance-tool/issues)
- **Email** : support@cloud-compliance-tool.com

---

## 🙏 Remerciements

- **ANSSI** - Pour le référentiel SecNumCloud
- **Commission Européenne** - Pour la directive NIS2
- **Communauté Open Source** - Pour les outils et bibliothèques

---

## ⚖️ Avertissement Légal

Cet outil est fourni à titre informatif. La conformité réglementaire nécessite une validation par des experts qualifiés. Les auteurs ne peuvent être tenus responsables des décisions prises sur la base des résultats de cet outil.

---

**Fait avec ❤️ pour la conformité et la sécurité cloud**
