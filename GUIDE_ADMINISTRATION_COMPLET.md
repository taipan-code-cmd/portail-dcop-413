# 📋 GUIDE COMPLET D'ADMINISTRATION - PORTAIL DCOP-413

## 🔐 INFORMATIONS D'ACCÈS ADMINISTRATEUR

### URL D'ACCÈS PRINCIPAL
```
https://localhost:8443
```

### COMPTES ADMINISTRATEURS

#### 1. **COMPTE ADMINISTRATEUR PRINCIPAL**
```
👤 Utilisateur : admin
🔑 Mot de passe : [REDACTED_[REDACTED]
🎯 Rôle : admin
✅ Permissions : Accès complet à toutes les fonctionnalités
```

#### 2. **COMPTE SUPERVISEUR**
```
👤 Utilisateur : supervisor
🔑 Mot de passe : supervisor123
🎯 Rôle : supervisor
✅ Permissions : Gestion des visites et supervision
```

#### 3. **COMPTE AGENT OPÉRATIONNEL**
```
👤 Utilisateur : agent
🔑 Mot de passe : agent123
🎯 Rôle : agent
✅ Permissions : Opérations de base et gestion des visites
```

---

## 🛠️ CRÉATION D'UN NOUVEL ADMINISTRATEUR

### Méthode 1 : Via Interface Web (Recommandée)
1. **Se connecter avec le compte admin principal**
   - URL : `https://localhost:8443/login`
   - Utilisateur : `admin`
   - Mot de passe : `[REDACTED_[REDACTED]

2. **Accéder à la gestion des utilisateurs**
   - Menu : Administration → Gestion des Utilisateurs
   - Cliquer sur "Créer un utilisateur"

3. **Remplir le formulaire**
   ```
   Nom d'utilisateur : [nouveau_admin]
   Mot de passe : [mot_de_passe_sécurisé]
   Rôle : admin / supervisor / agent
   Email : [email@domaine.com] (optionnel)
   Prénom : [prénom] (optionnel)
   Nom : [nom] (optionnel)
   ```

### Méthode 2 : Via Script SQL Direct
```sql
-- Se connecter à la base de données PostgreSQL
psql -U postgres -d dcop_413

-- Créer un nouvel administrateur
INSERT INTO users (
    id,
    username,
    [REDACTED]
    role,
    is_active,
    created_at,
    updated_at,
    integrity_hash
) VALUES (
    uuid_generate_v4(),
    'nouveau_admin',
    '$argon2id$v=19$m=65536,t=3,p=4$SALT_ICI$HASH_ICI', -- Hash du mot de passe
    'admin'::user_role,
    true,
    NOW(),
    NOW(),
    'integrity_hash_calculé'
);
```

### Méthode 3 : Via Script de Création
```bash
# Exécuter le script de création d'utilisateur
cd /home/taipan_51/portail_413/portail_413
./create_admin_user.sh

# Suivre les instructions interactives
```

---

## 🏗️ ARCHITECTURE DES RÔLES

### **ADMINISTRATEUR (admin)**
**Permissions complètes :**
- ✅ Gestion des utilisateurs (création, modification, suppression)
- ✅ Configuration du système
- ✅ Accès aux rapports d'audit
- ✅ Gestion des visiteurs et visites
- ✅ Statistiques complètes
- ✅ Configuration de sécurité
- ✅ Sauvegarde et restauration

**Dashboard spécialisé :**
- Tableau de bord administrateur complet
- Graphiques de performance
- Logs système en temps réel
- Gestion des paramètres globaux

### **SUPERVISEUR (supervisor)**
**Permissions de supervision :**
- ✅ Gestion des visites (approbation, modification)
- ✅ Supervision des agents
- ✅ Rapports de visites
- ✅ Statistiques d'équipe
- ❌ Gestion des utilisateurs (limitée)
- ❌ Configuration système

**Dashboard spécialisé :**
- Vue supervision des visites
- Approbation en temps réel
- Rapports d'équipe
- Monitoring des activités

### **AGENT (agent)**
**Permissions opérationnelles :**
- ✅ Gestion des visites quotidiennes
- ✅ Enregistrement des visiteurs
- ✅ Modification des visites assignées
- ✅ Consultation des plannings
- ❌ Gestion d'utilisateurs
- ❌ Rapports d'audit

**Dashboard spécialisé :**
- Interface opérationnelle simple
- Liste des visites du jour
- Enregistrement rapide
- Statuts des visites

---

## 📊 FONCTIONNALITÉS PAR INTERFACE

### **PAGE D'ACCUEIL PUBLIQUE**
```
URL : https://localhost:8443/
```
- ✅ Enregistrement public des visites
- ✅ Accès sans authentification
- ✅ Formulaire complet avec photo obligatoire
- ✅ Consignes de sécurité

### **INTERFACE D'AUTHENTIFICATION**
```
URL : https://localhost:8443/login
```
- ✅ Connexion sécurisée
- ✅ Redirection automatique par rôle
- ✅ Validation JWT
- ✅ Gestion des tentatives de connexion

### **DASHBOARD ADMINISTRATEUR**
```
URL : https://localhost:8443/admin/dashboard
Accès : Rôle admin uniquement
```
- ✅ Vue d'ensemble complète
- ✅ Gestion des utilisateurs
- ✅ Rapports et statistiques
- ✅ Configuration système
- ✅ Logs d'audit

### **DASHBOARD SUPERVISEUR**
```
URL : https://localhost:8443/supervisor/dashboard
Accès : Rôle supervisor
```
- ✅ Gestion des visites
- ✅ Approbation des demandes
- ✅ Supervision d'équipe
- ✅ Rapports de supervision

### **DASHBOARD AGENT**
```
URL : https://localhost:8443/agent/dashboard
Accès : Rôle agent
```
- ✅ Interface opérationnelle
- ✅ Gestion des visites quotidiennes
- ✅ Enregistrement rapide
- ✅ Consultation des plannings

---

## 🔧 CONFIGURATION ET DÉMARRAGE

### **Démarrage Complet**
```bash
# 1. Démarrer la base de données (Docker)
cd /home/taipan_51/portail_413/portail_413
docker-compose up -d

# 2. Vérifier les migrations
psql $DATABASE_URL -c "SELECT * FROM users LIMIT 1;"

# 3. Démarrer le backend
cargo run --release

# 4. Compiler le frontend
cd ../frontend
npm run build

# 5. Accéder à l'application
# https://localhost:8443
```

### **Variables d'Environnement**
```bash
# Base de données
export DATABASE_URL="postgresql://app_user:[SECURE_[REDACTED]

# Serveur
export SERVER_HOST="127.0.0.1"
export SERVER_PORT="8443"

# Sécurité
export JWT_[REDACTED]
export ENCRYPTION_KEY="your_encryption_key_32_chars_long"
```

---

## 🧪 TESTS ET VALIDATION

### **Test des Comptes d'Accès**
```bash
# Script de test automatique
cd /home/taipan_51/portail_413
./test_auth_api.sh

# Test manuel via curl
curl -k -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","[REDACTED]
```

### **Validation du Système**
```bash
# Validation complète
./validate_registration_system.sh

# Test d'enregistrement de visite
./test_visit_registration.sh
```

---

## 🔐 SÉCURITÉ ET BONNES PRATIQUES

### **Mot de Passe Admin**
- 🔒 **Actuel :** `[REDACTED_[REDACTED]
- ⚠️ **À changer immédiatement en production**
- ✅ **Exigences :** Minimum 12 caractères, majuscules, minuscules, chiffres, symboles

### **Tokens JWT**
- ⏱️ **Durée de vie :** 15 minutes (access token)
- 🔄 **Refresh token :** 7 jours
- 🔐 **Chiffrement :** HS256 avec clé secrète

### **Base de Données**
- 🔐 **Chiffrement :** AES-256-GCM pour données sensibles
- 🔒 **Hachage :** Argon2id pour mots de passe
- ✅ **Intégrité :** SHA-512 pour vérification

---

## 📞 SUPPORT ET MAINTENANCE

### **Logs Système**
```bash
# Logs du backend
tail -f /home/taipan_51/portail_413/portail_413/server.log

# Logs de la base de données
docker logs dcop_db

# Logs d'audit dans l'interface admin
```

### **Sauvegarde**
```bash
# Sauvegarde manuelle de la base
./backup-db.sh

# Sauvegarde planifiée (cron)
./setup-cron.sh
```

### **Monitoring**
```bash
# Health check
curl -k https://localhost:8443/health

# Statistiques API
curl -k https://localhost:8443/api/public/health
```

---

## ✅ RÉSUMÉ RAPIDE

### **ACCÈS IMMÉDIAT**
1. **Démarrer :** `cargo run --release`
2. **Accéder :** `https://localhost:8443`
3. **Admin :** `admin` / `[REDACTED_[REDACTED]
4. **Public :** Cliquer "Enregistrer une Visite"

### **COMPTES DE TEST**
- **Admin :** `admin` / `[REDACTED_[REDACTED] (Accès complet)
- **Superviseur :** `supervisor` / `supervisor123` (Supervision)
- **Agent :** `agent` / `agent123` (Opérations)

Votre portail DCOP-413 est **prêt pour la production** ! 🚀
