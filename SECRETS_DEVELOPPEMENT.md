# 🔐 GUIDE SECRETS ET MOTS DE PASSE

## **⚠️ INFORMATIONS SENSIBLES - DÉVELOPPEMENT UNIQUEMENT**

### **🔑 Comptes utilisateurs de test**
```yaml
# Compte Admin Principal
admin:
  username: "admin"
  password: "AdminDCOP2025!@#$"
  role: "Admin"
  email: "principal@dcop.local"

# Compte Admin de Test
test_admin:
  username: "test_admin"  
  password: "TestAdmin2025!@#$%^"
  role: "Admin"
  email: "admin@dcop.local"

# Compte Directeur
directeur:
  username: "directeur"
  password: "DirectorSecure2025!@#"
  role: "Directeur"
  email: "directeur@dcop.local"
```

### **🗄️ Base de données PostgreSQL**
```yaml
Host: localhost (via Docker)
Port: 5432 (interne uniquement)
Database: dcop_413
Username: dcop_user
Password: "gy4bMRN7SpRjexQKqb5o+EsryHJ6WuTX0gRPEiqAS7g="
```

### **🔐 Secrets Docker**
```yaml
# Fichier: secrets_secure/postgres_password.key
postgres_password: "gy4bMRN7SpRjexQKqb5o+EsryHJ6WuTX0gRPEiqAS7g="

# Fichier: secrets_secure/jwt_secret.key  
jwt_secret: "[Clé de 256 bits générée automatiquement]"

# Fichier: secrets_secure/encryption_key.key
encryption_key: "[Clé de chiffrement générée automatiquement]"
```

### **🌐 URLs d'accès**
```yaml
Frontend: http://localhost:8080
API Backend: http://localhost:8080/api (via proxy)
Admin Panel: http://localhost:8080/admin
Health Check: http://localhost:8080/api/health
Statistics: http://localhost:8080/api/public/statistics/dashboard
```

### **📝 Tests API rapides**
```bash
# Test de connexion
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test_admin","password":"TestAdmin2025!@#$%^"}'

# Test statistiques publiques
curl http://localhost:8080/api/public/statistics/dashboard

# Test avec token
curl -H "Authorization: Bearer [TOKEN]" \
  http://localhost:8080/api/visitors
```

### **🔧 Commandes Docker utiles**
```bash
# Connexion à la BD
docker exec -it dcop-413-db psql -U dcop_user -d dcop_413

# Logs des services
docker-compose logs -f backend
docker-compose logs -f nginx
docker-compose logs -f database

# Redémarrage rapide
./start_system.sh
```

⚠️ **ATTENTION :** Ces informations sont uniquement pour le développement. En production, utilisez des secrets sécurisés et des mots de passe complexes générés automatiquement.
