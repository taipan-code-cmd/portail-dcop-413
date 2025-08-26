use actix_web::{
    web::{Data, Json},
    HttpRequest, HttpResponse,
};
use serde_json::{json, Value};
use validator::Validate;

use crate::errors::{AppError, Result};
use crate::models::CreateVisitorRequest;
use crate::services::VisitorService;
use crate::utils::extract_user_agent;

pub struct PublicHandler;

impl PublicHandler {
    /// Page d'accueil publique - Style VisioFlow
    pub async fn home() -> HttpResponse {
        HttpResponse::Ok().content_type("text/html").body(r#"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DCOP (413) - Portail des Visites</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f9fafb;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
        }
        .logo {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #3b82f6, #1d4ed8);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 20px;
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6, #1d4ed8);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 12px 24px;
            font-weight: 500;
            font-size: 16px;
            transition: all 0.2s ease;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #2563eb, #1e40af);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }
        .feature-card {
            background: white;
            border-radius: 12px;
            padding: 32px 24px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);
            transition: all 0.3s ease;
            border: 1px solid #f3f4f6;
        }
        .feature-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }
        .feature-icon {
            width: 56px;
            height: 56px;
            background: linear-gradient(135deg, #3b82f6, #1d4ed8);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px auto;
            color: white;
            font-size: 24px;
        }
        .hero-section {
            background: linear-gradient(135deg, #f9fafb 0%, #e5e7eb 100%);
            padding: 80px 0 100px 0;
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-6 py-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <div class="logo">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <span class="text-xl font-bold text-gray-900">DCOP</span>
                </div>
                <a href="/login" class="btn-primary">
                    Login
                </a>
            </div>
        </div>
    </header>

    <!-- Hero Section -->
    <section class="hero-section">
        <div class="max-w-4xl mx-auto px-6 text-center">
            <h1 class="text-5xl font-bold text-gray-900 mb-6">
                Simplifiez la gestion<br>
                de vos visites
            </h1>
            <p class="text-xl text-gray-600 mb-10 max-w-2xl mx-auto leading-relaxed">
                DCOP est la solution intuitive pour enregistrer, suivre et organiser<br>
                toutes vos visites de manière efficace.
            </p>
            <a href="/register-visitor" class="btn-primary text-lg px-8 py-4 inline-flex items-center space-x-2">
                <span>Enregistrer une visite</span>
            </a>
        </div>
    </section>

    <!-- Features Section -->
    <section class="py-20 bg-white">
        <div class="max-w-6xl mx-auto px-6">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-cog"></i>
                    </div>
                    <h3 class="text-lg font-semibold text-gray-900 mb-3">
                        Gestion système
                    </h3>
                    <p class="text-gray-600 text-sm leading-relaxed">
                        L'authentification sécurisée pour toutes les visites et la planification.
                    </p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-calendar-alt"></i>
                    </div>
                    <h3 class="text-lg font-semibold text-gray-900 mb-3">
                        Planification
                    </h3>
                    <p class="text-gray-600 text-sm leading-relaxed">
                        Organisez et gérez facilement tous vos rendez-vous et visites.
                    </p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <h3 class="text-lg font-semibold text-gray-900 mb-3">
                        Sécurité renforcée
                    </h3>
                    <p class="text-gray-600 text-sm leading-relaxed">
                        Protection maximale pour toutes les données sensibles.
                    </p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-chart-bar"></i>
                    </div>
                    <h3 class="text-lg font-semibold text-gray-900 mb-3">
                        Suivi avancé
                    </h3>
                    <p class="text-gray-600 text-sm leading-relaxed">
                        Analytics et rapports détaillés pour tous vos visiteurs.
                    </p>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="bg-blue-600 text-white py-8">
        <div class="max-w-6xl mx-auto px-6">
            <div class="flex flex-col md:flex-row justify-between items-center">
                <div class="mb-4 md:mb-0">
                    <p class="text-sm">Contact: info@dcop.gouv.fr</p>
                    <p class="text-sm">Tél. +33 1 XX XX XX XX</p>
                </div>
                <div class="text-sm opacity-80">
                    © 2025 DCOP. Tous droits réservés.
                </div>
            </div>
        </div>
    </footer>
</body>
</html>
        "#)
    }

    /// Page de connexion pour le staff - Style VisioFlow
    pub async fn login_form() -> HttpResponse {
        HttpResponse::Ok().content_type("text/html").body(r#"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion Staff - DCOP (413)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f9fafb;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
        }
        .logo {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #3b82f6, #1d4ed8);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 20px;
        }
        .login-card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            padding: 48px 40px;
            max-width: 480px;
            margin: 0 auto;
        }
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.2s ease;
            background-color: white;
        }
        .form-input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6, #1d4ed8);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 14px 24px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.2s ease;
            cursor: pointer;
            width: 100%;
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #2563eb, #1e40af);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }
        .btn-primary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .error-message {
            background-color: #fef2f2;
            border: 1px solid #fecaca;
            color: #dc2626;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }
        .error-message.show {
            display: block;
        }
    </style>
</head>
<body class="min-h-screen flex flex-col">
    <!-- Header -->
    <header class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-6 py-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <div class="logo">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <span class="text-xl font-bold text-gray-900">DCOP</span>
                </div>
                <a href="/" class="text-gray-600 hover:text-gray-900 flex items-center space-x-2">
                    <i class="fas fa-arrow-left"></i>
                    <span>Retour</span>
                </a>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="flex-1 flex items-center justify-center py-16 px-6">
        <div class="login-card">
            <div class="text-center mb-8">
                <div class="w-20 h-20 mx-auto mb-6 bg-gradient-to-br from-blue-100 to-blue-200 rounded-full flex items-center justify-center">
                    <i class="fas fa-key text-3xl text-blue-600"></i>
                </div>
                <h1 class="text-3xl font-bold text-gray-900 mb-2">Connexion Staff</h1>
                <p class="text-gray-600">Accès sécurisé au portail DCOP</p>
            </div>

            <!-- Error Message -->
            <div class="error-message" id="error-message">
                <i class="fas fa-exclamation-circle mr-2"></i>
                <span id="error-text"></span>
            </div>

            <!-- Login Form -->
            <form id="loginForm" class="space-y-6">
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700 mb-2">
                        Nom d'utilisateur
                    </label>
                    <input 
                        type="text" 
                        id="username" 
                        name="username" 
                        required 
                        class="form-input"
                        placeholder="Votre nom d'utilisateur"
                        autocomplete="username"
                    >
                </div>

                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700 mb-2">
                        Mot de passe
                    </label>
                    <input 
                        type="password" 
                        id="password" 
                        name="password" 
                        required 
                        class="form-input"
                        placeholder="••••••••••••"
                    >
                </div>

                <button type="submit" class="btn-primary" id="login-btn">
                    <span id="login-text">Se connecter</span>
                </button>
            </form>

            <!-- Security Notice -->
            <div class="mt-8 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                <div class="flex items-start space-x-3">
                    <i class="fas fa-shield-alt text-yellow-600 mt-1"></i>
                    <div>
                        <p class="font-medium text-yellow-800 text-sm">Zone sécurisée</p>
                        <p class="text-yellow-700 text-xs mt-1">Accès réservé au personnel autorisé. Toutes les tentatives sont auditées.</p>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error-message');
            const errorText = document.getElementById('error-text');
            const button = document.getElementById('login-btn');
            const loginText = document.getElementById('login-text');
            
            if (!username || !password) {
                showError('Veuillez remplir tous les champs');
                return;
            }
            
            // Animation du bouton
            button.disabled = true;
            loginText.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Connexion...';
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: username,
                        password: password
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    localStorage.setItem('jwt_token', data.access_token);
                    
                    loginText.innerHTML = '<i class="fas fa-check mr-2"></i>Connexion réussie !';
                    button.style.background = 'linear-gradient(135deg, #10b981, #059669)';
                    
                    setTimeout(() => {
                        window.location.href = '/secure/dashboard';
                    }, 1000);
                } else {
                    const errorData = await response.json();
                    showError(errorData.message || 'Identifiants incorrects');
                    resetButton();
                }
            } catch (error) {
                showError('Erreur de communication avec le serveur');
                resetButton();
            }
        });
        
        function showError(message) {
            const errorDiv = document.getElementById('error-message');
            const errorText = document.getElementById('error-text');
            errorText.textContent = message;
            errorDiv.classList.add('show');
            
            setTimeout(() => {
                errorDiv.classList.remove('show');
            }, 5000);
        }
        
        function resetButton() {
            const button = document.getElementById('login-btn');
            const loginText = document.getElementById('login-text');
            button.disabled = false;
            button.style.background = 'linear-gradient(135deg, #3b82f6, #1d4ed8)';
            loginText.innerHTML = 'Se connecter';
        }
    </script>
</body>
</html>
        "#)
    }

    /// Page de formulaire d'enregistrement de visiteur - Style VisioFlow
    pub async fn visitor_registration_form() -> HttpResponse {
        HttpResponse::Ok().content_type("text/html").body(r#"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enregistrement Visiteur - DCOP (413)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f9fafb;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
        }
        .logo {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #3b82f6, #1d4ed8);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 20px;
        }
        .form-card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            padding: 48px 40px;
            max-width: 800px;
            margin: 0 auto;
        }
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.2s ease;
            background-color: white;
        }
        .form-input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6, #1d4ed8);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 14px 24px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #2563eb, #1e40af);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }
        .success-message {
            background-color: #f0fdf4;
            border: 1px solid #bbf7d0;
            color: #166534;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }
        .success-message.show {
            display: block;
        }
        .error-message {
            background-color: #fef2f2;
            border: 1px solid #fecaca;
            color: #dc2626;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }
        .error-message.show {
            display: block;
        }
    </style>
</head>
<body class="min-h-screen flex flex-col">
    <!-- Header -->
    <header class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-6 py-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <div class="logo">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <span class="text-xl font-bold text-gray-900">DCOP</span>
                </div>
                <a href="/" class="text-gray-600 hover:text-gray-900 flex items-center space-x-2">
                    <i class="fas fa-arrow-left"></i>
                    <span>Retour</span>
                </a>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="flex-1 py-16 px-6">
        <div class="form-card">
            <div class="text-center mb-8">
                <div class="w-20 h-20 mx-auto mb-6 bg-gradient-to-br from-green-100 to-green-200 rounded-full flex items-center justify-center">
                    <i class="fas fa-user-plus text-3xl text-green-600"></i>
                </div>
                <h1 class="text-3xl font-bold text-gray-900 mb-2">Enregistrement de visite</h1>
                <p class="text-gray-600">Veuillez remplir le formulaire ci-dessous pour votre visite</p>
            </div>

            <!-- Success Message -->
            <div class="success-message" id="success-message">
                <i class="fas fa-check-circle mr-2"></i>
                <span>Votre demande de visite a été enregistrée avec succès. Vous recevrez une confirmation prochainement.</span>
            </div>

            <!-- Error Message -->
            <div class="error-message" id="error-message">
                <i class="fas fa-exclamation-circle mr-2"></i>
                <span id="error-text"></span>
            </div>

            <!-- Registration Form -->
            <form id="registrationForm" class="space-y-6">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <label for="first_name" class="block text-sm font-medium text-gray-700 mb-2">
                            Prénom *
                        </label>
                        <input 
                            type="text" 
                            id="first_name" 
                            name="first_name" 
                            required 
                            class="form-input"
                            placeholder="Jean"
                        >
                    </div>

                    <div>
                        <label for="last_name" class="block text-sm font-medium text-gray-700 mb-2">
                            Nom de famille *
                        </label>
                        <input 
                            type="text" 
                            id="last_name" 
                            name="last_name" 
                            required 
                            class="form-input"
                            placeholder="Dupont"
                        >
                    </div>
                </div>

                <div>
                    <label for="email" class="block text-sm font-medium text-gray-700 mb-2">
                        Adresse e-mail *
                    </label>
                    <input 
                        type="email" 
                        id="email" 
                        name="email" 
                        required 
                        class="form-input"
                        placeholder="jean.dupont@example.com"
                    >
                </div>

                <div>
                    <label for="phone" class="block text-sm font-medium text-gray-700 mb-2">
                        Téléphone
                    </label>
                    <input 
                        type="tel" 
                        id="phone" 
                        name="phone" 
                        class="form-input"
                        placeholder="+33 1 23 45 67 89"
                    >
                </div>

                <div>
                    <label for="company" class="block text-sm font-medium text-gray-700 mb-2">
                        Entreprise/Organisation
                    </label>
                    <input 
                        type="text" 
                        id="company" 
                        name="company" 
                        class="form-input"
                        placeholder="Nom de votre organisation"
                    >
                </div>

                <div>
                    <label for="visit_purpose" class="block text-sm font-medium text-gray-700 mb-2">
                        Objet de la visite *
                    </label>
                    <textarea 
                        id="visit_purpose" 
                        name="visit_purpose" 
                        required 
                        rows="3"
                        class="form-input"
                        placeholder="Décrivez brièvement l'objet de votre visite..."
                    ></textarea>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <label for="visit_date" class="block text-sm font-medium text-gray-700 mb-2">
                            Date de visite souhaitée *
                        </label>
                        <input 
                            type="date" 
                            id="visit_date" 
                            name="visit_date" 
                            required 
                            class="form-input"
                        >
                    </div>

                    <div>
                        <label for="visit_time" class="block text-sm font-medium text-gray-700 mb-2">
                            Heure de visite souhaitée
                        </label>
                        <input 
                            type="time" 
                            id="visit_time" 
                            name="visit_time" 
                            class="form-input"
                        >
                    </div>
                </div>

                <div>
                    <label for="host_name" class="block text-sm font-medium text-gray-700 mb-2">
                        Personne à rencontrer
                    </label>
                    <input 
                        type="text" 
                        id="host_name" 
                        name="host_name" 
                        class="form-input"
                        placeholder="Nom de la personne à rencontrer"
                    >
                </div>

                <button type="submit" class="btn-primary w-full" id="submit-btn">
                    <span id="submit-text">Enregistrer ma visite</span>
                </button>

                <p class="text-xs text-gray-500 text-center">
                    * Champs obligatoires. Vos informations seront traitées de manière confidentielle.
                </p>
            </form>
        </div>
    </main>

    <script>
        // Set minimum date to today
        document.getElementById('visit_date').min = new Date().toISOString().split('T')[0];

        document.getElementById('registrationForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const data = Object.fromEntries(formData);
            
            const button = document.getElementById('submit-btn');
            const submitText = document.getElementById('submit-text');
            const errorDiv = document.getElementById('error-message');
            const successDiv = document.getElementById('success-message');
            
            // Hide previous messages
            errorDiv.classList.remove('show');
            successDiv.classList.remove('show');
            
            // Validate required fields
            if (!data.first_name || !data.last_name || !data.email || !data.visit_purpose || !data.visit_date) {
                showError('Veuillez remplir tous les champs obligatoires');
                return;
            }
            
            // Animation du bouton
            button.disabled = true;
            submitText.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Enregistrement...';
            
            try {
                const response = await fetch('/api/visitors/public', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });
                
                if (response.ok) {
                    successDiv.classList.add('show');
                    this.reset();
                    submitText.innerHTML = '<i class="fas fa-check mr-2"></i>Enregistré !';
                    button.style.background = 'linear-gradient(135deg, #10b981, #059669)';
                    
                    setTimeout(() => {
                        resetButton();
                    }, 3000);
                } else {
                    const errorData = await response.json();
                    showError(errorData.message || 'Erreur lors de l\'enregistrement');
                    resetButton();
                }
            } catch (error) {
                showError('Erreur de communication avec le serveur');
                resetButton();
            }
        });
        
        function showError(message) {
            const errorDiv = document.getElementById('error-message');
            const errorText = document.getElementById('error-text');
            errorText.textContent = message;
            errorDiv.classList.add('show');
        }
        
        function resetButton() {
            const button = document.getElementById('submit-btn');
            const submitText = document.getElementById('submit-text');
            button.disabled = false;
            button.style.background = 'linear-gradient(135deg, #3b82f6, #1d4ed8)';
            submitText.innerHTML = 'Enregistrer ma visite';
        }
    </script>
</body>
</html>
        "#)
    }

    /// Dashboard de statistiques publiques
    pub async fn dashboard() -> HttpResponse {
        // Pour l'instant, redirigeons vers la page d'accueil
        // La fonctionnalité complète est dans le dashboard authentifié
        HttpResponse::Found()
            .append_header(("Location", "/login"))
            .finish()
    }

    /// Endpoint de santé publique
    pub async fn health_check() -> Json<Value> {
        Json(json!({
            "status": "healthy",
            "service": "DCOP (413) - Portail des Visites",
            "version": env!("CARGO_PKG_VERSION"),
            "timestamp": chrono::Utc::now()
        }))
    }

    /// Informations sur l'API
    pub async fn api_info() -> HttpResponse {
        HttpResponse::Ok().json(serde_json::json!({
            "service": "DCOP (413) - Portail des Visites",
            "version": "1.0",
            "status": "active",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }

    /// Test de diagnostic pour /api/auth scope
    pub async fn auth_test() -> HttpResponse {
        HttpResponse::Ok().json(serde_json::json!({
            "test": "auth_scope_working",
            "message": "Le scope /api/auth fonctionne correctement",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }

    /// Endpoint pour l'enregistrement public de visiteurs
    pub async fn register_visitor_public(
        visitor_service: Data<VisitorService>,
        req: HttpRequest,
        Json(request): Json<CreateVisitorRequest>,
    ) -> Result<HttpResponse> {
        // Valider la requête
        request.validate().map_err(|e| AppError::Validation(e.to_string()))?;

        let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_string());
        let user_agent = extract_user_agent(&req);

        // Créer le visiteur sans utilisateur authentifié (enregistrement public)
        let visitor = visitor_service
            .create_visitor(request, None, ip_address, user_agent)
            .await?;

        Ok(HttpResponse::Ok().json(json!({
            "success": true,
            "data": visitor,
            "message": "Visiteur enregistré avec succès. Veuillez attendre la validation."
        })))
    }

    /// Handler pour le dashboard sécurisé avec authentification par cookie/localStorage
    pub async fn secure_dashboard(_req: HttpRequest) -> HttpResponse {
        // Pour l'instant, on sert la page du dashboard sans vérification d'auth
        // L'authentification sera gérée côté client via JavaScript et localStorage
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(include_str!("../../static/templates/dashboard_main.html"))
    }
}
