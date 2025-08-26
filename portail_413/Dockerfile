# DCOP (413) - Portail des Visites
# Dockerfile temporaire - Backend uniquement sur port 8443

# Stage 1: Build Backend - Image Alpine pour la compilation
FROM rust:1.83-alpine as builder

# Installer les dépendances système nécessaires (Alpine)
RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev \
    postgresql-dev \
    clang-dev \
    llvm-dev \
    build-base \
    && rm -rf /var/cache/apk/*

# Créer un utilisateur non-root pour la compilation
RUN addgroup -g 1001 builder && \
    adduser -D -s /bin/sh -u 1001 -G builder builder

# Définir le répertoire de travail
WORKDIR /app

# Changer la propriété du répertoire de travail
RUN chown -R builder:builder /app

# Changer vers l'utilisateur non-root
USER builder

# Copier les fichiers de configuration Cargo (INCLURE Cargo.lock pour versions fixes)
COPY --chown=builder:builder Cargo.toml ./
COPY --chown=builder:builder Cargo.lock ./
COPY --chown=builder:builder sqlx-data.json ./
# Copier le cache SQLx pour éviter les erreurs SQLX_OFFLINE
COPY --chown=builder:builder .sqlx ./.sqlx

# Créer un projet factice pour mettre en cache les dépendances
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN SQLX_OFFLINE=true cargo build --release && rm -rf src

# Copier le code source
COPY --chown=builder:builder src ./src
COPY --chown=builder:builder migrations ./migrations
COPY --chown=builder:builder static ./static

# Construire l'application avec optimisations de sécurité
ENV RUSTFLAGS="-C target-feature=+crt-static"
# Activer SQLX_OFFLINE pour utiliser le cache précompilé
    ENV SQLX_OFFLINE=true
    RUN rustup target add x86_64-unknown-linux-musl
    RUN cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Runtime - Image Alpine minimaliste
FROM alpine:3.19

# Installer uniquement les dépendances runtime essentielles (Alpine)
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    curl \
    wget \
    && rm -rf /var/cache/apk/*

# Créer un utilisateur non-root pour l'exécution avec sécurité renforcée
RUN addgroup -g 1001 dcop && \
    adduser -D -s /sbin/nologin -u 1001 -G dcop dcop

# Créer les répertoires nécessaires avec permissions strictes
RUN mkdir -p /app/logs /app/data /app/secrets && \
    chown -R dcop:dcop /app && \
    chmod 750 /app && \
    chmod 700 /app/secrets

# Copier l'exécutable statique depuis le stage de build
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/portail_413 /app/portail_413

# Copier les migrations avec permissions appropriées
COPY --from=builder --chown=dcop:dcop /app/migrations /app/migrations

# Copier les fichiers statiques optimisés depuis le stage de build
COPY --from=builder --chown=dcop:dcop /app/static /app/static

# Définir les permissions strictes et corriger l'accès static
RUN chmod 755 /app/portail_413 && \
    chmod -R 644 /app/migrations && \
    chmod -R 755 /app/static && \
    find /app/static -type f -exec chmod 644 {} \; && \
    chown -R dcop:dcop /app/static

# Passer à l'utilisateur non-root
USER dcop

# Définir le répertoire de travail
WORKDIR /app

# Exposer uniquement le port nécessaire
EXPOSE 8443

# Variables d'environnement sécurisées
ENV RUST_LOG=info
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8443

# Labels de sécurité et métadonnées
LABEL maintainer="DCOP Security Team" \
      version="1.0.0" \
      description="DCOP (413) - Portail des Visites Sécurisé" \
      security.scan="required" \
      security.non-root="true"

# Healthcheck pour monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8443/health || exit 1

# Commande de démarrage sécurisée
CMD ["./portail_413"]
