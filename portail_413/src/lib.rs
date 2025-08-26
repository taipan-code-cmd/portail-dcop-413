// DCOP (413) - Portail des Visites
// Système sécurisé de gestion des visiteurs
// Architecture modulaire avec défense en profondeur

pub mod config;
pub mod database;
pub mod models;
pub mod services;
pub mod handlers;
pub mod security;
pub mod state;
pub mod errors;
pub mod middleware;
pub mod utils;

#[cfg(test)]
mod test_role_serialization;

pub use config::Config;
pub use errors::{AppError, Result};
pub use state::AppState;
