// Handler de test temporaire pour diagnostiquer le problème d'AuthHandler
use actix_web::HttpResponse;
use serde_json::json;
use crate::errors::Result;

pub struct TestHandler;

impl TestHandler {
    pub async fn simple_test() -> Result<HttpResponse> {
        Ok(HttpResponse::Ok().json(json!({
            "message": "Test handler works!",
            "status": "success"
        })))
    }
    
    pub async fn test_login() -> Result<HttpResponse> {
        Ok(HttpResponse::Ok().json(json!({
            "message": "Test login endpoint works!",
            "status": "success"
        })))
    }
}
