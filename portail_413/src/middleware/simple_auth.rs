use actix_web::{
    dev::{ServiceRequest, ServiceResponse, Transform, Service, forward_ready},
    Error, HttpResponse,
    body::BoxBody,
};
use std::future::{Ready, ready};
use futures_util::future::LocalBoxFuture;

/// Middleware d'authentification simplifié pour tests
pub struct SimpleAuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SimpleAuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SimpleAuthService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SimpleAuthService { service }))
    }
}

pub struct SimpleAuthService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SimpleAuthService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Pour les tests, on vérifie simplement la présence de l'en-tête Authorization
        let auth_header = req.headers().get("Authorization");
        
        if auth_header.is_none() {
            // Retourner directement une erreur 401 simple
            return Box::pin(async move {
                let response = HttpResponse::Unauthorized()
                    .json(serde_json::json!({
                        "error": "Authentication required"
                    }));
                let (req, _) = req.into_parts();
                Ok(ServiceResponse::new(req, response))
            });
        }

        // Sinon, continuer normalement
        let fut = self.service.call(req);
        Box::pin(async move { fut.await })
    }
}
