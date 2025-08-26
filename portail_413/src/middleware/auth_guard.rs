use actix_web::{
    dev::{ServiceRequest, ServiceResponse, Transform, Service, forward_ready},
    Error, HttpResponse, http::header,
};
use std::future::{Ready, ready};
use futures_util::future::LocalBoxFuture;

/// Middleware d'authentification pour Actix-web
/// Vérifie la présence de l'en-tête Authorization avant d'accéder aux routes protégées
pub struct AuthenticationMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthenticationMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthenticationService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticationService { service }))
    }
}

pub struct AuthenticationService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthenticationService<S>
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
        // Vérifier la présence de l'en-tête Authorization
        let auth_header = req.headers().get(header::AUTHORIZATION);
        
        if auth_header.is_none() {
            // Pas d'en-tête Authorization, retourner une erreur 401
            return Box::pin(async move {
                let response = HttpResponse::Unauthorized()
                    .json(serde_json::json!({
                        "error": "Authentication required",
                        "message": "Missing Authorization header"
                    }));

                let (req, _) = req.into_parts();
                Ok(ServiceResponse::new(req, response).map_into_boxed_body().map_into_right_body())
            });
        }

        // Continuer avec la requête si l'en-tête Authorization est présent
        let fut = self.service.call(req);
        Box::pin(async move { fut.await })
    }
}
