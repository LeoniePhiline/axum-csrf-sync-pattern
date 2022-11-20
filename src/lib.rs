use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use async_session::Session;
use axum::{
    response::{IntoResponse, Response},
    BoxError,
};
use axum_sessions::SessionHandle;
use http::{HeaderValue, Request, StatusCode};
use rand::RngCore;
use tokio::sync::RwLockWriteGuard;
use tower::Layer;

pub static SESSION_KEY: &str = "csrf_token";
pub static CSRF_HEADER: &str = "X-CSRF-TOKEN";

struct CsrfLayer {
    single_use: bool,
}

impl CsrfLayer {
    fn new() -> Self {
        Self { single_use: false }
    }

    fn single_use(mut self, single_use: bool) -> Self {
        self.single_use = single_use;

        self
    }
}

impl<S> Layer<S> for CsrfLayer {
    type Service = CsrfProtect<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfProtect::new(inner, self.single_use)
    }
}

/// Verify the CSRF token header on the incoming request.
/// This middleware receives a CSRF token as `X-CSRF-TOKEN` HTTP request header value
/// and compares it to the token stored in the session.
/// Upon response from the inner service, the session token is returned to the
/// client via the `X-CSRF-TOKEN` response header.
/// Make sure to expose this header in your CORS configuration if necessary!
///
/// Requires and uses `axum_sessions`.
///
/// TODO: Optionally removes the token from the session after successful verification,
/// to ensure a new token is used for each writing (`POST`, `PUT`, `DELETE`) request.
/// TODO: Needs a layer for configuration.
#[derive(Debug, Clone)]
struct CsrfProtect<S> {
    inner: S,
    single_use: bool,
}

impl<S> CsrfProtect<S> {
    pub fn new(inner: S, single_use: bool) -> Self {
        CsrfProtect { inner, single_use }
    }

    fn regenerate_token(session_write: &mut RwLockWriteGuard<Session>) -> Result<String, BoxError> {
        let mut buf = [0; 32];
        rand::thread_rng().try_fill_bytes(&mut buf)?;
        let token = base64::encode(buf);
        session_write.insert(SESSION_KEY, &token)?;

        Ok(token)
    }
}

impl<S, B: Send + 'static> tower::Service<Request<B>> for CsrfProtect<S>
where
    S: tower::Service<Request<B>, Response = Response> + Clone + 'static,
    S::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let single_use = self.single_use;
        Box::pin(async move {
            let session_handle = match req.extensions().get::<SessionHandle>() {
                Some(session_handle) => session_handle,
                None => {
                    tracing::error!("Session extension missing. Is `axum_sessions::SessionLayer` installed and layered around the CsrfLayer?");
                    return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
                }
            };

            // Extract the CSRF server side token from the session; create a new one if none has been set yet.
            let mut session_write = session_handle.write().await;
            let mut server_token = match session_write.get::<String>(SESSION_KEY) {
                None => Self::regenerate_token(&mut session_write)?,
                Some(token) => token,
            };

            if !req.method().is_safe() {
                // Verify incoming CSRF token for unsafe request methods.
                let client_token = {
                    match req.headers().get(CSRF_HEADER) {
                        Some(token) => token,
                        None => {
                            tracing::warn!("{} header missing!", CSRF_HEADER);
                            return Ok((StatusCode::FORBIDDEN).into_response());
                        }
                    }
                };

                if client_token.to_str()? != server_token {
                    tracing::warn!("{} header mismatch!", CSRF_HEADER);
                    return Ok((StatusCode::FORBIDDEN).into_response());
                }

                // Optionally, create new token, if `single_use` is enabled on the layer.
                if single_use {
                    server_token = Self::regenerate_token(&mut session_write)?;
                }
            }

            drop(session_write);
            let mut response = inner.call(req).await.map_err(Into::into)?.into_response();

            // Add X-CSRF-TOKEN response header.
            response
                .headers_mut()
                .insert(CSRF_HEADER, HeaderValue::from_str(&server_token)?);

            Ok(response)
        })
    }
}
