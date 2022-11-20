use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use async_session::Session;
use axum::response::{IntoResponse, Response};
use axum_sessions::SessionHandle;
use http::{HeaderValue, Request, StatusCode};
use rand::RngCore;
use tokio::sync::RwLockWriteGuard;
use tower::Layer;

pub static SESSION_KEY: &str = "csrf_token";
pub static CSRF_HEADER: &str = "X-CSRF-TOKEN";

#[derive(Default)]
pub struct CsrfLayer {
    regenerate_token: RegenerateToken,
}

impl CsrfLayer {
    pub fn regenerate(mut self, regenerate_token: RegenerateToken) -> Self {
        self.regenerate_token = regenerate_token;

        self
    }
}

impl<S> Layer<S> for CsrfLayer {
    type Service = CsrfProtect<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfProtect::new(inner, self.regenerate_token.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum RegenerateToken {
    PerSession,
    PerUse,
    PerRequest,
}

impl Default for RegenerateToken {
    fn default() -> Self {
        RegenerateToken::PerSession
    }
}

#[derive(thiserror::Error, Debug)]
enum CsrfError {
    #[error("Random number generator error")]
    Rng(#[from] rand::Error),

    #[error("Serde JSON error")]
    Serde(#[from] async_session::serde_json::Error),

    #[error("Session extension missing. Is `axum_sessions::SessionLayer` installed and layered around the CsrfLayer?")]
    SessionLayerMissing,

    #[error("Incoming CSRF token header was not valid ASCII")]
    InvalidClientTokenHeader(#[from] http::header::ToStrError),

    #[error("Invalid CSRF token when preparing response header")]
    InvalidServerTokenHeader(#[from] http::header::InvalidHeaderValue),
}

impl IntoResponse for CsrfError {
    fn into_response(self) -> Response {
        tracing::error!(?self);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
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
pub struct CsrfProtect<S> {
    inner: S,
    regenerate_token: RegenerateToken,
}

impl<S> CsrfProtect<S> {
    pub fn new(inner: S, regenerate_token: RegenerateToken) -> Self {
        CsrfProtect {
            inner,
            regenerate_token,
        }
    }

    fn regenerate_token(
        session_write: &mut RwLockWriteGuard<Session>,
    ) -> Result<String, CsrfError> {
        let mut buf = [0; 32];
        rand::thread_rng().try_fill_bytes(&mut buf)?;
        let token = base64::encode(buf);
        session_write.insert(SESSION_KEY, &token)?;

        Ok(token)
    }

    fn response_with_token(mut response: Response, server_token: &str) -> Response {
        response.headers_mut().insert(
            CSRF_HEADER,
            match HeaderValue::from_str(server_token).map_err(CsrfError::from) {
                Ok(token_header) => token_header,
                Err(error) => return error.into_response(),
            },
        );
        response
    }
}

impl<S, B: Send + 'static> tower::Service<Request<B>> for CsrfProtect<S>
where
    S: tower::Service<Request<B>, Response = Response, Error = Infallible> + Send + Clone + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let regenerate = self.regenerate_token.clone();
        Box::pin(async move {
            let session_handle = match req
                .extensions()
                .get::<SessionHandle>()
                .ok_or(CsrfError::SessionLayerMissing)
            {
                Ok(session_handle) => session_handle,
                Err(error) => return Ok(error.into_response()),
            };

            // Extract the CSRF server side token from the session; create a new one if none has been set yet.
            // If the regeneration option is set to "per request", then regenerate the token even if present in the session.
            let mut session_write = session_handle.write().await;
            let mut server_token = match session_write.get::<String>(SESSION_KEY) {
                Some(token) => token,
                None => match Self::regenerate_token(&mut session_write) {
                    Ok(token) => token,
                    Err(error) => return Ok(error.into_response()),
                },
            };

            if !req.method().is_safe() {
                // Verify incoming CSRF token for unsafe request methods.
                let client_token = {
                    match req.headers().get(CSRF_HEADER) {
                        Some(token) => token,
                        None => {
                            tracing::warn!("{} header missing!", CSRF_HEADER);
                            return Ok(Self::response_with_token(
                                StatusCode::FORBIDDEN.into_response(),
                                &server_token,
                            ));
                        }
                    }
                };

                let client_token = match client_token.to_str().map_err(CsrfError::from) {
                    Ok(token) => token,
                    Err(error) => {
                        return Ok(Self::response_with_token(
                            error.into_response(),
                            &server_token,
                        ))
                    }
                };
                if client_token != server_token {
                    tracing::warn!("{} header mismatch!", CSRF_HEADER);
                    return Ok(Self::response_with_token(
                        (StatusCode::FORBIDDEN).into_response(),
                        &server_token,
                    ));
                }
            }

            // Create new token if configured to regenerate per each request,
            // or if configured to regenerate per use and just used.
            if regenerate == RegenerateToken::PerRequest
                || (!req.method().is_safe() && regenerate == RegenerateToken::PerUse)
            {
                server_token = match Self::regenerate_token(&mut session_write) {
                    Ok(token) => token,
                    Err(error) => {
                        return Ok(Self::response_with_token(
                            error.into_response(),
                            &server_token,
                        ))
                    }
                };
            }

            drop(session_write);

            let response = inner.call(req).await.into_response();

            // Add X-CSRF-TOKEN response header.
            Ok(Self::response_with_token(response, &server_token))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum::{
        body::{Body, HttpBody},
        response::{IntoResponse, Response},
        routing::get,
        Router,
    };
    use axum_sessions::{async_session::MemoryStore, SessionLayer};
    use http::{
        header::{COOKIE, SET_COOKIE},
        Method, Request, StatusCode,
    };
    use tower::{Service, ServiceExt};

    use super::*;

    async fn handler() -> Result<Response, Infallible> {
        Ok((
            StatusCode::OK,
            "The default test success response has a body",
        )
            .into_response())
    }

    fn session_layer() -> SessionLayer<MemoryStore> {
        let mut secret = [0; 64];
        rand::thread_rng().try_fill_bytes(&mut secret).unwrap();
        SessionLayer::new(MemoryStore::new(), &secret)
    }

    fn app<B: HttpBody + Send + 'static>(csrf_layer: CsrfLayer) -> Router<B> {
        Router::new()
            .route("/", get(handler).post(handler))
            .layer(csrf_layer)
            .layer(session_layer())
    }

    #[tokio::test]
    async fn get_without_token_succeeds() {
        let request = Request::builder()
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let response = app(CsrfLayer::default()).oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_eq!(base64::decode(client_token).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn post_without_token_fails() {
        let request = Request::builder()
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let response = app(CsrfLayer::default()).oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Assert: Response must contain token even on request token failure.
        let client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_eq!(base64::decode(client_token).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn session_token_remains_valid() {
        let mut app = app(CsrfLayer::default().regenerate(RegenerateToken::PerSession));

        // Get CSRF token
        let response = app
            .ready()
            .await
            .unwrap()
            .call(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Tokens are bound to the session - must re-use on each consecutive request.
        let session_cookie = response.headers().get(SET_COOKIE).unwrap().clone();

        let initial_client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_eq!(base64::decode(initial_client_token).unwrap().len(), 32);

        // Use CSRF token for POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header(CSRF_HEADER, initial_client_token)
                    .header(COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Assert token has not been changed after POST request
        let client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_eq!(client_token, initial_client_token);

        // Attempt token re-use for a second POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header(CSRF_HEADER, initial_client_token)
                    .header(COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Assert token has not been changed after POST request
        let client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_eq!(client_token, initial_client_token);
    }

    #[tokio::test]
    async fn single_use_token_is_regenerated() {
        let mut app = app(CsrfLayer::default().regenerate(RegenerateToken::PerUse));

        // Get single-use CSRF token
        let response = app
            .ready()
            .await
            .unwrap()
            .call(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Tokens are bound to the session - must re-use on each consecutive request.
        let session_cookie = response.headers().get(SET_COOKIE).unwrap().clone();

        let initial_client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_eq!(base64::decode(initial_client_token).unwrap().len(), 32);

        // Use CSRF token for POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header(CSRF_HEADER, initial_client_token)
                    .header(COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Assert token has been regenerated after POST request
        let client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_ne!(client_token, initial_client_token);

        // Attempt token re-use for a second POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header(CSRF_HEADER, initial_client_token)
                    .header(COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Assert token has been regenerated after POST request
        let client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_ne!(client_token, initial_client_token);
    }

    #[tokio::test]
    async fn single_request_token_is_regenerated() {
        let mut app = app(CsrfLayer::default().regenerate(RegenerateToken::PerRequest));

        // Get single-use CSRF token
        let response = app
            .ready()
            .await
            .unwrap()
            .call(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Tokens are bound to the session - must re-use on each consecutive request.
        let session_cookie = response.headers().get(SET_COOKIE).unwrap().clone();

        let initial_client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_eq!(base64::decode(initial_client_token).unwrap().len(), 32);

        // Perform another GET request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::GET)
                    .header(COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Assert token has been regenerated after GET request
        let client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_ne!(client_token, initial_client_token);

        // Attempt using single-request token for POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header(CSRF_HEADER, client_token)
                    .header(COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Assert token has been regenerated after POST request
        let client_token = response.headers().get(CSRF_HEADER).unwrap();
        assert_ne!(client_token, initial_client_token);
    }
}
