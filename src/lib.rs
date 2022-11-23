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

#[derive(Clone, Debug)]
pub struct CsrfSynchronizerTokenLayer {
    pub regenerate_token: RegenerateToken,
    pub request_header: &'static str,
    pub response_header: &'static str,
    pub session_key: &'static str,
}

impl Default for CsrfSynchronizerTokenLayer {
    fn default() -> Self {
        Self {
            regenerate_token: Default::default(),
            request_header: "X-CSRF-TOKEN",
            response_header: "X-CSRF-TOKEN",
            session_key: "csrf_token",
        }
    }
}

impl CsrfSynchronizerTokenLayer {
    pub fn regenerate(mut self, regenerate_token: RegenerateToken) -> Self {
        self.regenerate_token = regenerate_token;

        self
    }
    pub fn request_header(mut self, request_header: &'static str) -> Self {
        self.request_header = request_header;

        self
    }
    pub fn response_header(mut self, response_header: &'static str) -> Self {
        self.response_header = response_header;

        self
    }
    pub fn session_key(mut self, session_key: &'static str) -> Self {
        self.session_key = session_key;

        self
    }

    fn regenerate_token(
        &self,
        session_write: &mut RwLockWriteGuard<Session>,
    ) -> Result<String, Error> {
        let mut buf = [0; 32];
        rand::thread_rng().try_fill_bytes(&mut buf)?;
        let token = base64::encode(buf);
        session_write.insert(self.session_key, &token)?;

        Ok(token)
    }

    fn response_with_token(&self, mut response: Response, server_token: &str) -> Response {
        response.headers_mut().insert(
            self.response_header,
            match HeaderValue::from_str(server_token).map_err(Error::from) {
                Ok(token_header) => token_header,
                Err(error) => return error.into_response(),
            },
        );
        response
    }
}

impl<S> Layer<S> for CsrfSynchronizerTokenLayer {
    type Service = CsrfSynchronizerTokenMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfSynchronizerTokenMiddleware::new(inner, self.clone())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum RegenerateToken {
    #[default]
    PerSession,
    PerUse,
    PerRequest,
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("Random number generator error")]
    Rng(#[from] rand::Error),

    #[error("Serde JSON error")]
    Serde(#[from] async_session::serde_json::Error),

    #[error("Session extension missing. Is `axum_sessions::SessionLayer` installed and layered around the CsrfSynchronizerTokenLayer?")]
    SessionLayerMissing,

    #[error("Incoming CSRF token header was not valid ASCII")]
    InvalidClientTokenHeader(#[from] http::header::ToStrError),

    #[error("Invalid CSRF token when preparing response header")]
    InvalidServerTokenHeader(#[from] http::header::InvalidHeaderValue),
}

impl IntoResponse for Error {
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
/// Optionally regenerates the token from the session after successful verification,
/// to ensure a new token is used for each writing (`POST`, `PUT`, `DELETE`) request.
/// Enable with [`RegenerateToken::PerUse`].
///
/// For maximum security, but severely reduced ergonomics, optionally regenerates the
/// token from the session after each request, to keep the token validity as short as
/// possible. Enable with [`RegenerateToken::PerRequest`].
#[derive(Debug, Clone)]
pub struct CsrfSynchronizerTokenMiddleware<S> {
    inner: S,
    layer: CsrfSynchronizerTokenLayer,
}

impl<S> CsrfSynchronizerTokenMiddleware<S> {
    pub fn new(inner: S, layer: CsrfSynchronizerTokenLayer) -> Self {
        CsrfSynchronizerTokenMiddleware { inner, layer }
    }
}

impl<S, B: Send + 'static> tower::Service<Request<B>> for CsrfSynchronizerTokenMiddleware<S>
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
        let layer = self.layer.clone();
        Box::pin(async move {
            let session_handle = match req
                .extensions()
                .get::<SessionHandle>()
                .ok_or(Error::SessionLayerMissing)
            {
                Ok(session_handle) => session_handle,
                Err(error) => return Ok(error.into_response()),
            };

            // Extract the CSRF server side token from the session; create a new one if none has been set yet.
            // If the regeneration option is set to "per request", then regenerate the token even if present in the session.
            let mut session_write = session_handle.write().await;
            let mut server_token = match session_write.get::<String>(layer.session_key) {
                Some(token) => token,
                None => match layer.regenerate_token(&mut session_write) {
                    Ok(token) => token,
                    Err(error) => return Ok(error.into_response()),
                },
            };

            if !req.method().is_safe() {
                // Verify incoming CSRF token for unsafe request methods.
                let client_token = {
                    match req.headers().get(layer.request_header) {
                        Some(token) => token,
                        None => {
                            tracing::warn!("{} header missing!", layer.request_header);
                            return Ok(layer.response_with_token(
                                StatusCode::FORBIDDEN.into_response(),
                                &server_token,
                            ));
                        }
                    }
                };

                let client_token = match client_token.to_str().map_err(Error::from) {
                    Ok(token) => token,
                    Err(error) => {
                        return Ok(layer.response_with_token(error.into_response(), &server_token))
                    }
                };
                if client_token != server_token {
                    tracing::warn!("{} header mismatch!", layer.request_header);
                    return Ok(layer.response_with_token(
                        (StatusCode::FORBIDDEN).into_response(),
                        &server_token,
                    ));
                }
            }

            // Create new token if configured to regenerate per each request,
            // or if configured to regenerate per use and just used.
            if layer.regenerate_token == RegenerateToken::PerRequest
                || (!req.method().is_safe() && layer.regenerate_token == RegenerateToken::PerUse)
            {
                server_token = match layer.regenerate_token(&mut session_write) {
                    Ok(token) => token,
                    Err(error) => {
                        return Ok(layer.response_with_token(error.into_response(), &server_token))
                    }
                };
            }

            drop(session_write);

            let response = inner.call(req).await.into_response();

            // Add X-CSRF-TOKEN response header.
            Ok(layer.response_with_token(response, &server_token))
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
    use axum_sessions::{async_session::MemoryStore, extractors::ReadableSession, SessionLayer};
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

    fn app<B: HttpBody + Send + 'static>(csrf_layer: CsrfSynchronizerTokenLayer) -> Router<B> {
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

        let response = app(CsrfSynchronizerTokenLayer::default())
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_eq!(base64::decode(client_token).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn post_without_token_fails() {
        let request = Request::builder()
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let response = app(CsrfSynchronizerTokenLayer::default())
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Assert: Response must contain token even on request token failure.
        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_eq!(base64::decode(client_token).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn session_token_remains_valid() {
        let mut app =
            app(CsrfSynchronizerTokenLayer::default().regenerate(RegenerateToken::PerSession));

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

        let initial_client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_eq!(base64::decode(initial_client_token).unwrap().len(), 32);

        // Use CSRF token for POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header("X-CSRF-TOKEN", initial_client_token)
                    .header(COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Assert token has not been changed after POST request
        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_eq!(client_token, initial_client_token);

        // Attempt token re-use for a second POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header("X-CSRF-TOKEN", initial_client_token)
                    .header(COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Assert token has not been changed after POST request
        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_eq!(client_token, initial_client_token);
    }

    #[tokio::test]
    async fn single_use_token_is_regenerated() {
        let mut app =
            app(CsrfSynchronizerTokenLayer::default().regenerate(RegenerateToken::PerUse));

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

        let initial_client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_eq!(base64::decode(initial_client_token).unwrap().len(), 32);

        // Use CSRF token for POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header("X-CSRF-TOKEN", initial_client_token)
                    .header(COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Assert token has been regenerated after POST request
        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_ne!(client_token, initial_client_token);

        // Attempt token re-use for a second POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header("X-CSRF-TOKEN", initial_client_token)
                    .header(COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Assert token has been regenerated after POST request
        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_ne!(client_token, initial_client_token);
    }

    #[tokio::test]
    async fn single_request_token_is_regenerated() {
        let mut app =
            app(CsrfSynchronizerTokenLayer::default().regenerate(RegenerateToken::PerRequest));

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

        let initial_client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
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
        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_ne!(client_token, initial_client_token);

        // Attempt using single-request token for POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header("X-CSRF-TOKEN", client_token)
                    .header(COOKIE, session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Assert token has been regenerated after POST request
        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_ne!(client_token, initial_client_token);
    }

    #[tokio::test]
    async fn accepts_custom_request_header() {
        let mut app =
            app(CsrfSynchronizerTokenLayer::default()
                .request_header("X-Custom-Token-Request-Header"));

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

        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_eq!(base64::decode(client_token).unwrap().len(), 32);

        // Use CSRF token for POST request
        let response = app
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .method(Method::POST)
                    .header("X-Custom-Token-Request-Header", client_token)
                    .header(COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sends_custom_response_header() {
        // Get CSRF token
        let response =
            app(CsrfSynchronizerTokenLayer::default()
                .response_header("X-Custom-Token-Response-Header"))
            .oneshot(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let client_token = response
            .headers()
            .get("X-Custom-Token-Response-Header")
            .unwrap();
        assert_eq!(base64::decode(client_token).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn uses_custom_session_key() {
        // Custom handler asserting the layer's configured session key is set,
        // and its value looks like a CSRF token.
        async fn extract_session(session: ReadableSession) -> StatusCode {
            let session_csrf_token: String = session.get("custom_session_key").unwrap();

            assert_eq!(base64::decode(session_csrf_token).unwrap().len(), 32);
            StatusCode::OK
        }

        let app = Router::new()
            .route("/", get(extract_session))
            .layer(CsrfSynchronizerTokenLayer::default().session_key("custom_session_key"))
            .layer(session_layer());

        let response = app
            .oneshot(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
