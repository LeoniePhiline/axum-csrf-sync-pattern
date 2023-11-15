//! # Axum Synchronizer Token Pattern CSRF prevention
//!
//! This crate provides a CSRF protection layer and middleware for use with the [axum](https://docs.rs/axum/) web framework.
//!
//! The middleware implements the [CSRF Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern)
//! for AJAX backends and API endpoints as described in the OWASP CSRF prevention cheat sheet.
//!
//! ## Scope
//!
//! This middleware implements token transfer via [custom request headers](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers).
//!
//! The middleware requires and is built upon [`tower_sessions`](https://docs.rs/tower-sessions/).
//!
//! The [Same Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) prevents the custom request header to be set by foreign scripts.
//!
//! ### In which contexts should I use this middleware?
//!
//! The goal of this middleware is to prevent cross-site request forgery attacks specifically in applications communicating with their backend by means of the JavaScript
//! [`fetch()` API](https://developer.mozilla.org/en-US/docs/Web/API/fetch) or classic [`XmlHttpRequest`](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest),
//! traditionally called "AJAX".
//!
//! The Synchronizer Token Pattern is especially useful in [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) contexts,
//! as the underlying session cookie is obligatorily secured and inaccessible by JavaScript, while the custom HTTP response header carrying the CSRF token can be exposed
//! using the CORS [`Access-Control-Expose-Headers`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers) HTTP response header.
//!
//! While the [Same Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) commonly prevents custom request headers to be set on cross-origin requests,
//! use of the use of the [Access-Control-Allow-Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers) CORS HTTP response header
//! can be used to specifically allow CORS requests to be equipped with a required custom HTTP request header.
//!
//! This approach ensures that requests forged by auto-submitted forms or other data-submitting scripts from foreign origins are unable to add the required header.
//!
//! ### When should I use other CSRF protection patterns or libraries?
//!
//! Use other available middleware libraries if you plan on submitting classical HTML forms without the use of JavaScript, and if you do not send the form data across origins.
//!
//! ## Security
//! ### Token randomness
//!
//! The CSRF tokens are generated using [`rand::ThreadRng`](https://rust-random.github.io/rand/rand/rngs/struct.ThreadRng.html) which is considered cryptographically secure (CSPRNG).
//! See ["Our RNGs"](https://rust-random.github.io/book/guide-rngs.html#cryptographically-secure-pseudo-random-number-generators-csprngs) for more.
//!
//! ### Underlying session security
//!
//! The security of the underlying session is paramount - the CSRF prevention methods applied can only be as secure as the session carrying the server-side token.
//!
//! - When creating your [SessionManagerLayer](https://docs.rs/tower-sessions/latest/tower_sessions/struct.SessionManagerLayer.html)
//! - Do not lower the secure defaults: Keep the session cookie's `secure` flag **on**.
//! - Use the strictest possible same-site policy.
//!
//! ### CORS security
//!
//! If you need to provide and secure cross-site requests:
//!
//! - Allow only your backend origin when configuring the [`CorsLayer`](https://docs.rs/tower-http/latest/tower_http/cors/struct.CorsLayer.html)
//! - Allow only the headers you need. (At least the CSRF request token header.)
//! - Only expose the headers you need. (At least the CSRF response token header.)
//!
//! ### No leaks of error details
//!
//! Errors are logged using [`tracing::error!`]. Error responses do not contain error details.
//!
//! Use [`tower_http::TraceLayer`](https://docs.rs/tower-http/latest/tower_http/trace/struct.TraceLayer.html) to capture and view traces.
//!
//! ## Safety
//!
//! This crate uses no `unsafe` code.
//!
//! The layer and middleware functionality is tested. View the the module source code to learn more.
//!
//! ## Usage
//!
//! See the [example projects](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/tree/main/examples/) for same-site and cross-site usage.
//!
//! ### Same-site usage
//!
//! **Note:** The crate repository contains example projects for same-site and cross-site usage!
//!
//! Configure your session and CSRF protection layer in your backend application:
//!
//! ```rust
//! use axum::{
//!     BoxError,
//!     body::Body,
//!     http::StatusCode,
//!     routing::{get, Router},
//!     error_handling::HandleErrorLayer,
//! };
//! use tower::ServiceBuilder;
//! use axum_csrf_sync_pattern::{CsrfLayer, RegenerateToken};
//! use tower_sessions::{MemoryStore, SessionManagerLayer};
//! 
//! async fn handler() -> StatusCode {
//!     StatusCode::OK
//! }
//!
//! let app = Router::new()
//!     .route("/", get(handler).post(handler))
//!     .layer(
//!         CsrfLayer::new()
//!
//!         // Optionally, configure the layer with the following options:
//!
//!         // Default: RegenerateToken::PerSession
//!         .regenerate(RegenerateToken::PerUse)
//!         // Default: "X-CSRF-TOKEN"
//!         .request_header("X-Custom-Request-Header")
//!         // Default: "X-CSRF-TOKEN"
//!         .response_header("X-Custom-Response-Header")
//!         // Default: "_csrf_token"
//!         .session_key("_custom_session_key")
//!     )
//!     .layer(ServiceBuilder::new()
//!         .layer(HandleErrorLayer::new(|_: BoxError| async {
//!             StatusCode::BAD_REQUEST
//!         }))
//!         .layer(SessionManagerLayer::new(MemoryStore::default()))
//!     );
//!
//! // Use hyper to run `app` as service and expose on a local port or socket.
//!
//! # use tower::util::ServiceExt;
//! # tokio_test::block_on(async {
//! #     app.oneshot(
//! #         axum::http::Request::builder().body(axum::body::Body::empty()).unwrap()
//! #     ).await.unwrap();
//! # })
//! ```
//!
//! Receive the token and send same-site requests, using your custom header:
//!
//! ```javascript
//! const test = async () => {
//!     // Receive CSRF token (Default response header name: 'X-CSRF-TOKEN')
//!     const token = (await fetch('/')).headers.get('X-Custom-Response-Header');
//!
//!     // Submit data using the token
//!     await fetch('/', {
//!         method: 'POST',
//!         headers: {
//!            'Content-Type': 'application/json',
//!            // Default request header name: 'X-CSRF-TOKEN'
//!            'X-Custom-Request-Header': token,
//!         },
//!         body: JSON.stringify({ /* ... */ }),
//!     });
//! };
//! ```
//!
//! ### CORS-enabled usage
//!
//! **Note:** The crate repository contains example projects for same-site and cross-site usage!
//!
//! Configure your CORS layer, session and CSRF protection layer in your backend application:
//!
//! ```rust
//! use axum::{
//!     BoxError,
//!     body::Body,
//!     http::{header, Method, StatusCode},
//!     routing::{get, Router},
//!     error_handling::HandleErrorLayer,
//! };
//! use tower::ServiceBuilder;
//! use axum_csrf_sync_pattern::{CsrfLayer, RegenerateToken};
//! use tower_sessions::{MemoryStore, SessionManagerLayer};
//! use tower_http::cors::{AllowOrigin, CorsLayer};
//! 
//! async fn handler() -> StatusCode {
//!     StatusCode::OK
//! }
//!
//! let app = Router::new()
//!     .route("/", get(handler).post(handler))
//!     .layer(
//!         // See example above for custom layer configuration.
//!         CsrfLayer::new()
//!     )
//!     .layer(ServiceBuilder::new()
//!         .layer(HandleErrorLayer::new(|_: BoxError| async {
//!             StatusCode::BAD_REQUEST
//!         }))
//!         .layer(SessionManagerLayer::new(MemoryStore::default()))
//!         .layer(
//!             CorsLayer::new()
//!                 .allow_origin(AllowOrigin::list(["https://www.example.com".parse().unwrap()]))
//!                 .allow_methods([Method::GET, Method::POST])
//!                 .allow_headers([header::CONTENT_TYPE, "X-CSRF-TOKEN".parse().unwrap()])
//!                 .allow_credentials(true)
//!                 .expose_headers(["X-CSRF-TOKEN".parse().unwrap()]),
//!         )
//!     );
//!     
//!
//! // Use hyper to run `app` as service and expose on a local port or socket.
//!
//! # use tower::util::ServiceExt;
//! # tokio_test::block_on(async {
//! #     app.oneshot(
//! #         axum::http::Request::builder().body(axum::body::Body::empty()).unwrap()
//! #     ).await.unwrap();
//! # })
//! ```
//!
//! Receive the token and send cross-site requests, using your custom header:
//!
//! ```javascript
//! const test = async () => {
//!     // Receive CSRF token
//!     const token = (await fetch('https://backend.example.com/', {
//!         credentials: 'include',
//!     })).headers.get('X-CSRF-TOKEN');
//!
//!     // Submit data using the token
//!     await fetch('https://backend.example.com/', {
//!         method: 'POST',
//!         headers: {
//!            'Content-Type': 'application/json',
//!            'X-CSRF-TOKEN': token,
//!         },
//!         credentials: 'include',
//!         body: JSON.stringify({ /* ... */ }),
//!     });
//! };
//! ```
//!
//! ## Contributing
//!
//! Pull requests are welcome!
//!

#![forbid(unsafe_code, future_incompatible)]
#![deny(
    missing_debug_implementations,
    nonstandard_style,
    missing_docs,
    unreachable_pub,
    missing_copy_implementations,
    unused_qualifications
)]

use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::http::{self, HeaderValue, Request, StatusCode};
use axum_core::response::{IntoResponse, Response};
use tower_sessions::Session;
use base64::prelude::*;
use rand::RngCore;
use tower::Layer;

/// Use `CsrfLayer::new()` to provide the middleware and configuration to axum's service stack.
///
/// Use the provided methods to configure details, such as when tokens are regenerated, what request and response
/// headers should be named, and under which key the token should be stored in the session.
#[derive(Clone, Copy, Debug)]
pub struct CsrfLayer {
    /// Configures when tokens are regenerated: Per session, per use or per request. See [`RegenerateToken`] for details.
    pub regenerate_token: RegenerateToken,

    /// Configures the request header name accepted by the middleware. Defaults to `"X-CSRF-TOKEN"`.
    /// This header is set on your JavaScript or WASM requests originating from the browser.
    pub request_header: &'static str,

    /// Configures the response header name sent by the middleware. Defaults to `"X-CSRF-TOKEN"`.
    /// This header is received by your JavaScript or WASM code and its name must be used to extract the token from the HTTP response.
    pub response_header: &'static str,

    /// Configures the key under which the middleware stores the server-side token in the session. Defaults to `"_csrf_token"`.
    pub session_key: &'static str,
}

impl Default for CsrfLayer {
    fn default() -> Self {
        Self {
            regenerate_token: Default::default(),
            request_header: "X-CSRF-TOKEN",
            response_header: "X-CSRF-TOKEN",
            session_key: "_csrf_token",
        }
    }
}

impl CsrfLayer {
    /// Create a new CSRF synchronizer token layer to inject into your middleware stack using
    /// [`axum::Router::layer()`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure when tokens are regenerated: Per session, per use or per request. See [`RegenerateToken`] for details.
    pub fn regenerate(mut self, regenerate_token: RegenerateToken) -> Self {
        self.regenerate_token = regenerate_token;

        self
    }

    /// Configure a custom request header name accepted by the middleware. Defaults to `"X-CSRF-TOKEN"`.
    ///
    /// This header is set on your JavaScript or WASM requests originating from the browser.
    pub fn request_header(mut self, request_header: &'static str) -> Self {
        self.request_header = request_header;

        self
    }

    /// Configure a custom response header name sent by the middleware. Defaults to `"X-CSRF-TOKEN"`.
    ///
    /// This header is received by your JavaScript or WASM code and its name must be used to extract the token from the HTTP response.
    pub fn response_header(mut self, response_header: &'static str) -> Self {
        self.response_header = response_header;

        self
    }

    /// Configure a custom key under which the middleware stores the server-side token in the session. Defaults to `"_csrf_token"`.
    pub fn session_key(mut self, session_key: &'static str) -> Self {
        self.session_key = session_key;

        self
    }

    fn regenerate_token(
        &self,
        session: &Session,
    ) -> Result<String, Error> {
        let mut buf = [0; 32];
        rand::thread_rng().try_fill_bytes(&mut buf)?;
        let token = BASE64_STANDARD.encode(buf);
        session.insert(self.session_key, &token)?;

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

impl<S> Layer<S> for CsrfLayer {
    type Service = CsrfMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfMiddleware::new(inner, *self)
    }
}

/// This enum is used with [`CsrfLayer::regenerate`] to determine
/// at which occurences the CSRF token should be regenerated.
///
/// You could understand these options as modes to choose a level of paranoia, depending on your application's requirements.
///
/// This paranoia level is a trade-off between ergonomics and security; as more frequent
/// token invalidation requires more overhead for handling and renewing tokens on the client side,
/// as well as retrying requests with a fresh token, should they fail.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum RegenerateToken {
    /// Generate one CSRF token per session and use this token until the session ends.
    ///
    /// This is the default behavior and should work for most applications.
    #[default]
    PerSession,
    /// Regenerate the CSRF token after each use. A "use" describes an unsafe HTTP method
    /// (`POST`, `PUT`, `PATCH`, `DELETE`).
    ///
    /// CSRF tokens are not required for, and thus not invalidated by handling requests
    /// using safe HTTP methods (`HEAD`, `GET`, `OPTIONS`, `TRACE`, `CONNECT`).
    PerUse,
    /// Regenerate the CSRF token at each request, including safe HTTP methods (`HEAD`, `GET`, `OPTIONS`, `TRACE`, `CONNECT`).
    ///
    /// This behavior might require elaborate token handling on the client side,
    /// as any concurrent requests mean race conditions from the client's perspective,
    /// and each request's response yields a new token to be used on the consecutive request.
    PerRequest,
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("Random number generator error")]
    Rng(#[from] rand::Error),

    #[error("Session error")]
    Session(#[from] tower_sessions::session::Error),

    #[error("Session extension missing. Is `axum_sessions::SessionLayer` installed and layered around the `axum_csrf_sync_pattern::CsrfLayer`?")]
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

/// This middleware is created by axum by applying the `CsrfLayer`.
/// It verifies the CSRF token header on incoming requests, regenerates tokens as configured,
/// and attaches the current token to the outgoing response.
///
/// In detail, this middleware receives a CSRF token as `X-CSRF-TOKEN` (if not custom configured
/// with a different name) HTTP request header value
/// and compares it to the token stored in the session.
///
/// Upon response from the inner service, the session token is returned to the
/// client via the `X-CSRF-TOKEN` response header.
///
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
pub struct CsrfMiddleware<S> {
    inner: S,
    layer: CsrfLayer,
}

impl<S> CsrfMiddleware<S> {
    /// Create a new middleware from an inner [`tower::Service`] (axum-specific bounds, such as `Infallible` errors apply!) and a [`CsrfLayer`].
    /// Commonly, the middleware is created by the [`tower::Layer`] - and never manually.
    pub fn new(inner: S, layer: CsrfLayer) -> Self {
        CsrfMiddleware { inner, layer }
    }

    /// Create a new CSRF synchronizer token layer.
    /// Equivalent to calling [`CsrfLayer::new()`].
    pub fn layer() -> CsrfLayer {
        CsrfLayer::default()
    }
}

impl<S, B: Send + 'static> tower::Service<Request<B>> for CsrfMiddleware<S>
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
        let layer = self.layer;
        Box::pin(async move {
            let session = match req
                .extensions()
                .get::<Session>()
                .ok_or(Error::SessionLayerMissing)
            {
                Ok(session_handle) => session_handle,
                Err(error) => return Ok(error.into_response()),
            };

            // Extract the CSRF server side token from the session; create a new one if none has been set yet.
            // If the regeneration option is set to "per request", then regenerate the token even if present in the session.
            let mut server_token = match session.get::<String>(layer.session_key).ok().flatten() {
                Some(token) => token,
                None => match layer.regenerate_token(&session) {
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
                server_token = match layer.regenerate_token(&session) {
                    Ok(token) => token,
                    Err(error) => {
                        return Ok(layer.response_with_token(error.into_response(), &server_token))
                    }
                };
            }

            let response = inner.call(req).await.into_response();

            // Add X-CSRF-TOKEN response header.
            Ok(layer.response_with_token(response, &server_token))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum::{body::Body, routing::get, Router, error_handling::HandleErrorLayer};
    use axum_core::{response::{IntoResponse, Response}, BoxError};
    use tower_sessions::{MemoryStore, SessionManagerLayer};
    use http::{
        header::{COOKIE, SET_COOKIE},
        Method, Request, StatusCode,
    };
    use tower::{Service, ServiceExt, ServiceBuilder};

    use super::*;

    async fn handler() -> Result<Response, Infallible> {
        Ok((
            StatusCode::OK,
            "The default test success response has a body",
        )
            .into_response())
    }

    fn session_layer() -> SessionManagerLayer<MemoryStore> {
        SessionManagerLayer::new(MemoryStore::default())
    }

    fn app(csrf_layer: CsrfLayer) -> Router {
        Router::new()
            .route("/", get(handler).post(handler))
            .layer(csrf_layer)
            .layer(ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async {
                    StatusCode::BAD_REQUEST
                }))
                .layer(session_layer()))
    }

    #[tokio::test]
    async fn get_without_token_succeeds() {
        let request = Request::builder()
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let response = app(CsrfLayer::new()).oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_eq!(BASE64_STANDARD.decode(client_token).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn post_without_token_fails() {
        let request = Request::builder()
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let response = app(CsrfLayer::new()).oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Assert: Response must contain token even on request token failure.
        let client_token = response.headers().get("X-CSRF-TOKEN").unwrap();
        assert_eq!(BASE64_STANDARD.decode(client_token).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn session_token_remains_valid() {
        let mut app = app(CsrfLayer::new().regenerate(RegenerateToken::PerSession));

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
        assert_eq!(
            BASE64_STANDARD.decode(initial_client_token).unwrap().len(),
            32
        );

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
        let mut app = app(CsrfLayer::new().regenerate(RegenerateToken::PerUse));

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
        assert_eq!(
            BASE64_STANDARD.decode(initial_client_token).unwrap().len(),
            32
        );

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
        let mut app = app(CsrfLayer::new().regenerate(RegenerateToken::PerRequest));

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
        assert_eq!(
            BASE64_STANDARD.decode(initial_client_token).unwrap().len(),
            32
        );

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
        let mut app = app(CsrfLayer::new().request_header("X-Custom-Token-Request-Header"));

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
        assert_eq!(BASE64_STANDARD.decode(client_token).unwrap().len(), 32);

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
        let response = app(CsrfLayer::new().response_header("X-Custom-Token-Response-Header"))
            .oneshot(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let client_token = response
            .headers()
            .get("X-Custom-Token-Response-Header")
            .unwrap();
        assert_eq!(BASE64_STANDARD.decode(client_token).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn uses_custom_session_key() {
        // Custom handler asserting the layer's configured session key is set,
        // and its value looks like a CSRF token.
        async fn extract_session(session: Session) -> StatusCode {
            let session_csrf_token: String = session.get("custom_session_key").unwrap().unwrap();

            assert_eq!(
                BASE64_STANDARD.decode(session_csrf_token).unwrap().len(),
                32
            );
            StatusCode::OK
        }

        let app = Router::new()
            .route("/", get(extract_session))
            .layer(CsrfLayer::new().session_key("custom_session_key"))
            .layer(ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async {
                    StatusCode::BAD_REQUEST
                }))
                .layer(session_layer()));

        let response = app
            .oneshot(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_session_layer_error_response() {
        let app = Router::new()
            .route("/", get(handler))
            .layer(CsrfLayer::new());

        let response = app
            .oneshot(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn invalid_token_str_error_response() {
        let layer = CsrfLayer::new();
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::boxed(Body::empty()))
            .unwrap();
        let response = layer.response_with_token(response, "\n");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
