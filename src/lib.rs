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
//! The middleware requires and is built upon [`tower_sessions`](https://docs.rs/tower-sessions/), version 0.14.
//! The session layer and this middleware must share one version of `tower-sessions-core`; see [Version requirements](#version-requirements).
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
//! ## The token
//!
//! The token is derived from the session ID with a secret [`Key`], instead of being stored in the session:
//!
//! ```text
//! token = base64url_no_pad( version ‖ issued_at ‖ nonce ‖ tag )
//! tag   = HMAC-SHA256( key, label ‖ session_id ‖ version ‖ issued_at ‖ nonce )
//! ```
//!
//! `version` is one byte, `issued_at` the issuing time in Unix seconds as eight big-endian bytes, `nonce` 16 random bytes,
//! `session_id` the 16 bytes of the session ID, and `label` the fixed byte string `axum-csrf-sync-pattern token`.
//! The token has 76 characters.
//!
//! - **Bound to the session.** A token is valid only together with the session it was issued for.
//!   Cycling the session ID with [`Session::cycle_id`], as at login against session fixation, invalidates every token issued for the old ID.
//! - **A different token per response.** The nonce changes the token with every response, which defeats
//!   [BREACH](https://en.wikipedia.org/wiki/BREACH)-style compression attacks on responses carrying it.
//!   Every issued token stays valid until the session ID changes, or until it exceeds the maximum age configured with [`CsrfLayer::max_age`].
//! - **Constant-time verification.** The tag is compared in constant time.
//!
//! ## Concurrent requests
//!
//! The middleware never writes to an existing session. Any number of overlapping requests of one session derive and accept tokens independently,
//! so concurrent requests cannot invalidate each other's tokens.
//!
//! Two limits remain, both caused by cookie issuance rather than by the token:
//!
//! - Two concurrent **first** requests of a client without a session cookie create two sessions. The client keeps one cookie,
//!   and the token of the other response does not match it. Fetch a token with a single request before sending requests in parallel.
//! - Requests overlapping a login that calls [`Session::cycle_id`] carry the old session cookie, whose record no longer exists, and are refused.
//!
//! ### Why tokens do not rotate per use or per request
//!
//! Earlier versions offered to regenerate the token after each use or each request. `tower-sessions` offers no lock and no atomic store operation,
//! so a rotating token would be read and replaced by overlapping requests at once: single use would not be enforced,
//! and whichever response the store kept last would decide which token stayed valid, failing the client's next request at random.
//! To bound the lifetime of a token instead, configure [`CsrfLayer::max_age`].
//!
//! ## The key
//!
//! [`CsrfLayer::new`] requires a [`Key`] of at least 32 bytes, held in memory by [`secrecy`] and zeroed when dropped.
//!
//! - Load the key from your configuration with [`Key::try_from`]. Instances behind one load balancer must share the key.
//! - [`Key::generate`] creates a random key, suitable for a single process only: every restart invalidates all tokens,
//!   and instances generating their own keys refuse each other's tokens.
//! - Rotate keys with [`CsrfLayer::previous_key`]: tokens are issued with the current key and accepted with the current key or any previous one.
//!
//! ## Session data
//!
//! The only entry the middleware writes into a session is a marker, under `axum-csrf-sync-pattern.initialized` by default.
//! It is written once, into a new session no other request knows yet, so that the session manager keeps the session and sets its cookie.
//! Every key the crate uses starts with `axum-csrf-sync-pattern.`, so that it does not collide with other users of the session.
//!
//! ## Security
//!
//! ### Token randomness
//!
//! The nonce is drawn from [`rand::rng`], a cryptographically secure pseudo-random number generator (CSPRNG) seeded from the operating system.
//! See ["Our RNGs"](https://rust-random.github.io/book/guide-rngs.html#cryptographically-secure-pseudo-random-number-generators-csprngs) for more.
//!
//! ### Underlying session security
//!
//! The security of the underlying session is paramount - the CSRF prevention methods applied can only be as secure as the session the token is bound to.
//!
//! - Do not lower the secure defaults: Keep the session cookie's `secure` flag **on**.
//! - Use the strictest possible same-site policy.
//! - Call [`Session::cycle_id`] at login, to prevent session fixation.
//!
//! ### CORS security
//!
//! If you need to provide and secure cross-site requests:
//!
//! - Allow only your backend origin when configuring the [`CorsLayer`](https://docs.rs/tower-http/latest/tower_http/cors/struct.CorsLayer.html)
//! - Allow only the headers you need. (At least the CSRF request token header.)
//! - Only expose the headers you need. (At least the CSRF response token header.)
//!
//! ### Layer order
//!
//! Layer the [`CorsLayer`](https://docs.rs/tower-http/latest/tower_http/cors/struct.CorsLayer.html) outside the session layer,
//! and the session layer outside the [`CsrfLayer`]. In axum, a layer added later wraps the layers added before it.
//!
//! ### No leaks of error details
//!
//! Errors and refused requests are logged using [`tracing`]. Error responses do not contain error details.
//!
//! Use [`tower_http::TraceLayer`](https://docs.rs/tower-http/latest/tower_http/trace/struct.TraceLayer.html) to capture and view traces.
//!
//! ## Version requirements
//!
//! The middleware finds the session in the request extensions by its type. If your application resolves a different version of `tower-sessions-core`
//! than this crate, both versions are compiled in, and every request is answered with `500 Internal Server Error`,
//! logging that the session extension is missing. This crate requires `tower-sessions-core` 0.14, which `tower-sessions` 0.14 uses.
//! Check with `cargo tree --duplicates --package tower-sessions-core`.
//!
//! ## Safety
//!
//! This crate uses no `unsafe` code.
//!
//! The layer and middleware functionality is tested. View the the module source code and the integration tests to learn more.
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
//! use std::time::Duration;
//!
//! use axum::{
//!     http::StatusCode,
//!     routing::{get, Router},
//! };
//! use axum_csrf_sync_pattern::{CsrfLayer, Key};
//! use tower_sessions::{MemoryStore, SessionManagerLayer};
//!
//! # let key_from_configuration = [7; 64];
//! # let previous_key_from_configuration = [8; 64];
//! async fn handler() -> StatusCode {
//!     StatusCode::OK
//! }
//!
//! let app = Router::new()
//!     .route("/", get(handler).post(handler))
//!     .layer(
//!         // Load the key from your configuration; at least 32 bytes.
//!         CsrfLayer::new(Key::try_from(&key_from_configuration[..]).unwrap())
//!
//!         // Optionally, configure the layer with the following options:
//!
//!         // Default: none
//!         .previous_key(Key::try_from(&previous_key_from_configuration[..]).unwrap())
//!         // Default: none
//!         .max_age(Duration::from_secs(8 * 60 * 60))
//!         // Default: "X-CSRF-TOKEN"
//!         .request_header("X-Custom-Request-Header")
//!         // Default: "X-CSRF-TOKEN"
//!         .response_header("X-Custom-Response-Header")
//!         // Default: "axum-csrf-sync-pattern.initialized"
//!         .session_key("my-application.csrf-initialized")
//!     )
//!     .layer(SessionManagerLayer::new(MemoryStore::default()));
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
//!     http::{header, Method, StatusCode},
//!     routing::{get, Router},
//! };
//! use axum_csrf_sync_pattern::{CsrfLayer, Key};
//! use tower_http::cors::{AllowOrigin, CorsLayer};
//! use tower_sessions::{MemoryStore, SessionManagerLayer};
//!
//! async fn handler() -> StatusCode {
//!     StatusCode::OK
//! }
//!
//! let app = Router::new()
//!     .route("/", get(handler).post(handler))
//!     .layer(
//!         // See example above for custom layer configuration.
//!         // A generated key suits a single process only: it changes at every restart.
//!         CsrfLayer::new(Key::generate())
//!     )
//!     .layer(SessionManagerLayer::new(MemoryStore::default()))
//!     .layer(
//!         CorsLayer::new()
//!             .allow_origin(AllowOrigin::list(["https://www.example.com".parse().unwrap()]))
//!             .allow_methods([Method::GET, Method::POST])
//!             .allow_headers([header::CONTENT_TYPE, "X-CSRF-TOKEN".parse().unwrap()])
//!             .allow_credentials(true)
//!             .expose_headers(["X-CSRF-TOKEN".parse().unwrap()]),
//!    );
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
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum_core::response::{IntoResponse, Response};
use base64::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use http::{HeaderValue, Request, StatusCode};
use rand::Rng;
use secrecy::{ExposeSecret, SecretSlice};
use sha2::Sha256;
use tower_layer::Layer;
use tower_sessions_core::{Session, session::Id};

// == Token format ==

/// The version byte of the token format.
const TOKEN_VERSION: u8 = 1;

/// The fixed byte string that separates the tags of this crate from any other use of the key.
const TOKEN_LABEL: &[u8] = b"axum-csrf-sync-pattern token";

/// The lengths of the token fields, in bytes.
const TOKEN_VERSION_LENGTH: usize = 1;
const TOKEN_ISSUED_AT_LENGTH: usize = 8;
const TOKEN_NONCE_LENGTH: usize = 16;
const TOKEN_TAG_LENGTH: usize = 32;

/// The length of the signed part of the token: version, issuing time and nonce.
const TOKEN_MESSAGE_LENGTH: usize =
    TOKEN_VERSION_LENGTH + TOKEN_ISSUED_AT_LENGTH + TOKEN_NONCE_LENGTH;

/// The length of the decoded token, in bytes.
const TOKEN_LENGTH: usize = TOKEN_MESSAGE_LENGTH + TOKEN_TAG_LENGTH;

// == Defaults ==

const DEFAULT_HEADER: &str = "X-CSRF-TOKEN";
const DEFAULT_SESSION_KEY: &str = "axum-csrf-sync-pattern.initialized";

/// The length of a key made by [`Key::generate`], in bytes.
const GENERATED_KEY_LENGTH: usize = 64;

/// The secret key from which the middleware derives the tokens of a session and against which it verifies them.
///
/// Create it from your configuration with [`Key::try_from`], or for a single process with [`Key::generate`].
/// The key material is held by [`secrecy`]: it is zeroed when the key is dropped, and [`Debug`] does not print it.
#[derive(Clone)]
pub struct Key(SecretSlice<u8>);

impl Key {
    /// The minimum length of a key, in bytes.
    pub const MINIMUM_LENGTH: usize = 32;

    /// Generate a random key of 64 bytes.
    ///
    /// **Warning:** A generated key exists only in the process that generated it.
    /// Every restart of the application generates a new key and so invalidates all tokens issued before,
    /// and several instances behind one load balancer refuse each other's tokens.
    /// Clients then receive `403 Forbidden` with a fresh token, and have to retry.
    /// Load a key from your configuration with [`Key::try_from`] wherever this matters.
    pub fn generate() -> Self {
        let mut bytes = vec![0; GENERATED_KEY_LENGTH];
        rand::rng().fill_bytes(&mut bytes);

        Self(SecretSlice::from(bytes))
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = KeyError;

    /// Create a key from at least [`Key::MINIMUM_LENGTH`] bytes of key material.
    ///
    /// The bytes are copied; zero your own copy once the key is created.
    ///
    /// # Errors
    ///
    /// - Returns [`KeyError::TooShort`] if `bytes` is shorter than [`Key::MINIMUM_LENGTH`].
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < Self::MINIMUM_LENGTH {
            return Err(KeyError::TooShort {
                length: bytes.len(),
            });
        }

        Ok(Self(SecretSlice::from(bytes.to_vec())))
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Key([REDACTED])")
    }
}

/// The error returned by [`Key::try_from`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The key material is shorter than [`Key::MINIMUM_LENGTH`].
    #[error("the key has {length} bytes, fewer than the minimum of 32")]
    TooShort {
        /// The length of the refused key material, in bytes.
        length: usize,
    },
}

/// The current key and the previous keys of a layer.
#[derive(Clone, Debug)]
struct Keys {
    current: Key,
    previous: Vec<Key>,
}

impl Keys {
    /// Compute the tag of a token for the given session ID with the current key.
    fn sign(&self, session_id: Id, message: &[u8]) -> [u8; TOKEN_TAG_LENGTH] {
        Self::mac(&self.current, session_id, message)
            .finalize()
            .into_bytes()
            .into()
    }

    /// Verify the tag of a token for the given session ID against the current key, then the previous keys in the order
    /// they were added. Each comparison runs in constant time.
    fn verify(&self, session_id: Id, message: &[u8], tag: &[u8]) -> bool {
        std::iter::once(&self.current)
            .chain(&self.previous)
            .any(|key| {
                Self::mac(key, session_id, message)
                    .verify_slice(tag)
                    .is_ok()
            })
    }

    fn mac(key: &Key, session_id: Id, message: &[u8]) -> Hmac<Sha256> {
        // PANICS: Does not panic, as HMAC accepts keys of any length.
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.0.expose_secret())
            .expect("HMAC accepts keys of any length");
        mac.update(TOKEN_LABEL);
        mac.update(&session_id.0.to_le_bytes());
        mac.update(message);

        mac
    }
}

/// Use [`CsrfLayer::new`] to provide the middleware and configuration to axum's service stack.
///
/// Use the provided methods to configure details, such as previous keys, a maximum token age, the names of the request and response
/// headers, and the session key of the marker.
#[derive(Clone, Debug)]
pub struct CsrfLayer {
    keys: Arc<Keys>,

    /// Configures the maximum age of a token. Older tokens are refused. Defaults to none: a token is valid as long as its session ID.
    pub max_age: Option<Duration>,

    /// Configures the request header name accepted by the middleware. Defaults to `"X-CSRF-TOKEN"`.
    /// This header is set on your JavaScript or WASM requests originating from the browser.
    pub request_header: &'static str,

    /// Configures the response header name sent by the middleware. Defaults to `"X-CSRF-TOKEN"`.
    /// This header is received by your JavaScript or WASM code and its name must be used to extract the token from the HTTP response.
    pub response_header: &'static str,

    /// Configures the key under which the middleware stores its marker in a new session.
    /// Defaults to `"axum-csrf-sync-pattern.initialized"`.
    pub session_key: &'static str,
}

impl CsrfLayer {
    /// Create a new CSRF synchronizer token layer to inject into your middleware stack using
    /// [`axum::Router::layer()`](https://docs.rs/axum/latest/axum/struct.Router.html#method.layer).
    ///
    /// Tokens are issued with `key` and verified against it. See [`Key`] for how to create one.
    pub fn new(key: Key) -> Self {
        Self {
            keys: Arc::new(Keys {
                current: key,
                previous: Vec::new(),
            }),
            max_age: None,
            request_header: DEFAULT_HEADER,
            response_header: DEFAULT_HEADER,
            session_key: DEFAULT_SESSION_KEY,
        }
    }

    /// Accept tokens issued with a previous key, for key rotation. Call it once per previous key.
    ///
    /// Tokens are always issued with the key passed to [`CsrfLayer::new`].
    pub fn previous_key(mut self, key: Key) -> Self {
        Arc::make_mut(&mut self.keys).previous.push(key);

        self
    }

    /// Configure the maximum age of a token. Older tokens are refused with `403 Forbidden` and a fresh token.
    ///
    /// The age is measured in whole seconds from the issuing time stored in the token. Defaults to none.
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);

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

    /// Configure a custom key under which the middleware stores its marker in a new session.
    /// Defaults to `"axum-csrf-sync-pattern.initialized"`.
    ///
    /// Choose a key in a namespace of your own, so that it does not collide with other users of the session.
    pub fn session_key(mut self, session_key: &'static str) -> Self {
        self.session_key = session_key;

        self
    }

    /// Issue a token for `session_id` with the current key, as of `issued_at` in Unix seconds.
    fn token(&self, session_id: Id, issued_at: u64) -> String {
        let mut token = [0; TOKEN_LENGTH];
        let (message, tag) = token.split_at_mut(TOKEN_MESSAGE_LENGTH);
        let (version, rest) = message.split_at_mut(TOKEN_VERSION_LENGTH);
        let (issued_at_bytes, nonce) = rest.split_at_mut(TOKEN_ISSUED_AT_LENGTH);

        version.copy_from_slice(&[TOKEN_VERSION]);
        issued_at_bytes.copy_from_slice(&issued_at.to_be_bytes());
        rand::rng().fill_bytes(nonce);
        tag.copy_from_slice(&self.keys.sign(session_id, message));

        BASE64_URL_SAFE_NO_PAD.encode(token)
    }

    /// Verify a token for `session_id` against the current and the previous keys, and against the maximum age as of `now` in Unix seconds.
    fn verify_token(&self, token: &str, session_id: Id, now: u64) -> Result<(), Rejection> {
        let token = BASE64_URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| Rejection::Undecodable)?;
        let token: [u8; TOKEN_LENGTH] =
            token
                .try_into()
                .map_err(|token: Vec<u8>| Rejection::WrongLength {
                    length: token.len(),
                })?;

        let (message, tag) = token.split_at(TOKEN_MESSAGE_LENGTH);
        let (version, rest) = message.split_at(TOKEN_VERSION_LENGTH);
        let (issued_at, _nonce) = rest.split_at(TOKEN_ISSUED_AT_LENGTH);

        if version != [TOKEN_VERSION] {
            return Err(Rejection::UnknownVersion);
        }

        if !self.keys.verify(session_id, message, tag) {
            return Err(Rejection::TagMismatch);
        }

        if let Some(max_age) = self.max_age {
            // PANICS: Does not panic, as `split_at` has cut exactly `TOKEN_ISSUED_AT_LENGTH` bytes.
            let issued_at = u64::from_be_bytes(
                issued_at
                    .try_into()
                    .expect("the issuing time has exactly eight bytes"),
            );
            let age = now.saturating_sub(issued_at);

            if age > max_age.as_secs() {
                return Err(Rejection::Expired {
                    age,
                    max_age: max_age.as_secs(),
                });
            }
        }

        Ok(())
    }

    /// Verify the token of an unsafe request against the session ID the store has confirmed.
    fn verify_request<B>(
        &self,
        request: &Request<B>,
        validated_id: Option<Id>,
    ) -> Result<(), Rejection> {
        let session_id = validated_id.ok_or(Rejection::NoSession)?;
        let token = request
            .headers()
            .get(self.request_header)
            .ok_or(Rejection::MissingHeader {
                header: self.request_header,
            })?
            .to_str()
            .map_err(|_| Rejection::InvalidHeader)?;

        self.verify_token(token, session_id, unix_seconds_now())
    }

    /// Attach a token for the session as the inner service has left it.
    ///
    /// An existing session is never written. A session without an ID is saved first: one a handler has filled or cycled,
    /// or a new, empty one, into which the marker is inserted so that the session manager keeps it.
    async fn issue_token(
        &self,
        session: &Session,
        validated_id: Option<Id>,
        mut response: Response,
    ) -> Response {
        // The session manager does not persist the session of a server error response.
        if response.status().is_server_error() {
            return response;
        }

        let session_id = match session.id() {
            Some(session_id) => session_id,
            None => {
                if session.is_empty().await {
                    // A session that had a record before the request and has none now has been flushed, as at logout.
                    if validated_id.is_some() {
                        return response;
                    }

                    if let Err(error) = session.insert(self.session_key, true).await {
                        return Error::from(error).into_response();
                    }
                }

                if let Err(error) = session.save().await {
                    return Error::from(error).into_response();
                }

                match session.id() {
                    Some(session_id) => session_id,
                    None => return Error::SessionIdMissing.into_response(),
                }
            }
        };

        match HeaderValue::try_from(self.token(session_id, unix_seconds_now())) {
            Ok(token) => {
                response.headers_mut().insert(self.response_header, token);
                response
            }
            Err(error) => Error::from(error).into_response(),
        }
    }
}

impl<S> Layer<S> for CsrfLayer {
    type Service = CsrfMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfMiddleware::new(inner, self.clone())
    }
}

/// The current time in Unix seconds.
fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// The reasons for refusing an unsafe request with `403 Forbidden`.
#[derive(Debug, thiserror::Error)]
enum Rejection {
    #[error("the session has no record in the store")]
    NoSession,

    #[error("the request carries no `{header}` header")]
    MissingHeader { header: &'static str },

    #[error("the token header is not visible ASCII")]
    InvalidHeader,

    #[error("the token is not unpadded base64url")]
    Undecodable,

    #[error("the token has {length} bytes instead of {TOKEN_LENGTH}")]
    WrongLength { length: usize },

    #[error("the token has an unknown format version")]
    UnknownVersion,

    #[error("the token was not issued for this session with a known key")]
    TagMismatch,

    #[error("the token is {age} seconds old, more than the maximum age of {max_age} seconds")]
    Expired { age: u64, max_age: u64 },
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("the session store failed")]
    Session(#[from] tower_sessions_core::session::Error),

    #[error(
        "the session extension is missing; layer `tower_sessions::SessionManagerLayer` around `axum_csrf_sync_pattern::CsrfLayer`, \
         and make sure that the application resolves a single version of `tower-sessions-core`"
    )]
    SessionLayerMissing,

    #[error("the session has no ID after it was saved")]
    SessionIdMissing,

    #[error("the token is not a valid header value")]
    InvalidServerTokenHeader(#[from] http::header::InvalidHeaderValue),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "Failed to handle the CSRF token: {self}.");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

/// This middleware is created by axum by applying the `CsrfLayer`.
/// It verifies the CSRF token header on incoming requests and attaches a token to the outgoing response.
///
/// In detail, this middleware receives a CSRF token as `X-CSRF-TOKEN` (if not custom configured
/// with a different name) HTTP request header value on unsafe requests (`POST`, `PUT`, `PATCH`, `DELETE`),
/// and verifies that it was issued for the request's session with a known key.
///
/// Upon response from the inner service, a fresh token for the session is returned to the
/// client via the `X-CSRF-TOKEN` response header.
///
/// Make sure to expose this header in your CORS configuration if necessary!
///
/// Requires and uses `tower_sessions`.
#[derive(Debug, Clone)]
pub struct CsrfMiddleware<S> {
    inner: S,
    layer: CsrfLayer,
}

impl<S> CsrfMiddleware<S> {
    /// Create a new middleware from an inner [`tower_service::Service`] (axum-specific bounds, such as `Infallible` errors apply!) and a [`CsrfLayer`].
    /// Commonly, the middleware is created by the [`tower_layer::Layer`] - and never manually.
    pub fn new(inner: S, layer: CsrfLayer) -> Self {
        CsrfMiddleware { inner, layer }
    }

    /// Create a new CSRF synchronizer token layer.
    /// Equivalent to calling [`CsrfLayer::new()`].
    pub fn layer(key: Key) -> CsrfLayer {
        CsrfLayer::new(key)
    }
}

impl<S, B: Send + 'static> tower_service::Service<Request<B>> for CsrfMiddleware<S>
where
    S: tower_service::Service<Request<B>, Response = Response, Error = Infallible>
        + Send
        + Clone
        + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let layer = self.layer.clone();
        Box::pin(async move {
            let Some(session) = request.extensions().get::<Session>().cloned() else {
                return Ok(Error::SessionLayerMissing.into_response());
            };

            // Load the record before reading the ID. Until the record is loaded, the ID is the cookie's,
            // which the store may not know; loading resets it if the store holds no record.
            if let Err(error) = session.get_value(layer.session_key).await {
                return Ok(Error::from(error).into_response());
            }
            let validated_id = session.id();

            let response = if request.method().is_safe() {
                inner.call(request).await.into_response()
            } else {
                match layer.verify_request(&request, validated_id) {
                    Ok(()) => inner.call(request).await.into_response(),
                    Err(rejection) => {
                        tracing::warn!(
                            ?rejection,
                            "Refused an unsafe request, because {rejection}."
                        );
                        StatusCode::FORBIDDEN.into_response()
                    }
                }
            };

            Ok(layer.issue_token(&session, validated_id, response).await)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Key {
        Key::try_from(&[byte; Key::MINIMUM_LENGTH][..]).unwrap()
    }

    fn session_id() -> Id {
        Id(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef)
    }

    #[test]
    fn key_shorter_than_minimum_is_refused() {
        assert_eq!(
            Key::try_from(&[0; Key::MINIMUM_LENGTH - 1][..]).unwrap_err(),
            KeyError::TooShort {
                length: Key::MINIMUM_LENGTH - 1
            },
        );
    }

    #[test]
    fn key_debug_prints_no_key_material() {
        assert_eq!(format!("{:?}", key(42)), "Key([REDACTED])");
        assert!(!format!("{:?}", CsrfLayer::new(key(42))).contains("42"));
    }

    #[test]
    fn token_has_76_characters() {
        let token = CsrfLayer::new(key(1)).token(session_id(), 1_700_000_000);

        assert_eq!(token.len(), 76);
    }

    #[test]
    fn token_is_accepted_for_its_session() {
        let layer = CsrfLayer::new(key(1));
        let token = layer.token(session_id(), 1_700_000_000);

        assert!(
            layer
                .verify_token(&token, session_id(), 1_700_000_000)
                .is_ok()
        );
    }

    #[test]
    fn token_of_another_session_is_refused() {
        let layer = CsrfLayer::new(key(1));
        let token = layer.token(Id(1), 1_700_000_000);

        assert!(matches!(
            layer.verify_token(&token, Id(2), 1_700_000_000),
            Err(Rejection::TagMismatch)
        ));
    }

    #[test]
    fn token_of_unknown_version_is_refused() {
        let layer = CsrfLayer::new(key(1));
        let mut token = BASE64_URL_SAFE_NO_PAD
            .decode(layer.token(session_id(), 1_700_000_000))
            .unwrap();
        token[0] = 2;

        assert!(matches!(
            layer.verify_token(
                &BASE64_URL_SAFE_NO_PAD.encode(token),
                session_id(),
                1_700_000_000
            ),
            Err(Rejection::UnknownVersion)
        ));
    }

    #[test]
    fn token_older_than_maximum_age_is_refused() {
        let layer = CsrfLayer::new(key(1)).max_age(Duration::from_secs(60));
        let token = layer.token(session_id(), 1_700_000_000);

        assert!(
            layer
                .verify_token(&token, session_id(), 1_700_000_060)
                .is_ok()
        );
        assert!(matches!(
            layer.verify_token(&token, session_id(), 1_700_000_061),
            Err(Rejection::Expired {
                age: 61,
                max_age: 60
            })
        ));
    }

    #[test]
    fn token_of_previous_key_is_accepted_and_of_unknown_key_refused() {
        let previous = CsrfLayer::new(key(1));
        let unknown = CsrfLayer::new(key(3));
        let current = CsrfLayer::new(key(2)).previous_key(key(1));

        let token = previous.token(session_id(), 1_700_000_000);
        assert!(
            current
                .verify_token(&token, session_id(), 1_700_000_000)
                .is_ok()
        );

        let token = unknown.token(session_id(), 1_700_000_000);
        assert!(matches!(
            current.verify_token(&token, session_id(), 1_700_000_000),
            Err(Rejection::TagMismatch)
        ));
    }
}
