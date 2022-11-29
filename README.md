# Axum Synchronizer Token Pattern CSRF prevention

This crate provides a Cross-Site Request Forgery protection layer and middleware for use with the [axum](https://docs.rs/axum/) web framework.

[![Crates.io](https://img.shields.io/crates/v/axum-csrf-sync-pattern)](https://crates.io/crates/axum-csrf-sync-pattern)
[![Documentation](https://docs.rs/axum-csrf-sync-pattern/badge.svg)][docs]

The middleware implements the [CSRF Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern)
for AJAX backends and API endpoints as described in the OWASP CSRF prevention cheat sheet.

More information about this crate can be found in the [crate documentation][docs].

## Installation

```toml
axum-csrf-sync-pattern = "0.1.4"
```

## Examples

See the [example projects](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/tree/main/examples/) for same-site and cross-site usage.

Consider as well to use the [crate unit tests](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/blob/main/src/lib.rs#:~:text=%23%5Bcfg,mod%20tests) as your reference.

## Scope

This middleware implements token transfer via [custom request headers](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers).

The middleware requires and is built upon [`axum_sessions`](https://docs.rs/axum-sessions/), which in turn uses [`async_session`](https://docs.rs/async-session/).

The current version is built for and works with `axum 0.6.x`, `axum-sessions 0.4.x` and `async_session 3.x`.

There will be support for `axum 0.7` and later versions.

The [Same Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) prevents the custom request header to be set by foreign scripts.

### In which contexts should I use this middleware?

The goal of this middleware is to prevent cross-site request forgery attacks specifically in applications communicating with their backend by means of the JavaScript
[`fetch()` API](https://developer.mozilla.org/en-US/docs/Web/API/fetch) or classic [`XmlHttpRequest`](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest),
traditionally called "AJAX".

The Synchronizer Token Pattern is especially useful in [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) contexts,
as the underlying session cookie is obligatorily secured and inaccessible by JavaScript, while the custom HTTP response header carrying the CSRF token can be exposed
using the CORS [`Access-Control-Expose-Headers`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers) HTTP response header.

While the [Same Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) commonly prevents custom request headers to be set on cross-origin requests,
use of the use of the [Access-Control-Allow-Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers) CORS HTTP response header
can be used to specifically allow CORS requests to be equipped with a required custom HTTP request header.

This approach ensures that requests forged by auto-submitted forms or other data-submitting scripts from foreign origins are unable to add the required header.

### When should I use other CSRF protection patterns or libraries?

Use other available middleware libraries if you plan on submitting classical HTML forms without the use of JavaScript, and if you do not send the form data across origins.

## Security

### Token randomness

The CSRF tokens are generated using [`rand::ThreadRng`](https://rust-random.github.io/rand/rand/rngs/struct.ThreadRng.html) which is considered cryptographically secure (CSPRNG).
See ["Our RNGs"](https://rust-random.github.io/book/guide-rngs.html#cryptographically-secure-pseudo-random-number-generators-csprngs) for more.

### Underlying session security

The security of the underlying session is paramount - the CSRF prevention methods applied can only be as secure as the session carrying the server-side token.

- When creating your [SessionLayer](https://docs.rs/axum-sessions/latest/axum_sessions/struct.SessionLayer.html), make sure to use at least 64 bytes of cryptographically secure randomness.
- Do not lower the secure defaults: Keep the session cookie's `secure` flag **on**.
- Use the strictest possible same-site policy.

### CORS security

If you need to provide and secure cross-site requests:

- Allow only your backend origin when configuring the [`CorsLayer`](https://docs.rs/tower-http/latest/tower_http/cors/struct.CorsLayer.html)
- Allow only the headers you need. (At least the CSRF request token header.)
- Only expose the headers you need. (At least the CSRF response token header.)

### No leaks of error details

Errors are logged using [`tracing::error!`]. Error responses do not contain error details.

Use [`tower_http::TraceLayer`](https://docs.rs/tower-http/latest/tower_http/trace/struct.TraceLayer.html) to capture and view traces.

## Safety

This crate uses no `unsafe` code.

The layer and middleware functionality is tested. View the the module source code to learn more.

## Usage

See the [example projects](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/tree/main/examples/) for same-site and cross-site usage.
These examples are interactive demos. Run them, then interact with them in the browser.

### Same-site usage

**Note:** The crate repository contains example projects for same-site and cross-site usage!
In each example directory, execute `cargo run`, then open [http://127.0.0.1:3000](http://127.0.0.1:3000) in your browser.

Configure your session and CSRF protection layer in your backend application:

```rust
use axum::{
    body::Body,
    http::StatusCode,
    routing::{get, Router},
};
use axum_csrf_sync_pattern::{CsrfLayer, RegenerateToken};
use axum_sessions::{async_session::MemoryStore, SessionLayer};
use rand::RngCore;

let mut secret = [0; 64];
rand::thread_rng().try_fill_bytes(&mut secret).unwrap();

async fn handler() -> StatusCode {
    StatusCode::OK
}

let app = Router::new()
 .route("/", get(handler).post(handler))
 .layer(
     CsrfLayer::new()

     // Optionally, configure the layer with the following options:

     // Default: RegenerateToken::PerSession
     .regenerate(RegenerateToken::PerUse)
     // Default: "X-CSRF-TOKEN"
     .request_header("X-Custom-Request-Header")
     // Default: "X-CSRF-TOKEN"
     .response_header("X-Custom-Response-Header")
     // Default: "_csrf_token"
     .session_key("_custom_session_key")
 )
 .layer(SessionLayer::new(MemoryStore::new(), &secret));

// Use hyper to run `app` as service and expose on a local port or socket.

use tower::util::ServiceExt;
tokio_test::block_on(async {
    app.oneshot(
        axum::http::Request::builder().body(axum::body::Body::empty()).unwrap()
    ).await.unwrap();
})
```

Receive the token and send same-site requests, using your custom header:

```javascript
const test = async () => {
  // Receive CSRF token (Default response header name: 'X-CSRF-TOKEN')
  const token = (await fetch("/")).headers.get("X-Custom-Response-Header");

  // Submit data using the token
  await fetch("/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // Default request header name: 'X-CSRF-TOKEN'
      "X-Custom-Request-Header": token,
    },
    body: JSON.stringify({
      /* ... */
    }),
  });
};
```

For a full demo, run the [same-site example project](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/tree/main/examples/same-site).
You will find the interactive demo at [http://127.0.0.1:3000](http://127.0.0.1:3000).

### CORS-enabled usage

**Note:** The crate repository contains example projects for same-site and cross-site usage!
In each example directory, execute `cargo run`, then open [http://127.0.0.1:3000](http://127.0.0.1:3000) in your browser.

Configure your CORS layer, session and CSRF protection layer in your backend application:

```rust
use axum::{
    body::Body,
    http::{header, Method, StatusCode},
    routing::{get, Router},
};
use axum_csrf_sync_pattern::{CsrfLayer, RegenerateToken};
use axum_sessions::{async_session::MemoryStore, SessionLayer};
use rand::RngCore;
use tower_http::cors::{AllowOrigin, CorsLayer};

let mut secret = [0; 64];
rand::thread_rng().try_fill_bytes(&mut secret).unwrap();

async fn handler() -> StatusCode {
    StatusCode::OK
}

let app = Router::new()
 .route("/", get(handler).post(handler))
 .layer(
     // See example above for custom layer configuration.
     CsrfLayer::new()
 )
 .layer(SessionLayer::new(MemoryStore::new(), &secret))
 .layer(
     CorsLayer::new()
         .allow_origin(AllowOrigin::list(["https://www.example.com".parse().unwrap()]))
         .allow_methods([Method::GET, Method::POST])
         .allow_headers([header::CONTENT_TYPE, "X-CSRF-TOKEN".parse().unwrap()])
         .allow_credentials(true)
         .expose_headers(["X-CSRF-TOKEN".parse().unwrap()]),
);

// Use hyper to run `app` as service and expose on a local port or socket.

use tower::util::ServiceExt;
tokio_test::block_on(async {
    app.oneshot(
        axum::http::Request::builder().body(axum::body::Body::empty()).unwrap()
    ).await.unwrap();
})
```

Receive the token and send cross-site requests, using your custom header:

```javascript
const test = async () => {
  // Receive CSRF token
  const token = (
    await fetch("https://backend.example.com/", {
      credentials: "include",
    })
  ).headers.get("X-CSRF-TOKEN");

  // Submit data using the token
  await fetch("https://backend.example.com/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-TOKEN": token,
    },
    credentials: "include",
    body: JSON.stringify({
      /* ... */
    }),
  });
};
```

For a full demo, run the [cross-site example project](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/tree/main/examples/cross-site).
You will find the interactive demo at [http://127.0.0.1:3000](http://127.0.0.1:3000).

## Contributing

Pull requests are welcome!

[docs]: https://docs.rs/axum-csrf-sync-pattern
