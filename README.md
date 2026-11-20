# Axum Synchronizer Token Pattern CSRF prevention

This crate provides a Cross-Site Request Forgery protection layer and middleware for use with the [axum](https://docs.rs/axum/) web framework.

[![Crates.io](https://img.shields.io/crates/v/axum-csrf-sync-pattern)](https://crates.io/crates/axum-csrf-sync-pattern)
[![Documentation](https://docs.rs/axum-csrf-sync-pattern/badge.svg)][docs]
[![Continuous integration](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/actions/workflows/ci.yml/badge.svg)](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/actions/workflows/ci.yml)
[![Dependency status](https://deps.rs/repo/github/LeoniePhiline/axum-csrf-sync-pattern/status.svg)](https://deps.rs/repo/github/LeoniePhiline/axum-csrf-sync-pattern)

The middleware implements the [CSRF Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern)
for AJAX backends and API endpoints as described in the OWASP CSRF prevention cheat sheet.

More information about this crate can be found in the [crate documentation][docs].

## Installation

```toml
axum-csrf-sync-pattern = "0.3.2"
```

## Examples

See the [example projects](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/tree/main/examples/) for same-site and cross-site usage.

Consider as well to use the [integration tests](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/blob/main/tests/middleware.rs) as your reference.

## Scope

This middleware implements token transfer via [custom request headers](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers).

The middleware requires and is built upon [`tower_sessions`](https://docs.rs/tower-sessions/).

The current version is built for and works with `axum 0.8.x` and `tower-sessions 0.14.x`.
The session layer and this middleware must share one version of `tower-sessions-core`; see [Version requirements](#version-requirements).

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

## The token

The token is derived from the session ID with a secret [`Key`](https://docs.rs/axum-csrf-sync-pattern/latest/axum_csrf_sync_pattern/struct.Key.html), instead of being stored in the session:

```text
token = base64url_no_pad( version ‖ issued_at ‖ nonce ‖ tag )
tag   = HMAC-SHA256( key, label ‖ session_id ‖ version ‖ issued_at ‖ nonce )
```

`version` is one byte, `issued_at` the issuing time in Unix seconds as eight big-endian bytes, `nonce` 16 random bytes,
`session_id` the 16 bytes of the session ID, and `label` the fixed byte string `axum-csrf-sync-pattern token`.
The token has 76 characters.

- **Bound to the session.** A token is valid only together with the session it was issued for.
  Cycling the session ID with [`Session::cycle_id`](https://docs.rs/tower-sessions/0.14.0/tower_sessions/struct.Session.html#method.cycle_id), as at login against session fixation, invalidates every token issued for the old ID.
- **A different token per response.** The nonce changes the token with every response, which defeats
  [BREACH](https://en.wikipedia.org/wiki/BREACH)-style compression attacks on responses carrying it.
  Every issued token stays valid until the session ID changes, or until it exceeds the maximum age configured with [`CsrfLayer::max_age`](https://docs.rs/axum-csrf-sync-pattern/latest/axum_csrf_sync_pattern/struct.CsrfLayer.html#method.max_age).
- **Constant-time verification.** The tag is compared in constant time.

## Concurrent requests

The middleware never writes to an existing session. Any number of overlapping requests of one session derive and accept tokens independently,
so concurrent requests cannot invalidate each other's tokens.

Two limits remain, both caused by cookie issuance rather than by the token:

- Two concurrent **first** requests of a client without a session cookie create two sessions. The client keeps one cookie,
  and the token of the other response does not match it. Fetch a token with a single request before sending requests in parallel.
- Requests overlapping a login that calls [`Session::cycle_id`](https://docs.rs/tower-sessions/0.14.0/tower_sessions/struct.Session.html#method.cycle_id) carry the old session cookie, whose record no longer exists, and are refused.

### Why tokens do not rotate per use or per request

Earlier versions offered to regenerate the token after each use or each request. `tower-sessions` offers no lock and no atomic store operation,
so a rotating token would be read and replaced by overlapping requests at once: single use would not be enforced,
and whichever response the store kept last would decide which token stayed valid, failing the client's next request at random.
To bound the lifetime of a token instead, configure [`CsrfLayer::max_age`](https://docs.rs/axum-csrf-sync-pattern/latest/axum_csrf_sync_pattern/struct.CsrfLayer.html#method.max_age).

## The key

[`CsrfLayer::new`](https://docs.rs/axum-csrf-sync-pattern/latest/axum_csrf_sync_pattern/struct.CsrfLayer.html#method.new) requires a [`Key`](https://docs.rs/axum-csrf-sync-pattern/latest/axum_csrf_sync_pattern/struct.Key.html) of at least 32 bytes,
held in memory by [`secrecy`](https://docs.rs/secrecy/) and zeroed when dropped.

- Load the key from your configuration with `Key::try_from`. Instances behind one load balancer must share the key.
- [`Key::generate`](https://docs.rs/axum-csrf-sync-pattern/latest/axum_csrf_sync_pattern/struct.Key.html#method.generate) creates a random key, suitable for a single process only: every restart invalidates all tokens,
  and instances generating their own keys refuse each other's tokens.
- Rotate keys with [`CsrfLayer::previous_key`](https://docs.rs/axum-csrf-sync-pattern/latest/axum_csrf_sync_pattern/struct.CsrfLayer.html#method.previous_key):
  tokens are issued with the current key and accepted with the current key or any previous one.

## Session data

The only entry the middleware writes into a session is a marker, under `axum-csrf-sync-pattern.initialized` by default.
It is written once, into a new session no other request knows yet, so that the session manager keeps the session and sets its cookie.
Every key the crate uses starts with `axum-csrf-sync-pattern.`, so that it does not collide with other users of the session.

## Security

### Token randomness

The nonce is drawn from [`rand::rng`](https://docs.rs/rand/latest/rand/fn.rng.html), a cryptographically secure pseudo-random number generator (CSPRNG) seeded from the operating system.
See ["Our RNGs"](https://rust-random.github.io/book/guide-rngs.html#cryptographically-secure-pseudo-random-number-generators-csprngs) for more.

### Underlying session security

The security of the underlying session is paramount - the CSRF prevention methods applied can only be as secure as the session the token is bound to.

- Do not lower the secure defaults: Keep the session cookie's `secure` flag **on**.
- Use the strictest possible same-site policy.
- Call [`Session::cycle_id`](https://docs.rs/tower-sessions/0.14.0/tower_sessions/struct.Session.html#method.cycle_id) at login, to prevent session fixation.

### CORS security

If you need to provide and secure cross-site requests:

- Allow only your backend origin when configuring the [`CorsLayer`](https://docs.rs/tower-http/latest/tower_http/cors/struct.CorsLayer.html)
- Allow only the headers you need. (At least the CSRF request token header.)
- Only expose the headers you need. (At least the CSRF response token header.)

### Layer order

Layer the [`CorsLayer`](https://docs.rs/tower-http/latest/tower_http/cors/struct.CorsLayer.html) outside the session layer,
and the session layer outside the `CsrfLayer`. In axum, a layer added later wraps the layers added before it.

### No leaks of error details

Errors and refused requests are logged using [`tracing`](https://docs.rs/tracing/). Error responses do not contain error details.

Use [`tower_http::TraceLayer`](https://docs.rs/tower-http/latest/tower_http/trace/struct.TraceLayer.html) to capture and view traces.

## Version requirements

The middleware finds the session in the request extensions by its type. If your application resolves a different version of `tower-sessions-core`
than this crate, both versions are compiled in, and every request is answered with `500 Internal Server Error`,
logging that the session extension is missing. This crate requires `tower-sessions-core` 0.14, which `tower-sessions` 0.14 uses.
Check with `cargo tree --duplicates --package tower-sessions-core`.

## Safety

This crate uses no `unsafe` code.

The layer and middleware functionality is tested. View the module source code and the integration tests to learn more.

## Usage

See the [example projects](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/tree/main/examples/) for same-site and cross-site usage.
These examples are interactive demos. Run them, then interact with them in the browser.

### Same-site usage

**Note:** The crate repository contains example projects for same-site and cross-site usage!
In each example directory, execute `cargo run`, then open [http://127.0.0.1:3000](http://127.0.0.1:3000) in your browser.

Configure your session and CSRF protection layer in your backend application:

```rust
use std::time::Duration;

use axum::{
    http::StatusCode,
    routing::{get, Router},
};
use axum_csrf_sync_pattern::{CsrfLayer, Key};
use tower_sessions::{MemoryStore, SessionManagerLayer};

// Key material from your configuration, at least 32 bytes each.
let key_from_configuration = [7; 64];
let previous_key_from_configuration = [8; 64];

async fn handler() -> StatusCode {
    StatusCode::OK
}

let app = Router::new()
 .route("/", get(handler).post(handler))
 .layer(
     // Load the key from your configuration; at least 32 bytes.
     CsrfLayer::new(Key::try_from(&key_from_configuration[..]).unwrap())

     // Optionally, configure the layer with the following options:

     // Default: none
     .previous_key(Key::try_from(&previous_key_from_configuration[..]).unwrap())
     // Default: none
     .max_age(Duration::from_secs(8 * 60 * 60))
     // Default: "X-CSRF-TOKEN"
     .request_header("X-Custom-Request-Header")
     // Default: "X-CSRF-TOKEN"
     .response_header("X-Custom-Response-Header")
     // Default: "axum-csrf-sync-pattern.initialized"
     .session_key("my-application.csrf-initialized")
 )
 .layer(SessionManagerLayer::new(MemoryStore::default()));

// Use hyper to run `app` as service and expose on a local port or socket.
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
    http::{header, Method, StatusCode},
    routing::{get, Router},
};
use axum_csrf_sync_pattern::{CsrfLayer, Key};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_sessions::{MemoryStore, SessionManagerLayer};

async fn handler() -> StatusCode {
    StatusCode::OK
}

let app = Router::new()
 .route("/", get(handler).post(handler))
 .layer(
     // See example above for custom layer configuration.
     // A generated key suits a single process only: it changes at every restart.
     CsrfLayer::new(Key::generate())
 )
 .layer(SessionManagerLayer::new(MemoryStore::default()))
 .layer(
     CorsLayer::new()
         .allow_origin(AllowOrigin::list(["https://www.example.com".parse().unwrap()]))
         .allow_methods([Method::GET, Method::POST])
         .allow_headers([header::CONTENT_TYPE, "X-CSRF-TOKEN".parse().unwrap()])
         .allow_credentials(true)
         .expose_headers(["X-CSRF-TOKEN".parse().unwrap()]),
);

// Use hyper to run `app` as service and expose on a local port or socket.
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
