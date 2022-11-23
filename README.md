# Axum Synchronizer Token Pattern CSRF prevention

This crate provides a Cross-Site Request Forgery protection layer and middleware for use with the [axum](https://docs.rs/axum/) web framework.

The middleware implements the [CSRF Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern)
for AJAX backends and API endpoints as described in the OWASP CSRF prevention cheat sheet.

## Examples

See the [example projects](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/tree/main/examples/) for same-site and cross-site usage.

Consider as well to use the [crate unit tests](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/blob/main/src/lib.rs#:~:text=%23%5Bcfg,mod%20tests) as your reference.

## Scope

This middleware implements token transfer via [custom request headers](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers).

The middleware requires and is built upon [`axum_sessions`](https://docs.rs/axum-sessions/), which in turn uses [`async_session`](https://docs.rs/async-session/).

The current version is built for and works with `axum 0.5.x`, `axum-sessions 0.3.x` and `async_session 3.x`.

There will be support for `axum 0.6` and later versions.

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

### Same-site usage

**Note:** The crate repository contains example projects for same-site and cross-site usage!

Configure your session and CSRF protection layer in your backend application:

```rust
use rand::RngCore;

let mut secret = [0; 64];
rand::thread_rng().try_fill_bytes(&mut secret).unwrap();

async fn handler() -> axum::http::StatusCode {
 axum::http::StatusCode::OK
}

let app = axum::Router::new()
 .route("/", axum::routing::get(handler).post(handler))
 .layer(
     axum_csrf_sync_pattern::CsrfSynchronizerTokenLayer::default()

     // Optionally, configure the layer with the following options:

     // Default: RegenerateToken::PerSession
     .regenerate(axum_csrf_sync_pattern::RegenerateToken::PerUse)
     // Default: "X-CSRF-TOKEN"
     .request_header("X-Custom-CSRF-Token-Client-Request-Header")
     // Default: "X-CSRF-TOKEN"
     .response_header("X-Custom-CSRF-Token-Server-Response-Header")
     // Default: "_csrf_token"
     .session_key("_custom_csrf_token_session_key")
 )
 .layer(
     axum_sessions::SessionLayer::new(
         async_session::MemoryStore::new(),
         &secret
     )
 );

// Use hyper to run `app` as service and expose on a local port or socket.

# use tower::util::ServiceExt;
# tokio_test::block_on(async {
#     app.oneshot(
#         axum::http::Request::builder().body(axum::body::Body::empty()).unwrap()
#     ).await.unwrap();
# })
```

Receive the token and send same-site requests, using your custom header:

```javascript
const test = async () => {
  // Receive CSRF token (Default response header name: 'X-CSRF-TOKEN')
  const token = (await fetch("/")).headers.get(
    "X-Custom-CSRF-Token-Server-Response-Header"
  );

  // Submit data using the token
  await fetch("/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // Default request header name: 'X-CSRF-TOKEN'
      "X-Custom-CSRF-Token-Client-Request-Header": token,
    },
    body: JSON.stringify({
      /* ... */
    }),
  });
};
```

### CORS-enabled usage

**Note:** The crate repository contains example projects for same-site and cross-site usage!

Configure your CORS layer, session and CSRF protection layer in your backend application:

```rust
use rand::RngCore;

let mut secret = [0; 64];
rand::thread_rng().try_fill_bytes(&mut secret).unwrap();

async fn handler() -> axum::http::StatusCode {
 axum::http::StatusCode::OK
}

let app = axum::Router::new()
 .route("/", axum::routing::get(handler).post(handler))
 .layer(
     // See example above for custom layer configuration.
     axum_csrf_sync_pattern::CsrfSynchronizerTokenLayer::default()
 )
 .layer(
     axum_sessions::SessionLayer::new(
         async_session::MemoryStore::new(),
         &secret
     )
 )
 .layer(
     tower_http::cors::CorsLayer::new()
         .allow_origin(tower_http::cors::AllowOrigin::list(["https://www.example.com".parse().unwrap()]))
         .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
         .allow_headers([axum::http::header::CONTENT_TYPE, "X-CSRF-TOKEN".parse().unwrap()])
         .allow_credentials(true)
         .expose_headers(["X-CSRF-TOKEN".parse().unwrap()]),
);

// Use hyper to run `app` as service and expose on a local port or socket.

# use tower::util::ServiceExt;
# tokio_test::block_on(async {
#     app.oneshot(
#         axum::http::Request::builder().body(axum::body::Body::empty()).unwrap()
#     ).await.unwrap();
# })
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

## Contributing

Pull requests are welcome!
