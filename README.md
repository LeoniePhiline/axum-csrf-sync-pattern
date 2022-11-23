# Axum Cross Site Request Forgery protection implementing the Synchronizer Token Pattern

An axum middleware, providing Cross Site Request Forgery protection by implementing the [CSRF Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern) as described by OWASP.

This middleware is built for and works with `axum 0.5.x` and `axum-sessions 0.3.x`.

There will be support for `axum 0.6` and later versions.

Although documentation is lacking as of this moment, the middleware is usable immediately.
The unit tests shall stand in as usage documentation until proper documentation has been written.

## Examples

See the [example projects](https://github.com/LeoniePhiline/axum-csrf-sync-pattern/tree/main/examples/) for same-site and cross-site usage.

