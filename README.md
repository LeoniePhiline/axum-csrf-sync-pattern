# Axum Cross Site Request Forgery protection implementing the Synchronizer Token Pattern

An axum middleware, providing Cross Site Request Forgery protection by inplementing the [CSRF Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern) as described by OWASP. 
The middleware requires and is built on top of `axum-sessions`.