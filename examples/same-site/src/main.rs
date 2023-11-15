use axum::{
    BoxError,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    error_handling::HandleErrorLayer,
    Server,
};
use tower::ServiceBuilder;
use axum_csrf_sync_pattern::CsrfLayer;
use tower_sessions::{MemoryStore, SessionManagerLayer};
use color_eyre::eyre::{self, eyre, WrapErr};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    // Use the "Send POST request without CSRF token" button in your browser,
    // then check your console to find "WARN axum_csrf_sync_pattern: X-CSRF-TOKEN header missing!".
    // The middleware uses tracing to log all error cases, including CSRF rejections.
    tracing_subscriber::fmt::try_init()
        .map_err(|e| eyre!(e))
        .wrap_err("Failed to initialize tracing-subscriber.")?;

    let app = axum::Router::new()
        .route("/", get(index).post(handler))
        .layer(CsrfLayer::new())
        .layer(ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|_: BoxError| async {
                StatusCode::BAD_REQUEST
            }))
            .layer(SessionManagerLayer::new(MemoryStore::default())));

    // Visit "http://127.0.0.1:3000/" in your browser.
    Server::try_bind(
        &"0.0.0.0:3000"
            .parse()
            .wrap_err("Failed to parse socket address.")?,
    )
    .wrap_err("Could not bind to network address.")?
    .serve(app.into_make_service())
    .await
    .wrap_err("Failed to serve the app.")?;

    Ok(())
}

async fn index() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html")],
        include_str!("./index.html"),
    )
}

async fn handler() -> StatusCode {
    StatusCode::ACCEPTED
}
