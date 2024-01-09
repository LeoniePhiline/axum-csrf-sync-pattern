use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
};
use axum_csrf_sync_pattern::CsrfLayer;
use color_eyre::eyre::{self, eyre, WrapErr};
use tower_sessions::{MemoryStore, SessionManagerLayer};

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
        .layer(SessionManagerLayer::new(MemoryStore::default()));

    // Visit "http://127.0.0.1:3000/" in your browser.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .wrap_err("Could not bind to network address.")?;
    axum::serve(listener, app)
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
