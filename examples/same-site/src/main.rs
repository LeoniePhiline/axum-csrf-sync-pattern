use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
};
use color_eyre::eyre::{self, eyre, WrapErr};
use rand::RngCore;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    // Use the "Send POST request without CSRF token" button in your browser,
    // then check your console to find "WARN axum_csrf_sync_pattern: X-CSRF-TOKEN header missing!".
    // The middleware uses tracing to log all error cases, including CSRF rejections.
    tracing_subscriber::fmt::try_init()
        .map_err(|e| eyre!(e))
        .wrap_err("Failed to initialize tracing-subscriber.")?;

    let mut secret = [0; 64];
    rand::thread_rng().try_fill_bytes(&mut secret).unwrap();

    let app = axum::Router::new()
        .route("/", axum::routing::get(index).post(handler))
        .layer(axum_csrf_sync_pattern::CsrfSynchronizerTokenLayer::default())
        .layer(axum_sessions::SessionLayer::new(
            async_session::MemoryStore::new(),
            &secret,
        ));

    // Visit "http://127.0.0.1:3000/" in your browser.
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn index() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html")],
        include_str!("./index.html"),
    )
}

async fn handler() -> axum::http::StatusCode {
    StatusCode::ACCEPTED
}
