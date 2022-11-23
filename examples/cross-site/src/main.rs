use axum::{
    http::{header, Method, StatusCode},
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

    let frontend = async {
        let app = axum::Router::new().route("/", axum::routing::get(index));

        // Visit "http://127.0.0.1:3000/" in your browser.
        serve(app, 3000).await;
    };

    let backend = async {
        let mut secret = [0; 64];
        rand::thread_rng().try_fill_bytes(&mut secret).unwrap();

        let app = axum::Router::new()
            .route("/", axum::routing::get(get_token).post(post_handler))
            .layer(axum_csrf_sync_pattern::CsrfSynchronizerTokenLayer::default())
            .layer(axum_sessions::SessionLayer::new(
                async_session::MemoryStore::new(),
                &secret,
            ))
            .layer(
                tower_http::cors::CorsLayer::new()
                    .allow_origin(tower_http::cors::AllowOrigin::list([
                        // Allow CORS requests from our frontend.
                        "http://127.0.0.1:3000".parse().unwrap(),
                    ]))
                    // Allow GET and POST methods. Adjust to your needs.
                    .allow_methods([Method::GET, Method::POST])
                    .allow_headers([
                        // Allow incoming CORS requests to use the Content-Type header,
                        axum::http::header::CONTENT_TYPE,
                        // as well as the `CsrfSynchronizerTokenLayer` default request header.
                        "X-CSRF-TOKEN".parse().unwrap(),
                    ])
                    // Allow CORS requests with session cookies.
                    .allow_credentials(true)
                    // Instruct the browser to allow JavaScript on the configured origin
                    // to read the `CsrfSynchronizerTokenLayer` default response header.
                    .expose_headers(["X-CSRF-TOKEN".parse().unwrap()]),
            );

        serve(app, 4000).await;
    };

    tokio::join!(frontend, backend);

    Ok(())
}

async fn serve(app: axum::Router, port: u16) {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn index() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html")],
        include_str!("./index.html"),
    )
}

async fn get_token() -> StatusCode {
    StatusCode::OK
}

async fn post_handler() -> StatusCode {
    StatusCode::ACCEPTED
}
