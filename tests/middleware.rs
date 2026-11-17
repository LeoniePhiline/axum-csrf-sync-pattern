//! Integration tests of the middleware through an `axum` router, with the session stored by `tower-sessions`.
//!
//! The memory store of `tower-sessions` hands out a copy of the record on every load, as a Redis store does,
//! so overlapping requests do not share session state in these tests either.

use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{
        Method, Request, StatusCode,
        header::{COOKIE, SET_COOKIE},
    },
    response::Response,
    routing::{get, post},
};
use axum_csrf_sync_pattern::{CsrfLayer, Key};
use tokio::{sync::Barrier, task::JoinSet};
use tower::ServiceExt;
use tower_sessions::{
    MemoryStore, Session, SessionManagerLayer, SessionStore,
    session::{Id, Record},
    session_store,
};

const TOKEN_HEADER: &str = "X-CSRF-TOKEN";
const MARKER_KEY: &str = "axum-csrf-sync-pattern.initialized";
const TOKEN_CHARACTERS: usize = 76;
const OVERLAPPING_REQUESTS: usize = 32;

// == Store ==

/// A memory store that counts its writes.
#[derive(Clone, Debug, Default)]
struct CountingStore {
    inner: MemoryStore,
    writes: Arc<AtomicUsize>,
}

impl CountingStore {
    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SessionStore for CountingStore {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.create(record).await
    }

    async fn save(&self, record: &Record) -> session_store::Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.save(record).await
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        self.inner.load(session_id).await
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        self.inner.delete(session_id).await
    }
}

// == Application ==

fn key(byte: u8) -> Key {
    Key::try_from(&[byte; Key::MINIMUM_LENGTH][..]).unwrap()
}

async fn ok() -> StatusCode {
    StatusCode::OK
}

async fn login(session: Session) -> StatusCode {
    session.cycle_id().await.unwrap();
    StatusCode::OK
}

async fn logout(session: Session) -> StatusCode {
    session.flush().await.unwrap();
    StatusCode::OK
}

async fn fail() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

fn router<S: SessionStore + Clone>(layer: CsrfLayer, store: S) -> Router {
    Router::new()
        .route("/", get(ok).post(ok))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/fail", get(fail))
        .layer(layer)
        .layer(SessionManagerLayer::new(store))
}

// == Requests ==

/// Send a request with the session cookie and the token, where given.
async fn send(
    router: &Router,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    token: Option<&str>,
) -> Response {
    let mut request = Request::builder().method(method).uri(path);

    if let Some(cookie) = cookie {
        request = request.header(COOKIE, cookie);
    }

    if let Some(token) = token {
        request = request.header(TOKEN_HEADER, token);
    }

    router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn token(response: &Response) -> String {
    response
        .headers()
        .get(TOKEN_HEADER)
        .expect("the response carries a token")
        .to_str()
        .unwrap()
        .to_owned()
}

/// The `name=value` pair of the session cookie set by the response.
fn cookie(response: &Response) -> String {
    response
        .headers()
        .get(SET_COOKIE)
        .expect("the response sets the session cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

fn session_id(cookie: &str) -> Id {
    cookie.split_once('=').unwrap().1.parse().unwrap()
}

/// Start a session with a first request, and return its cookie and token.
async fn start_session(router: &Router) -> (String, String) {
    let response = send(router, Method::GET, "/", None, None).await;
    assert_eq!(response.status(), StatusCode::OK);

    (cookie(&response), token(&response))
}

fn assert_refused_with_fresh_token(response: &Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(token(response).len(), TOKEN_CHARACTERS);
}

// == Concurrency ==

#[tokio::test]
async fn overlapping_posts_with_one_token_all_succeed() {
    // Every request waits inside the handler until all of them have arrived there,
    // so the test cannot pass without the requests overlapping.
    let barrier = Arc::new(Barrier::new(OVERLAPPING_REQUESTS));
    let router = Router::new()
        .route(
            "/",
            get(ok).post(move || {
                let barrier = Arc::clone(&barrier);
                async move {
                    barrier.wait().await;
                    StatusCode::OK
                }
            }),
        )
        .layer(CsrfLayer::new(key(1)))
        .layer(SessionManagerLayer::new(MemoryStore::default()));
    let (cookie, token) = start_session(&router).await;

    let mut requests = JoinSet::new();
    for _ in 0..OVERLAPPING_REQUESTS {
        let (router, cookie, token) = (router.clone(), cookie.clone(), token.clone());
        requests.spawn(async move {
            send(&router, Method::POST, "/", Some(&cookie), Some(&token))
                .await
                .status()
        });
    }

    let statuses = tokio::time::timeout(Duration::from_secs(10), requests.join_all())
        .await
        .expect("all requests reach the handler at once");

    assert_eq!(statuses, vec![StatusCode::OK; OVERLAPPING_REQUESTS]);
}

#[tokio::test]
async fn requests_of_an_existing_session_write_nothing_to_the_store() {
    let store = CountingStore::default();
    let router = router(CsrfLayer::new(key(1)), store.clone());
    let (cookie, token) = start_session(&router).await;
    let writes = store.writes();
    assert!(writes > 0);

    for _ in 0..8 {
        let response = send(&router, Method::GET, "/", Some(&cookie), None).await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = send(&router, Method::POST, "/", Some(&cookie), Some(&token)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    assert_eq!(store.writes(), writes);
}

#[tokio::test]
async fn overlapping_gets_return_distinct_tokens_each_accepted() {
    let router = router(CsrfLayer::new(key(1)), MemoryStore::default());
    let (cookie, _) = start_session(&router).await;

    let mut requests = JoinSet::new();
    for _ in 0..OVERLAPPING_REQUESTS {
        let (router, cookie) = (router.clone(), cookie.clone());
        requests.spawn(async move {
            token(&send(&router, Method::GET, "/", Some(&cookie), None).await)
        });
    }
    let tokens: HashSet<String> = requests.join_all().await.into_iter().collect();

    assert_eq!(tokens.len(), OVERLAPPING_REQUESTS);
    for token in tokens {
        let response = send(&router, Method::POST, "/", Some(&cookie), Some(&token)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}

// == Sessions ==

#[tokio::test]
async fn first_visit_sets_cookie_and_token_and_stores_only_the_marker() {
    let store = MemoryStore::default();
    let router = router(CsrfLayer::new(key(1)), store.clone());
    let (cookie, token) = start_session(&router).await;

    assert_eq!(token.len(), TOKEN_CHARACTERS);

    let record = store.load(&session_id(&cookie)).await.unwrap().unwrap();
    assert_eq!(
        record.data.keys().map(String::as_str).collect::<Vec<_>>(),
        [MARKER_KEY]
    );

    let response = send(&router, Method::POST, "/", Some(&cookie), Some(&token)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_cycling_the_session_id_issues_a_token_for_the_new_id_and_refuses_the_old_one() {
    let router = router(CsrfLayer::new(key(1)), MemoryStore::default());
    let (old_cookie, old_token) = start_session(&router).await;

    let response = send(
        &router,
        Method::POST,
        "/login",
        Some(&old_cookie),
        Some(&old_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let (new_cookie, new_token) = (cookie(&response), token(&response));
    assert_ne!(new_cookie, old_cookie);

    let response = send(
        &router,
        Method::POST,
        "/",
        Some(&new_cookie),
        Some(&old_token),
    )
    .await;
    assert_refused_with_fresh_token(&response);

    let response = send(
        &router,
        Method::POST,
        "/",
        Some(&new_cookie),
        Some(&new_token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn logout_flushing_the_session_returns_no_token_and_removes_the_cookie() {
    let router = router(CsrfLayer::new(key(1)), MemoryStore::default());
    let (cookie, token) = start_session(&router).await;

    let response = send(
        &router,
        Method::POST,
        "/logout",
        Some(&cookie),
        Some(&token),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(TOKEN_HEADER).is_none());
    assert!(
        response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
}

#[tokio::test]
async fn server_error_on_first_visit_leaves_no_record() {
    let store = CountingStore::default();
    let router = router(CsrfLayer::new(key(1)), store.clone());

    let response = send(&router, Method::GET, "/fail", None, None).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(response.headers().get(TOKEN_HEADER).is_none());
    assert!(response.headers().get(SET_COOKIE).is_none());
    assert_eq!(store.writes(), 0);
}

// == Refusals ==

#[tokio::test]
async fn unsafe_request_without_session_is_refused_with_fresh_token() {
    let router = router(CsrfLayer::new(key(1)), MemoryStore::default());

    let response = send(&router, Method::POST, "/", None, None).await;

    assert_refused_with_fresh_token(&response);
    assert!(response.headers().get(SET_COOKIE).is_some());
}

#[tokio::test]
async fn unsafe_request_without_token_header_is_refused_with_fresh_token() {
    let router = router(CsrfLayer::new(key(1)), MemoryStore::default());
    let (cookie, _) = start_session(&router).await;

    let response = send(&router, Method::POST, "/", Some(&cookie), None).await;

    assert_refused_with_fresh_token(&response);
}

#[tokio::test]
async fn garbled_token_is_refused_with_fresh_token() {
    let router = router(CsrfLayer::new(key(1)), MemoryStore::default());
    let (cookie, _) = start_session(&router).await;

    let response = send(&router, Method::POST, "/", Some(&cookie), Some("garbled")).await;

    assert_refused_with_fresh_token(&response);
}

#[tokio::test]
async fn token_of_another_session_is_refused_with_fresh_token() {
    let router = router(CsrfLayer::new(key(1)), MemoryStore::default());
    let (cookie, _) = start_session(&router).await;
    let (_, other_token) = start_session(&router).await;

    let response = send(
        &router,
        Method::POST,
        "/",
        Some(&cookie),
        Some(&other_token),
    )
    .await;

    assert_refused_with_fresh_token(&response);
}

#[tokio::test]
async fn token_for_a_cookie_whose_record_is_gone_is_refused_with_fresh_token() {
    let store = MemoryStore::default();
    let router = router(CsrfLayer::new(key(1)), store.clone());
    let (cookie, token) = start_session(&router).await;
    store.delete(&session_id(&cookie)).await.unwrap();

    let response = send(&router, Method::POST, "/", Some(&cookie), Some(&token)).await;

    assert_refused_with_fresh_token(&response);
    assert_ne!(self::cookie(&response), cookie);
}

// == Keys ==

#[tokio::test]
async fn token_of_a_previous_key_is_accepted_and_of_an_unknown_key_refused() {
    let store = MemoryStore::default();
    let before_rotation = router(CsrfLayer::new(key(1)), store.clone());
    let after_rotation = router(CsrfLayer::new(key(2)).previous_key(key(1)), store.clone());
    let unrelated = router(CsrfLayer::new(key(2)), store.clone());
    let (cookie, token) = start_session(&before_rotation).await;

    let response = send(
        &after_rotation,
        Method::POST,
        "/",
        Some(&cookie),
        Some(&token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = send(&unrelated, Method::POST, "/", Some(&cookie), Some(&token)).await;
    assert_refused_with_fresh_token(&response);
}

// == Configuration ==

#[tokio::test]
async fn missing_session_layer_answers_internal_server_error() {
    let router = Router::new()
        .route("/", get(ok))
        .layer(CsrfLayer::new(key(1)));

    let response = send(&router, Method::GET, "/", None, None).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn custom_request_header_is_accepted() {
    let router = router(
        CsrfLayer::new(key(1)).request_header("X-Custom-Request-Header"),
        MemoryStore::default(),
    );
    let (cookie, token) = start_session(&router).await;

    let request = Request::builder()
        .method(Method::POST)
        .header(COOKIE, cookie)
        .header("X-Custom-Request-Header", token)
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn custom_response_header_is_sent() {
    let router = router(
        CsrfLayer::new(key(1)).response_header("X-Custom-Response-Header"),
        MemoryStore::default(),
    );

    let response = send(&router, Method::GET, "/", None, None).await;

    assert_eq!(
        response
            .headers()
            .get("X-Custom-Response-Header")
            .unwrap()
            .len(),
        TOKEN_CHARACTERS
    );
}

#[tokio::test]
async fn custom_session_key_holds_the_marker() {
    let store = MemoryStore::default();
    let router = router(
        CsrfLayer::new(key(1)).session_key("my-application.csrf-initialized"),
        store.clone(),
    );
    let (cookie, _) = start_session(&router).await;

    let record = store.load(&session_id(&cookie)).await.unwrap().unwrap();

    assert_eq!(
        record.data.keys().map(String::as_str).collect::<Vec<_>>(),
        ["my-application.csrf-initialized"]
    );
}
