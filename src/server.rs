use axum::{
    Router,
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{normalize_path::NormalizePathLayer, services::ServeDir, trace::TraceLayer};

use crate::config::Config;
use crate::persona;
use crate::session;
use crate::store::SqliteStore;
use crate::traps::{CanaryIndex, MAX_INDEXED_SESSIONS};

/// Shared application state available to every handler via axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub store: Arc<SqliteStore>,
    pub canaries: CanaryIndex,
}

/// Build the router and start serving.
pub async fn run(config: Config) -> anyhow::Result<()> {
    let store = Arc::new(SqliteStore::open(&config.database.path)?);
    let canaries = CanaryIndex::new();

    // Warm the canary index with existing sessions so exfiltrated canaries can
    // still be attributed after a server restart.
    let sessions = store.list_sessions(MAX_INDEXED_SESSIONS as u32).await?;
    for session in sessions.into_iter().rev() {
        canaries.add_session(&session);
    }

    let state = Arc::new(AppState {
        config: config.clone(),
        store,
        canaries,
    });

    let app = build_router(state);

    let addr = config.bind_addr();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Rook listening on http://{}", addr);
    tracing::info!(
        "   Persona: {} ({}) — dashboard at {}",
        config.persona.name,
        config.persona.domain,
        config.dashboard.path
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// Construct the full router. Kept separate so tests can build it without binding.
pub fn build_router(state: Arc<AppState>) -> Router {
    let tracked_site = Router::new()
        .route("/", get(persona::landing))
        .route("/blog", get(persona::blog_index))
        .route("/blog/{slug}", get(persona::blog_post))
        .route("/docs", get(persona::docs))
        .route("/pricing", get(persona::pricing))
        .route("/robots.txt", get(persona::robots_txt))
        .route("/sitemap.xml", get(persona::sitemap_xml))
        .route("/h/{token}", get(persona::honeypot))
        .route("/continue/{canary}", get(persona::honeypot))
        .fallback(persona::not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session::middleware,
        ))
        .with_state(state.clone());

    let operational = Router::new()
        .route("/favicon.ico", get(persona::favicon))
        .route("/health", get(health))
        .nest_service("/static", ServeDir::new("static"))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session::middleware,
        ))
        .with_state(state.clone());

    let dashboard_path = state.config.dashboard.path.clone();
    let dashboard = Router::new().nest(&dashboard_path, crate::dashboard::router(state));

    tracked_site
        .merge(operational)
        .merge(dashboard)
        .layer(NormalizePathLayer::trim_trailing_slash())
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(security_headers))
}

async fn health() -> &'static str {
    "ok\n"
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let policies = [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    ];

    for (name, value) in policies {
        headers
            .entry(HeaderName::from_static(name))
            .or_insert_with(|| HeaderValue::from_static(value));
    }

    response
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!("failed to install Ctrl+C handler: {error}");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::warn!("failed to install SIGTERM handler: {error}"),
        }
    };

    #[cfg(unix)]
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    #[cfg(not(unix))]
    ctrl_c.await;

    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;

    fn test_state() -> Arc<AppState> {
        let config = Config::default().validate().expect("test config is valid");
        Arc::new(AppState {
            config,
            store: Arc::new(SqliteStore::open(":memory:").expect("test database opens")),
            canaries: CanaryIndex::new(),
        })
    }

    fn browser_request(path: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header(header::USER_AGENT, "Mozilla/5.0")
            .header(header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
            .header("sec-fetch-site", "none")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "document")
            .body(Body::empty())
            .expect("request is valid")
    }

    #[tokio::test]
    async fn first_browser_navigation_stays_unflagged_and_records_status() {
        let state = test_state();
        let response = build_router(state.clone())
            .oneshot(browser_request("/"))
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(header::SET_COOKIE));
        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        assert!(String::from_utf8_lossy(&body).contains("FrameShift"));

        let sessions = state
            .store
            .list_sessions(10)
            .await
            .expect("sessions should load");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].agent_probability, 0.0);
        assert!(!sessions[0].is_agent);
        let requests = state
            .store
            .get_session_requests(&sessions[0].id)
            .await
            .expect("requests should load");
        assert_eq!(requests[0].status_code, Some(200));
    }

    #[tokio::test]
    async fn health_checks_do_not_create_honeypot_sessions() {
        let state = test_state();
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request is valid"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            state
                .store
                .get_stats()
                .await
                .expect("stats should load")
                .total_sessions,
            0
        );
    }

    #[tokio::test]
    async fn dashboard_requires_the_configured_bearer_token() {
        let state = test_state();
        let app = build_router(state);

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/__rook__")
                    .body(Body::empty())
                    .expect("request is valid"),
            )
            .await
            .expect("router should respond");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert!(
            unauthorized
                .headers()
                .contains_key(header::WWW_AUTHENTICATE)
        );

        let authorized = app
            .oneshot(
                Request::builder()
                    .uri("/__rook__")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", Config::default().dashboard.token),
                    )
                    .body(Body::empty())
                    .expect("request is valid"),
            )
            .await
            .expect("router should respond");
        assert_eq!(authorized.status(), StatusCode::OK);
        assert_eq!(
            authorized
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }

    #[tokio::test]
    async fn honeypot_links_are_attributed_even_without_the_original_cookie() {
        let state = test_state();
        let original = state
            .store
            .create_session("127.0.0.1", "original")
            .await
            .expect("original session should be created");
        state.canaries.add_session(&original);

        let response = build_router(state.clone())
            .oneshot(browser_request(&format!("/h/{}", original.honeypot_token)))
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let catches = state
            .store
            .get_session_catches(&original.id)
            .await
            .expect("catches should load");
        assert_eq!(catches.len(), 1);
        assert_eq!(catches[0].payload_id, "honeypot_link");
        assert_eq!(catches[0].canary, original.honeypot_token);
    }

    #[tokio::test]
    async fn arbitrary_unknown_paths_are_scanned_for_canaries() {
        let state = test_state();
        let original = state
            .store
            .create_session("127.0.0.1", "original")
            .await
            .expect("original session should be created");
        state.canaries.add_session(&original);
        let canary = crate::traps::canary_for(&original.id, "confession");

        let response = build_router(state.clone())
            .oneshot(browser_request(&format!("/leaked/{canary}")))
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let catches = state
            .store
            .get_session_catches(&original.id)
            .await
            .expect("catches should load");
        assert_eq!(catches.len(), 1);
        assert_eq!(catches[0].payload_id, "confession");
        assert_eq!(catches[0].canary, canary);
    }

    #[tokio::test]
    async fn operational_routes_scan_canaries_without_creating_sessions() {
        let state = test_state();
        let original = state
            .store
            .create_session("127.0.0.1", "original")
            .await
            .expect("original session should be created");
        state.canaries.add_session(&original);
        let canary = crate::traps::canary_for(&original.id, "confession");

        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/health?leaked={canary}"))
                    .body(Body::empty())
                    .expect("request is valid"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let catches = state
            .store
            .get_session_catches(&original.id)
            .await
            .expect("catches should load");
        assert_eq!(catches.len(), 1);
        assert_eq!(catches[0].canary, canary);
        assert_eq!(
            state
                .store
                .get_stats()
                .await
                .expect("stats should load")
                .total_sessions,
            1
        );
    }
}
