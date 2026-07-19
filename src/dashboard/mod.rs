use askama::Template;
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::server::AppState;
use crate::store::{CatchRow, RequestRow, Session, Stats};

/// Render an Askama template into an axum HTML `Response`.
struct HtmlTemplate<T>(T);

impl<T: Template> IntoResponse for HtmlTemplate<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => {
                let mut response =
                    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response();
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    "no-store".parse().expect("static cache policy is valid"),
                );
                response.headers_mut().insert(
                    header::HeaderName::from_static("x-robots-tag"),
                    "noindex, nofollow"
                        .parse()
                        .expect("static robots policy is valid"),
                );
                response
            }
            Err(e) => {
                tracing::error!("dashboard template render error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

#[derive(Template)]
#[template(path = "dashboard/overview.html")]
struct OverviewTemplate {
    path: String,
    stats: Stats,
    sessions: Vec<Session>,
}

#[derive(Template)]
#[template(path = "dashboard/session.html")]
struct SessionTemplate {
    path: String,
    session: Session,
    requests: Vec<RequestRow>,
    catches: Vec<CatchRow>,
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, token)| scheme.eq_ignore_ascii_case("bearer") && !token.is_empty())
        .map(|(_, token)| token)
}

fn dashboard_path(cfg: &crate::config::Config) -> String {
    let mut path = cfg.dashboard.path.clone();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    path
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(overview))
        .route("/session/{id}", get(session_detail))
        .with_state(state)
}

async fn overview(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers) {
        return unauthorized();
    }

    let stats = match state.store.get_stats().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("failed to load stats: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let sessions = match state.store.list_sessions(100).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("failed to list sessions: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    HtmlTemplate(OverviewTemplate {
        path: dashboard_path(&state.config),
        stats,
        sessions,
    })
    .into_response()
}

async fn session_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers) {
        return unauthorized();
    }

    let session_id = match Uuid::parse_str(&id) {
        Ok(uuid) => uuid,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let session = match state.store.get_session_by_id(&session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("failed to load session: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let requests = match state.store.get_session_requests(&session_id).await {
        Ok(requests) => requests,
        Err(error) => {
            tracing::error!("failed to load session requests: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let catches = match state.store.get_session_catches(&session_id).await {
        Ok(catches) => catches,
        Err(error) => {
            tracing::error!("failed to load session catches: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    HtmlTemplate(SessionTemplate {
        path: dashboard_path(&state.config),
        session,
        requests,
        catches,
    })
    .into_response()
}

fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let expected = &state.config.dashboard.token;
    if expected.is_empty() {
        return false;
    }
    extract_bearer(headers)
        .is_some_and(|provided| bool::from(expected.as_bytes().ct_eq(provided.as_bytes())))
}

fn unauthorized() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        "Bearer realm=\"Rook dashboard\""
            .parse()
            .expect("static authentication challenge is valid"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static cache policy is valid"),
    );
    response
}
