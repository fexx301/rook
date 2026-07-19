use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, header::SET_COOKIE},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::detect;
use crate::server::AppState;
use crate::store::Session;
use crate::traps;

pub const COOKIE_NAME: &str = "_fs_sid";

/// Extract the value of a named cookie from raw request headers.
fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{}=", name);
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|header| {
            header.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix(&prefix).map(|s| s.to_string())
            })
        })
}

/// Build a list of strings from the request that might contain exfiltrated canaries.
fn build_haystacks(req: &Request<Body>) -> Vec<String> {
    let mut haystacks = Vec::new();
    haystacks.push(req.uri().path().to_string());
    if let Some(q) = req.uri().query() {
        haystacks.push(q.to_string());
    }
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            haystacks.push(format!("{}: {}", name.as_str(), v));
        }
    }
    haystacks
}

/// Scan the request for any known canary across all sessions.
fn scan_canaries(index: &traps::CanaryIndex, req: &Request<Body>) -> Vec<traps::CanaryInfo> {
    let haystacks = build_haystacks(req);
    index.scan(&haystacks)
}

async fn record_catches(
    state: &AppState,
    catches: Vec<traps::CanaryInfo>,
    current_session_id: Option<Uuid>,
    request_id: Option<i64>,
) {
    for catch in catches {
        tracing::info!(
            "🎯 canary caught: session={} payload={} kind={} canary={}",
            catch.session_id,
            catch.payload_id,
            catch.payload_kind,
            catch.canary
        );
        let request_id_for_catch = if current_session_id == Some(catch.session_id) {
            request_id
        } else {
            None
        };
        if let Err(error) = state
            .store
            .record_catch(
                &catch.session_id,
                request_id_for_catch,
                &catch.payload_id,
                &catch.payload_kind,
                &catch.canary,
                Some("request"),
            )
            .await
        {
            tracing::warn!("failed to record catch: {error}");
        }
    }
}

/// Session middleware:
/// - Reads (or mints) the `_fs_sid` session cookie.
/// - Loads/creates the session in the SQLite store.
/// - Records the request and extracts agent-detection signals.
/// - Scans for exfiltrated canaries (globally) and records catches.
/// - Injects the session into request extensions for downstream handlers.
/// - Sets the cookie on the response when a new session is created.
pub async fn middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if detect::signals::is_untracked_path(req.uri().path()) {
        let catches = scan_canaries(&state.canaries, &req);
        record_catches(&state, catches, None, None).await;
        return next.run(req).await;
    }

    let user_agent = req
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let remote_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let cookie_value = extract_cookie(req.headers(), COOKIE_NAME);

    // Try to load an existing session.
    let existing = match cookie_value {
        Some(ref cookie) => match state.store.get_session_by_cookie(cookie).await {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!("failed to load session cookie: {error}");
                None
            }
        },
        None => None,
    };

    let (session, is_new) = match existing {
        Some(s) => (s, false),
        None => match state.store.create_session(&remote_ip, &user_agent).await {
            Ok(s) => {
                state.canaries.add_session(&s);
                (s, true)
            }
            Err(e) => {
                tracing::error!("failed to create session: {}; using transient session", e);
                let s = Session::new(&remote_ip, &user_agent);
                state.canaries.add_session(&s);
                (s, true)
            }
        },
    };

    // Record this request. Failures are logged but do not break the response.
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    let request_id = state
        .store
        .record_request(
            &session.id,
            &method,
            &path,
            query.as_deref(),
            Some(&user_agent),
            Some(&remote_ip),
        )
        .await
        .inspect_err(|e| tracing::warn!("failed to record request: {}", e))
        .ok();

    // Extract and persist detection signals.
    let signals = detect::signals::extract_signals(
        req.headers(),
        &path,
        &session,
        &state.config.detection,
        Utc::now(),
    );
    if let Some(request_id) = request_id {
        match state
            .store
            .record_signals(
                &session.id,
                request_id,
                &signals,
                state.config.detection.agent_threshold,
            )
            .await
        {
            Ok(score) if score.is_agent && !session.is_agent => {
                tracing::info!(
                    session_id = %session.id,
                    probability = score.probability,
                    "session crossed the agent threshold"
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!("failed to record signals: {error}");
            }
        }
    }

    // Scan for exfiltrated canaries globally and record catches.
    let catches = scan_canaries(&state.canaries, &req);
    record_catches(&state, catches, Some(session.id), request_id).await;

    let mut req = req;
    req.extensions_mut().insert(session.clone());

    let mut response = next.run(req).await;

    if let Some(request_id) = request_id
        && let Err(error) = state
            .store
            .update_request_status(request_id, response.status().as_u16())
            .await
    {
        tracing::warn!("failed to record response status: {error}");
    }

    if is_new {
        let mut cookie = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800",
            COOKIE_NAME, session.cookie_id
        );
        if state.config.server.secure_cookies {
            cookie.push_str("; Secure");
        }
        match cookie.parse() {
            Ok(value) => {
                response.headers_mut().append(SET_COOKIE, value);
            }
            Err(error) => tracing::error!("failed to construct session cookie: {error}"),
        }
    }

    response
}
