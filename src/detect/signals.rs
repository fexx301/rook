use axum::http::HeaderMap;
use chrono::{DateTime, TimeDelta, Utc};
use regex::Regex;
use std::sync::LazyLock;

use crate::config::DetectionConfig;
use crate::store::Session;

static SUSPICIOUS_UA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(bot|crawler|spider|scrape|httpclient|urllib|wget|curl|python-requests|go-http|node-fetch|httpx)",
    )
    .expect("the suspicious user-agent regex is valid")
});

/// Routes that should remain operational but must not alter a visitor's score.
pub fn is_untracked_path(path: &str) -> bool {
    path == "/health" || path == "/favicon.ico" || path == "/static" || path.starts_with("/static/")
}

/// Extract a named cookie value from raw request headers.
pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{}=", name);
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|header| {
            header.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix(&prefix).map(|s| s.to_string())
            })
        })
}

/// Inspect the current request and session, returning a list of detected
/// signals and their configured weights.
pub fn extract_signals(
    headers: &HeaderMap,
    path: &str,
    session: &Session,
    config: &DetectionConfig,
    now: DateTime<Utc>,
) -> Vec<(String, f64)> {
    let mut signals = Vec::new();

    if is_untracked_path(path) {
        return signals;
    }

    // Header-based signals.
    if headers.get("sec-fetch-site").is_none()
        && headers.get("sec-fetch-mode").is_none()
        && headers.get("sec-fetch-dest").is_none()
    {
        signals.push((
            "missing_sec_fetch".to_string(),
            config.weights.missing_sec_fetch,
        ));
    }

    if headers.get("accept-language").is_none() {
        signals.push((
            "missing_accept_language".to_string(),
            config.weights.missing_accept_language,
        ));
    }

    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if SUSPICIOUS_UA_RE.is_match(ua) || ua.is_empty() || ua == "unknown" {
        signals.push((
            "suspicious_user_agent".to_string(),
            config.weights.suspicious_user_agent,
        ));
    }

    // Give the first page response a chance to execute site.js before treating
    // the missing cookie as evidence. This avoids scoring normal first visits.
    if session.request_count > 0 && extract_cookie(headers, "_fs_js").is_none() {
        signals.push((
            "missing_js_canary".to_string(),
            config.weights.missing_js_canary,
        ));
    }

    // Machine-speed: requests separated by <500ms are unlikely to be human.
    if session.request_count > 0 {
        let elapsed = now.signed_duration_since(session.last_seen_at);
        if elapsed >= TimeDelta::zero() && elapsed.num_milliseconds() < 500 {
            signals.push((
                "machine_speed_requests".to_string(),
                config.weights.machine_speed_requests,
            ));
        }
    }

    // Honeypot link: only the current session knows its token.
    if path == format!("/h/{}", session.honeypot_token) {
        signals.push((
            "followed_honeypot_link".to_string(),
            config.weights.followed_honeypot_link,
        ));
    }

    if path == "/robots.txt" {
        signals.push((
            "accessed_robots_txt".to_string(),
            config.weights.accessed_robots_txt,
        ));
    }

    if path == "/sitemap.xml" {
        signals.push((
            "accessed_sitemap".to_string(),
            config.weights.accessed_sitemap,
        ));
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::http::{HeaderMap, HeaderValue};

    fn browser_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
        );
        headers.insert(
            "accept-language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        headers
    }

    #[test]
    fn first_browser_navigation_is_not_penalized_for_missing_js_cookie() {
        let session = Session::new("127.0.0.1", "Mozilla/5.0");
        let config = Config::default();

        let signals = extract_signals(
            &browser_headers(),
            "/",
            &session,
            &config.detection,
            Utc::now(),
        );

        assert!(signals.is_empty());
    }

    #[test]
    fn later_navigation_without_js_cookie_is_detected() {
        let mut session = Session::new("127.0.0.1", "Mozilla/5.0");
        session.request_count = 1;
        session.last_seen_at = Utc::now() - TimeDelta::seconds(2);
        let config = Config::default();

        let signals = extract_signals(
            &browser_headers(),
            "/blog",
            &session,
            &config.detection,
            Utc::now(),
        );

        assert!(signals.iter().any(|(name, _)| name == "missing_js_canary"));
        assert!(
            !signals
                .iter()
                .any(|(name, _)| name == "machine_speed_requests")
        );
    }

    #[test]
    fn operational_routes_do_not_affect_scoring() {
        let mut session = Session::new("127.0.0.1", "curl/8");
        session.request_count = 3;
        let config = Config::default();

        for path in ["/health", "/favicon.ico", "/static", "/static/site.css"] {
            assert!(
                extract_signals(
                    &HeaderMap::new(),
                    path,
                    &session,
                    &config.detection,
                    Utc::now(),
                )
                .is_empty()
            );
        }
    }

    #[test]
    fn discovery_and_honeypot_routes_emit_their_specific_signals() {
        let session = Session::new("127.0.0.1", "curl/8");
        let config = Config::default();

        let robots = extract_signals(
            &HeaderMap::new(),
            "/robots.txt",
            &session,
            &config.detection,
            Utc::now(),
        );
        assert!(robots.iter().any(|(name, _)| name == "accessed_robots_txt"));

        let honeypot_path = format!("/h/{}", session.honeypot_token);
        let honeypot = extract_signals(
            &HeaderMap::new(),
            &honeypot_path,
            &session,
            &config.detection,
            Utc::now(),
        );
        assert!(
            honeypot
                .iter()
                .any(|(name, _)| name == "followed_honeypot_link")
        );
    }
}
