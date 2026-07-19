pub mod sqlite;

pub use sqlite::SqliteStore;

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Session {
    pub id: Uuid,
    pub cookie_id: String,
    pub honeypot_token: String,
    pub first_ip: Option<String>,
    pub first_user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub request_count: u32,
    pub agent_probability: f64,
    pub is_agent: bool,
}

impl Session {
    /// Build a brand-new, unsaved session.
    pub fn new(ip: &str, ua: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            cookie_id: Uuid::new_v4().to_string(),
            honeypot_token: Uuid::new_v4().to_string(),
            first_ip: Some(ip.to_string()),
            first_user_agent: Some(ua.to_string()),
            created_at: Utc::now(),
            last_seen_at: Utc::now(),
            request_count: 0,
            agent_probability: 0.0,
            is_agent: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RequestRow {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub status_code: Option<u16>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub signals_json: Option<String>,
    pub score_delta: f64,
}

#[derive(Clone, Debug)]
pub struct CatchRow {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub session_id: Uuid,
    pub payload_id: String,
    pub payload_kind: String,
    pub canary: String,
    pub leaked_text: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub total_sessions: i64,
    pub agent_sessions: i64,
    pub total_requests: i64,
    pub total_catches: i64,
}
