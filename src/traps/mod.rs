pub mod payloads;

use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;
use std::sync::{Arc, LazyLock, RwLock};
use uuid::Uuid;

use crate::store::Session;

pub const MAX_INDEXED_SESSIONS: usize = 10_000;

static CANARY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"FS-[0-9a-f]{32}").expect("the canary extraction regex is valid"));
static HONEYPOT_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/h/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
        .expect("the honeypot token extraction regex is valid")
});

/// Generate a deterministic, cryptographically hard-to-guess canary for a
/// session + payload. The random session UUID supplies the secret entropy.
pub fn canary_for(session_id: &Uuid, payload_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update([0]);
    hasher.update(payload_id.as_bytes());
    let digest = hasher.finalize();

    let mut canary = String::with_capacity(35);
    canary.push_str("FS-");
    for byte in &digest[..16] {
        write!(&mut canary, "{byte:02x}").expect("writing to a String cannot fail");
    }
    canary
}

/// Metadata attached to a canary so a catch can be attributed.
#[derive(Clone)]
pub struct CanaryInfo {
    pub session_id: Uuid,
    pub payload_id: String,
    pub payload_kind: String,
    pub canary: String,
}

/// In-memory index of all active canaries. Populated on startup and when new
/// sessions are created.
#[derive(Clone)]
pub struct CanaryIndex {
    state: Arc<RwLock<CanaryIndexState>>,
    max_sessions: usize,
}

#[derive(Default)]
struct CanaryIndexState {
    map: HashMap<String, CanaryInfo>,
    session_ids: HashSet<Uuid>,
    order: VecDeque<(Uuid, Vec<String>)>,
}

impl CanaryIndex {
    pub fn new() -> Self {
        Self::with_capacity(MAX_INDEXED_SESSIONS)
    }

    fn with_capacity(max_sessions: usize) -> Self {
        Self {
            state: Arc::new(RwLock::new(CanaryIndexState::default())),
            max_sessions,
        }
    }

    /// Register all canaries for a session.
    pub fn add_session(&self, session: &Session) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if state.session_ids.contains(&session.id) {
            return;
        }

        let mut keys = Vec::with_capacity(payloads::all().len() + 1);
        for payload in payloads::all() {
            let canary = canary_for(&session.id, payload.id);
            keys.push(canary.clone());
            state.map.insert(
                canary.clone(),
                CanaryInfo {
                    session_id: session.id,
                    payload_id: payload.id.to_string(),
                    payload_kind: payload.kind.to_string(),
                    canary,
                },
            );
        }
        keys.push(session.honeypot_token.clone());
        state.map.insert(
            session.honeypot_token.clone(),
            CanaryInfo {
                session_id: session.id,
                payload_id: "honeypot_link".to_string(),
                payload_kind: "hidden_link".to_string(),
                canary: session.honeypot_token.clone(),
            },
        );
        state.session_ids.insert(session.id);
        state.order.push_back((session.id, keys));

        while state.order.len() > self.max_sessions {
            if let Some((session_id, keys)) = state.order.pop_front() {
                state.session_ids.remove(&session_id);
                for key in keys {
                    state.map.remove(&key);
                }
            }
        }
    }

    /// Scan request haystacks for any known canary.
    pub fn scan(&self, haystacks: &[String]) -> Vec<CanaryInfo> {
        let state = self.state.read().unwrap_or_else(|error| error.into_inner());
        let mut seen = HashSet::new();
        let mut matches = Vec::new();

        for haystack in haystacks {
            for candidate in CANARY_RE.find_iter(haystack) {
                let candidate = candidate.as_str();
                if seen.insert(candidate.to_string())
                    && let Some(info) = state.map.get(candidate)
                {
                    matches.push(info.clone());
                }
            }
            for captures in HONEYPOT_TOKEN_RE.captures_iter(haystack) {
                let candidate = captures
                    .get(1)
                    .expect("the honeypot regex always has a capture")
                    .as_str();
                if seen.insert(candidate.to_string())
                    && let Some(info) = state.map.get(candidate)
                {
                    matches.push(info.clone());
                }
            }
        }

        matches
    }
}

/// HTML-escape a string for safe insertion into attribute values.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Encode a string using zero-width unicode steganography.
/// Each byte is split into four 2-bit values mapped to four zero-width chars.
pub fn zero_width_encode(text: &str) -> String {
    let chars = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'];
    let mut out = String::new();
    for byte in text.bytes() {
        out.push(chars[((byte >> 6) & 0b11) as usize]);
        out.push(chars[((byte >> 4) & 0b11) as usize]);
        out.push(chars[((byte >> 2) & 0b11) as usize]);
        out.push(chars[(byte & 0b11) as usize]);
    }
    out
}

/// Rendered trap fragments ready to be dropped into templates.
pub struct TrapContext {
    pub meta_tag: String,
    pub css_content: String,
    pub data_attribute: String,
    pub html_comment: String,
    pub loop_comment: String,
    pub hidden_span: String,
    pub aria_hidden: String,
    pub zero_width: String,
}

impl TrapContext {
    pub fn build(session: &crate::store::Session) -> Self {
        Self {
            meta_tag: format!(
                r#"<meta name="generator" content="{}">"#,
                html_escape(&payloads::render(&payloads::META_CANARY, session))
            ),
            css_content: {
                let text = payloads::render(&payloads::CSS_CANARY, session);
                format!(
                    r#"<style>.trap::before{{content:'{}';}}</style>"#,
                    text.replace('\\', "\\\\").replace('\'', "\\'")
                )
            },
            data_attribute: format!(
                r#"data-trap="{}""#,
                html_escape(&payloads::render(&payloads::DATA_CANARY, session))
            ),
            html_comment: format!(
                "<!-- {} -->",
                payloads::render(&payloads::CONFESSION, session)
            ),
            loop_comment: format!(
                "<!-- {} -->",
                payloads::render(&payloads::LOOP_TRAP, session)
            ),
            hidden_span: format!(
                r#"<span style="display:none" aria-hidden="true">{}</span>"#,
                html_escape(&payloads::render(&payloads::HIDDEN_CANARY, session))
            ),
            aria_hidden: format!(
                r#"<span aria-hidden="true" class="sr-only">{}</span>"#,
                html_escape(&payloads::render(&payloads::ARIA_CANARY, session))
            ),
            zero_width: zero_width_encode(&payloads::render(&payloads::ZERO_WIDTH_CANARY, session)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn canary_is_deterministic() {
        let sid = Uuid::new_v4();
        let a = canary_for(&sid, "confession");
        let b = canary_for(&sid, "confession");
        assert_eq!(a, b);
        assert!(a.starts_with("FS-"));
        assert_eq!(a.len(), 35);
    }

    #[test]
    fn canary_differs_by_payload() {
        let sid = Uuid::new_v4();
        let a = canary_for(&sid, "confession");
        let b = canary_for(&sid, "hidden_canary");
        assert_ne!(a, b);
    }

    #[test]
    fn index_finds_registered_canaries_without_duplicates() {
        let session = Session::new("127.0.0.1", "test");
        let index = CanaryIndex::new();
        index.add_session(&session);
        let canary = canary_for(&session.id, payloads::CONFESSION.id);

        let found = index.scan(&[format!("{canary} appears twice: {canary}")]);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].session_id, session.id);
        assert_eq!(found[0].payload_id, payloads::CONFESSION.id);
        assert_eq!(found[0].canary, canary);
    }

    #[test]
    fn index_ignores_canary_shaped_values_that_are_not_registered() {
        let index = CanaryIndex::new();

        let found = index.scan(&["FS-00000000000000000000000000000000".to_string()]);

        assert!(found.is_empty());
    }

    #[test]
    fn index_attributes_honeypot_links_to_their_original_session() {
        let session = Session::new("127.0.0.1", "test");
        let index = CanaryIndex::new();
        index.add_session(&session);

        let found = index.scan(&[format!("/h/{}", session.honeypot_token)]);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].session_id, session.id);
        assert_eq!(found[0].payload_id, "honeypot_link");
        assert_eq!(found[0].canary, session.honeypot_token);
    }

    #[test]
    fn index_evicts_the_oldest_session_at_capacity() {
        let first = Session::new("127.0.0.1", "first");
        let second = Session::new("127.0.0.1", "second");
        let index = CanaryIndex::with_capacity(1);
        index.add_session(&first);
        index.add_session(&second);

        let first_canary = canary_for(&first.id, payloads::CONFESSION.id);
        let second_canary = canary_for(&second.id, payloads::CONFESSION.id);

        assert!(index.scan(&[first_canary]).is_empty());
        assert_eq!(index.scan(&[second_canary]).len(), 1);
    }
}
