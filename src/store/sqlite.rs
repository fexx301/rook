use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Row, params, types::Type};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

use crate::store::{CatchRow, RequestRow, Session, Stats};

#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SessionScore {
    pub probability: f64,
    pub is_agent: bool,
}

fn invalid_text<E>(column: usize, error: E) -> rusqlite::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
}

fn session_from_row(row: &Row<'_>) -> rusqlite::Result<Session> {
    let id: String = row.get(0)?;
    let created_at: String = row.get(5)?;
    let last_seen_at: String = row.get(6)?;

    Ok(Session {
        id: Uuid::parse_str(&id).map_err(|error| invalid_text(0, error))?,
        cookie_id: row.get(1)?,
        honeypot_token: row.get(2)?,
        first_ip: row.get(3)?,
        first_user_agent: row.get(4)?,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .map_err(|error| invalid_text(5, error))?
            .with_timezone(&Utc),
        last_seen_at: DateTime::parse_from_rfc3339(&last_seen_at)
            .map_err(|error| invalid_text(6, error))?
            .with_timezone(&Utc),
        request_count: row.get(7)?,
        agent_probability: row.get(8)?,
        is_agent: row.get::<_, i32>(9)? != 0,
    })
}

fn request_from_row(row: &Row<'_>) -> rusqlite::Result<RequestRow> {
    let timestamp: String = row.get(1)?;
    Ok(RequestRow {
        id: row.get(0)?,
        timestamp: DateTime::parse_from_rfc3339(&timestamp)
            .map_err(|error| invalid_text(1, error))?
            .with_timezone(&Utc),
        method: row.get(2)?,
        path: row.get(3)?,
        query: row.get(4)?,
        status_code: row.get(5)?,
        user_agent: row.get(6)?,
        ip: row.get(7)?,
        signals_json: row.get(8)?,
        score_delta: row.get(9)?,
    })
}

fn catch_from_row(row: &Row<'_>) -> rusqlite::Result<CatchRow> {
    let timestamp: String = row.get(1)?;
    let session_id: String = row.get(2)?;
    Ok(CatchRow {
        id: row.get(0)?,
        timestamp: DateTime::parse_from_rfc3339(&timestamp)
            .map_err(|error| invalid_text(1, error))?
            .with_timezone(&Utc),
        session_id: Uuid::parse_str(&session_id).map_err(|error| invalid_text(2, error))?,
        payload_id: row.get(3)?,
        payload_kind: row.get(4)?,
        canary: row.get(5)?,
        leaked_text: row.get(6)?,
    })
}

impl SqliteStore {
    /// Open (or create) the SQLite database and run migrations.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open sqlite database at {path}"))?;
        conn.busy_timeout(Duration::from_secs(5))
            .context("failed to configure sqlite busy timeout")?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("failed to enable sqlite foreign keys")?;
        if path != ":memory:" {
            conn.pragma_update(None, "journal_mode", "WAL")
                .context("failed to enable sqlite WAL mode")?;
            conn.pragma_update(None, "synchronous", "NORMAL")
                .context("failed to configure sqlite synchronous mode")?;
        }
        conn.execute_batch(include_str!("../../migrations/schema.sql"))
            .context("failed to run database migrations")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock_conn(conn: &Mutex<Connection>) -> Result<std::sync::MutexGuard<'_, Connection>> {
        conn.lock()
            .map_err(|e| anyhow::anyhow!("database mutex poisoned: {e}"))
    }

    pub async fn create_session(&self, ip: &str, ua: &str) -> Result<Session> {
        let conn = self.conn.clone();
        let session = Session::new(ip, ua);

        tokio::task::spawn_blocking(move || {
            let conn = Self::lock_conn(&conn)?;

            conn.execute(
                "INSERT INTO sessions
                 (id, cookie_id, honeypot_token, first_ip, first_user_agent, created_at, last_seen_at, request_count, agent_probability, is_agent)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0.0, 0)",
                params![
                    session.id.to_string(),
                    &session.cookie_id,
                    &session.honeypot_token,
                    &session.first_ip,
                    &session.first_user_agent,
                    session.created_at.to_rfc3339(),
                    session.last_seen_at.to_rfc3339(),
                ],
            )
            .context("failed to insert session")?;

            Ok(session)
        })
        .await?
    }

    pub async fn get_session_by_cookie(&self, cookie_id: &str) -> Result<Option<Session>> {
        let conn = self.conn.clone();
        let cookie_id = cookie_id.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = Self::lock_conn(&conn)?;
            conn.query_row(
                "SELECT id, cookie_id, honeypot_token, first_ip, first_user_agent, created_at,
                            last_seen_at, request_count, agent_probability, is_agent
                     FROM sessions WHERE cookie_id = ?1",
                params![&cookie_id],
                session_from_row,
            )
            .optional()
            .context("failed to query session by cookie")
        })
        .await?
    }

    pub async fn record_request(
        &self,
        session_id: &Uuid,
        method: &str,
        path: &str,
        query: Option<&str>,
        user_agent: Option<&str>,
        ip: Option<&str>,
    ) -> Result<i64> {
        let conn = self.conn.clone();
        let session_id = session_id.to_string();
        let method = method.to_string();
        let path = path.to_string();
        let query = query.map(str::to_string);
        let user_agent = user_agent.map(str::to_string);
        let ip = ip.map(str::to_string);
        let now = Utc::now().to_rfc3339();

        tokio::task::spawn_blocking(move || {
            let mut conn = Self::lock_conn(&conn)?;
            let transaction = conn
                .transaction()
                .context("failed to begin request transaction")?;

            let updated = transaction
                .execute(
                "UPDATE sessions SET request_count = request_count + 1, last_seen_at = ?1 WHERE id = ?2",
                params![&now, &session_id],
            )
            .context("failed to update session request count")?;
            if updated != 1 {
                anyhow::bail!("cannot record a request for missing session {session_id}");
            }

            transaction.execute(
                "INSERT INTO requests
                 (session_id, timestamp, method, path, query, user_agent, ip)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &session_id,
                    &now,
                    &method,
                    &path,
                    query,
                    user_agent,
                    ip,
                ],
            )
            .context("failed to insert request")?;

            let request_id = transaction.last_insert_rowid();
            transaction
                .commit()
                .context("failed to commit request transaction")?;
            Ok(request_id)
        })
        .await?
    }

    pub async fn update_request_status(&self, request_id: i64, status_code: u16) -> Result<()> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Self::lock_conn(&conn)?;
            let updated = conn
                .execute(
                    "UPDATE requests SET status_code = ?1 WHERE id = ?2",
                    params![status_code, request_id],
                )
                .context("failed to store request status")?;
            if updated != 1 {
                anyhow::bail!("request {request_id} no longer exists");
            }
            Ok(())
        })
        .await?
    }

    pub async fn record_signals(
        &self,
        session_id: &Uuid,
        request_id: i64,
        signals: &[(String, f64)],
        agent_threshold: f64,
    ) -> Result<SessionScore> {
        let conn = self.conn.clone();
        let session_id = session_id.to_string();
        let signals_json =
            serde_json::to_string(signals).context("failed to serialize detection signals")?;
        let total_score: f64 = signals.iter().map(|(_, w)| w).sum();

        tokio::task::spawn_blocking(move || {
            let mut conn = Self::lock_conn(&conn)?;
            let transaction = conn
                .transaction()
                .context("failed to begin signal transaction")?;

            let request_updated = transaction
                .execute(
                    "UPDATE requests
                     SET signals_json = ?1, score_delta = ?2
                     WHERE id = ?3 AND session_id = ?4",
                    params![&signals_json, total_score, request_id, &session_id],
                )
                .context("failed to store request signals")?;
            if request_updated != 1 {
                anyhow::bail!("request {request_id} does not belong to session {session_id}");
            }

            let session_updated = transaction
                .execute(
                    "UPDATE sessions
                     SET is_agent = CASE
                             WHEN MIN(1.0, agent_probability + ?1) >= ?2 THEN 1
                             ELSE is_agent
                         END,
                         agent_probability = MIN(1.0, agent_probability + ?1)
                     WHERE id = ?3",
                    params![total_score, agent_threshold, &session_id],
                )
                .context("failed to update session score")?;
            if session_updated != 1 {
                anyhow::bail!("session {session_id} no longer exists");
            }

            let score = transaction
                .query_row(
                    "SELECT agent_probability, is_agent FROM sessions WHERE id = ?1",
                    params![&session_id],
                    |row| {
                        Ok(SessionScore {
                            probability: row.get(0)?,
                            is_agent: row.get::<_, i32>(1)? != 0,
                        })
                    },
                )
                .context("failed to read updated session score")?;

            transaction
                .commit()
                .context("failed to commit signal transaction")?;
            Ok(score)
        })
        .await?
    }

    pub async fn list_sessions(&self, limit: u32) -> Result<Vec<Session>> {
        let conn = self.conn.clone();

        tokio::task::spawn_blocking(move || {
            let conn = Self::lock_conn(&conn)?;
            let mut stmt = conn.prepare(
                "SELECT id, cookie_id, honeypot_token, first_ip, first_user_agent, created_at,
                        last_seen_at, request_count, agent_probability, is_agent
                 FROM sessions ORDER BY last_seen_at DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit], session_from_row)?;

            let mut sessions = Vec::new();
            for row in rows {
                sessions.push(row?);
            }
            Ok(sessions)
        })
        .await?
    }

    pub async fn get_session_requests(&self, session_id: &Uuid) -> Result<Vec<RequestRow>> {
        let conn = self.conn.clone();
        let session_id = session_id.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = Self::lock_conn(&conn)?;
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, method, path, query, status_code, user_agent, ip,
                        signals_json, score_delta
                 FROM requests WHERE session_id = ?1 ORDER BY timestamp DESC LIMIT 100",
            )?;
            let rows = stmt.query_map(params![&session_id], request_from_row)?;

            let mut requests = Vec::new();
            for row in rows {
                requests.push(row?);
            }
            Ok(requests)
        })
        .await?
    }

    pub async fn get_session_catches(&self, session_id: &Uuid) -> Result<Vec<CatchRow>> {
        let conn = self.conn.clone();
        let session_id = session_id.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = Self::lock_conn(&conn)?;
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, session_id, payload_id, payload_kind, canary, leaked_text
                 FROM catches WHERE session_id = ?1 ORDER BY timestamp DESC LIMIT 100",
            )?;
            let rows = stmt.query_map(params![&session_id], catch_from_row)?;

            let mut catches = Vec::new();
            for row in rows {
                catches.push(row?);
            }
            Ok(catches)
        })
        .await?
    }

    pub async fn get_stats(&self) -> Result<Stats> {
        let conn = self.conn.clone();

        tokio::task::spawn_blocking(move || {
            let conn = Self::lock_conn(&conn)?;
            let total_sessions: i64 = conn
                .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
                .context("failed to count sessions")?;
            let agent_sessions: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sessions WHERE is_agent = 1",
                    [],
                    |row| row.get(0),
                )
                .context("failed to count agent sessions")?;
            let total_requests: i64 = conn
                .query_row("SELECT COUNT(*) FROM requests", [], |row| row.get(0))
                .context("failed to count requests")?;
            let total_catches: i64 = conn
                .query_row("SELECT COUNT(*) FROM catches", [], |row| row.get(0))
                .context("failed to count catches")?;
            Ok(Stats {
                total_sessions,
                agent_sessions,
                total_requests,
                total_catches,
            })
        })
        .await?
    }

    pub async fn get_session_by_id(&self, id: &Uuid) -> Result<Option<Session>> {
        let conn = self.conn.clone();
        let id = id.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = Self::lock_conn(&conn)?;
            conn.query_row(
                "SELECT id, cookie_id, honeypot_token, first_ip, first_user_agent, created_at,
                            last_seen_at, request_count, agent_probability, is_agent
                     FROM sessions WHERE id = ?1",
                params![&id],
                session_from_row,
            )
            .optional()
            .context("failed to query session by id")
        })
        .await?
    }

    pub async fn record_catch(
        &self,
        session_id: &Uuid,
        request_id: Option<i64>,
        payload_id: &str,
        payload_kind: &str,
        canary: &str,
        leaked_text: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.clone();
        let session_id = session_id.to_string();
        let payload_id = payload_id.to_string();
        let payload_kind = payload_kind.to_string();
        let canary = canary.to_string();
        let leaked_text = leaked_text.map(|s| s.to_string());
        let now = Utc::now().to_rfc3339();

        tokio::task::spawn_blocking(move || {
            let conn = Self::lock_conn(&conn)?;
            conn.execute(
                "INSERT INTO catches (session_id, request_id, timestamp, payload_id, payload_kind, canary, leaked_text)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &session_id,
                    request_id,
                    &now,
                    &payload_id,
                    &payload_kind,
                    &canary,
                    leaked_text,
                ],
            )
            .context("failed to insert catch")?;
            Ok(())
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn persists_request_metadata_status_and_score() {
        let store = SqliteStore::open(":memory:").expect("in-memory store should open");
        let session = store
            .create_session("127.0.0.1", "test-agent")
            .await
            .expect("session should be created");
        let request_id = store
            .record_request(
                &session.id,
                "GET",
                "/search",
                Some("q=canary"),
                Some("test-agent"),
                Some("127.0.0.1"),
            )
            .await
            .expect("request should be recorded");

        let score = store
            .record_signals(&session.id, request_id, &[("signal".to_string(), 0.6)], 0.5)
            .await
            .expect("signals should be recorded");
        store
            .update_request_status(request_id, 200)
            .await
            .expect("status should be recorded");

        assert_eq!(
            score,
            SessionScore {
                probability: 0.6,
                is_agent: true,
            }
        );
        let requests = store
            .get_session_requests(&session.id)
            .await
            .expect("requests should load");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].query.as_deref(), Some("q=canary"));
        assert_eq!(requests[0].status_code, Some(200));
        assert_eq!(requests[0].user_agent.as_deref(), Some("test-agent"));
        assert_eq!(requests[0].ip.as_deref(), Some("127.0.0.1"));
        assert!((requests[0].score_delta - 0.6).abs() < f64::EPSILON);

        let updated_session = store
            .get_session_by_id(&session.id)
            .await
            .expect("session query should succeed")
            .expect("session should exist");
        assert_eq!(updated_session.request_count, 1);
        assert!(updated_session.is_agent);
    }

    #[tokio::test]
    async fn rejects_requests_for_missing_sessions_without_partial_writes() {
        let store = SqliteStore::open(":memory:").expect("in-memory store should open");

        let result = store
            .record_request(&Uuid::new_v4(), "GET", "/", None, None, None)
            .await;

        assert!(result.is_err());
        let stats = store.get_stats().await.expect("stats should load");
        assert_eq!(stats.total_requests, 0);
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        let store = SqliteStore::open(":memory:").expect("in-memory store should open");

        let result = store
            .record_catch(
                &Uuid::new_v4(),
                None,
                "test",
                "test",
                "FS-00000000000000000000000000000000",
                None,
            )
            .await;

        assert!(result.is_err());
    }
}
