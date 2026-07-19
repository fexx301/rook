use serde::Deserialize;
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;

pub const DEFAULT_DASHBOARD_TOKEN: &str = "rook-demo-token-change-me";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub dashboard: DashboardConfig,
    pub persona: PersonaConfig,
    pub detection: DetectionConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub secure_cookies: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfig {
    pub path: String,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaConfig {
    pub name: String,
    pub tagline: String,
    pub domain: String,
    pub blog_posts: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionConfig {
    pub agent_threshold: f64,
    pub weights: Weights,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weights {
    pub missing_sec_fetch: f64,
    pub missing_accept_language: f64,
    pub suspicious_user_agent: f64,
    pub followed_honeypot_link: f64,
    pub missing_js_canary: f64,
    pub machine_speed_requests: f64,
    pub accessed_robots_txt: f64,
    pub accessed_sitemap: f64,
}

fn optional_env_var_with_legacy(
    primary: &'static str,
    legacy: &'static str,
) -> Result<Option<String>, std::env::VarError> {
    match std::env::var(primary) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => match std::env::var(legacy) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("environment variable {name} must contain valid Unicode: {source}")]
    Environment {
        name: &'static str,
        source: std::env::VarError,
    },
    #[error("invalid configuration: {0}")]
    Validation(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_str(&contents)
    }

    pub fn from_str(contents: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(contents)?)
    }

    /// Apply deployment secrets that should not need to live in `config.toml`.
    pub fn with_environment_overrides(mut self) -> Result<Self, ConfigError> {
        match optional_env_var_with_legacy("ROOK_DASHBOARD_TOKEN", "AGENTSBANE_DASHBOARD_TOKEN") {
            Ok(Some(token)) => self.dashboard.token = token,
            Ok(None) => {}
            Err(source) => {
                return Err(ConfigError::Environment {
                    name: "ROOK_DASHBOARD_TOKEN",
                    source,
                });
            }
        }
        match optional_env_var_with_legacy("ROOK_DATABASE_PATH", "AGENTSBANE_DATABASE_PATH") {
            Ok(Some(path)) => self.database.path = path,
            Ok(None) => {}
            Err(source) => {
                return Err(ConfigError::Environment {
                    name: "ROOK_DATABASE_PATH",
                    source,
                });
            }
        }
        Ok(self)
    }

    /// Normalize path-like values and reject unsafe or nonsensical settings.
    pub fn validate(mut self) -> Result<Self, ConfigError> {
        let invalid = |message: &str| ConfigError::Validation(message.to_string());

        if self.server.host.trim().is_empty() || self.server.host.chars().any(char::is_whitespace) {
            return Err(invalid(
                "server.host must be a non-empty host name or IP address",
            ));
        }
        if self.database.path.trim().is_empty() {
            return Err(invalid("database.path must not be empty"));
        }

        let raw_path = self.dashboard.path.trim();
        if raw_path.is_empty() {
            return Err(invalid("dashboard.path must not be empty"));
        }
        let mut dashboard_path = if raw_path.starts_with('/') {
            raw_path.to_string()
        } else {
            format!("/{raw_path}")
        };
        while dashboard_path.len() > 1 && dashboard_path.ends_with('/') {
            dashboard_path.pop();
        }
        if dashboard_path == "/"
            || dashboard_path.contains("//")
            || !dashboard_path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_'))
        {
            return Err(invalid(
                "dashboard.path must be a non-root URL path containing only letters, numbers, '/', '-' or '_'",
            ));
        }
        let first_segment = dashboard_path
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or_default();
        if [
            "blog",
            "docs",
            "pricing",
            "robots.txt",
            "sitemap.xml",
            "favicon.ico",
            "health",
            "static",
            "h",
            "continue",
        ]
        .contains(&first_segment)
        {
            return Err(invalid(
                "dashboard.path must not overlap a public or operational route",
            ));
        }
        self.dashboard.path = dashboard_path;

        if self.dashboard.token.len() < 16 {
            return Err(invalid("dashboard.token must be at least 16 characters"));
        }
        if !is_loopback_host(&self.server.host) && self.dashboard.token == DEFAULT_DASHBOARD_TOKEN {
            return Err(invalid(
                "the demo dashboard token cannot be used on a non-loopback server; set ROOK_DASHBOARD_TOKEN",
            ));
        }

        if self.persona.name.trim().is_empty() || self.persona.tagline.trim().is_empty() {
            return Err(invalid(
                "persona.name and persona.tagline must not be empty",
            ));
        }
        if self.persona.domain.trim().is_empty()
            || self.persona.domain.contains("://")
            || self.persona.domain.contains('/')
            || self.persona.domain.chars().any(char::is_whitespace)
            || !self
                .persona
                .domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        {
            return Err(invalid(
                "persona.domain must be a host name without a scheme, path, or whitespace",
            ));
        }
        if self.persona.blog_posts == 0 {
            return Err(invalid("persona.blog_posts must be greater than zero"));
        }

        if !self.detection.agent_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.detection.agent_threshold)
            || self.detection.agent_threshold == 0.0
        {
            return Err(invalid(
                "detection.agent_threshold must be greater than 0 and at most 1",
            ));
        }
        for (name, weight) in self.detection.weights.named_values() {
            if !weight.is_finite() || !(0.0..=1.0).contains(&weight) {
                return Err(invalid(&format!(
                    "detection.weights.{name} must be between 0 and 1"
                )));
            }
        }

        Ok(self)
    }

    /// The full bind address, e.g. "127.0.0.1:7878".
    pub fn bind_addr(&self) -> String {
        let host = self.server.host.trim_matches(|c| matches!(c, '[' | ']'));
        match host.parse::<IpAddr>() {
            Ok(ip) => std::net::SocketAddr::new(ip, self.server.port).to_string(),
            Err(_) => format!("{}:{}", self.server.host, self.server.port),
        }
    }
}

impl Weights {
    fn named_values(&self) -> [(&'static str, f64); 8] {
        [
            ("missing_sec_fetch", self.missing_sec_fetch),
            ("missing_accept_language", self.missing_accept_language),
            ("suspicious_user_agent", self.suspicious_user_agent),
            ("followed_honeypot_link", self.followed_honeypot_link),
            ("missing_js_canary", self.missing_js_canary),
            ("machine_speed_requests", self.machine_speed_requests),
            ("accessed_robots_txt", self.accessed_robots_txt),
            ("accessed_sitemap", self.accessed_sitemap),
        ]
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(|c| matches!(c, '[' | ']'));
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 7788,
                secure_cookies: false,
            },
            database: DatabaseConfig {
                path: "rook.db".to_string(),
            },
            dashboard: DashboardConfig {
                path: "/__rook__".to_string(),
                token: DEFAULT_DASHBOARD_TOKEN.to_string(),
            },
            persona: PersonaConfig {
                name: "FrameShift".to_string(),
                tagline: "Developer tools that bend reality.".to_string(),
                domain: "frameshift.dev".to_string(),
                blog_posts: 4,
            },
            detection: DetectionConfig {
                agent_threshold: 0.5,
                weights: Weights {
                    missing_sec_fetch: 0.20,
                    missing_accept_language: 0.10,
                    suspicious_user_agent: 0.25,
                    followed_honeypot_link: 0.45,
                    missing_js_canary: 0.20,
                    machine_speed_requests: 0.20,
                    accessed_robots_txt: 0.05,
                    accessed_sitemap: 0.05,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let toml = r#"
[server]
host = "0.0.0.0"
port = 9999

[database]
path = "test.db"

[dashboard]
path = "/secret"
token = "a-long-test-token"

[persona]
name = "TestCo"
tagline = "We test."
domain = "test.example"
blog_posts = 2

[detection]
agent_threshold = 0.7

[detection.weights]
missing_sec_fetch = 0.1
missing_accept_language = 0.1
suspicious_user_agent = 0.2
followed_honeypot_link = 0.4
missing_js_canary = 0.2
machine_speed_requests = 0.2
accessed_robots_txt = 0.05
accessed_sitemap = 0.05
"#;
        let cfg = Config::from_str(toml)
            .and_then(Config::validate)
            .expect("config should parse");
        assert_eq!(cfg.server.port, 9999);
        assert!(!cfg.server.secure_cookies);
        assert_eq!(cfg.persona.name, "TestCo");
        assert_eq!(cfg.bind_addr(), "0.0.0.0:9999");
        assert!((cfg.detection.agent_threshold - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn normalizes_dashboard_path_and_ipv6_address() {
        let mut cfg = Config::default();
        cfg.server.host = "::1".to_string();
        cfg.dashboard.path = "secret/".to_string();

        let cfg = cfg.validate().expect("config should be valid");

        assert_eq!(cfg.dashboard.path, "/secret");
        assert_eq!(cfg.bind_addr(), "[::1]:7788");
    }

    #[test]
    fn rejects_demo_token_on_public_bind_address() {
        let mut cfg = Config::default();
        cfg.server.host = "0.0.0.0".to_string();

        let error = cfg.validate().expect_err("demo token must be rejected");

        assert!(error.to_string().contains("demo dashboard token"));
    }

    #[test]
    fn rejects_invalid_detection_weights() {
        let mut cfg = Config::default();
        cfg.detection.weights.missing_js_canary = -0.1;

        let error = cfg
            .validate()
            .expect_err("negative weight must be rejected");

        assert!(error.to_string().contains("missing_js_canary"));
    }

    #[test]
    fn rejects_dashboard_paths_that_overlap_public_routes() {
        let mut cfg = Config::default();
        cfg.dashboard.path = "/health".to_string();

        let error = cfg
            .validate()
            .expect_err("overlapping dashboard path must be rejected");

        assert!(error.to_string().contains("must not overlap"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let invalid = "unexpected = true";

        assert!(Config::from_str(invalid).is_err());
    }
}
