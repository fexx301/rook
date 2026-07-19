use tracing_subscriber::EnvFilter;

/// Initialise structured tracing. Respects `RUST_LOG` if set; otherwise uses
/// a sensible default that keeps Rook itself at `debug` and the rest at `info`.
pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,rook=debug,tower_http=info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();
}
