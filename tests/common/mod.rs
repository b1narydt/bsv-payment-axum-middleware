#![allow(dead_code)]

pub mod mock_wallet;
pub mod test_server;

pub use mock_wallet::MockWallet;
pub use test_server::get_server_url;

use std::sync::Once;

static INIT_TRACING: Once = Once::new();

pub fn init_tracing() {
    INIT_TRACING.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with_test_writer()
            .try_init();
    });
}
