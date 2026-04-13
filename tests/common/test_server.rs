//! In-process axum server bootstrapper for integration tests.
//!
//! Stacks AuthLayer (bsv-auth-axum-middleware) and PaymentLayer (this crate)
//! on a real in-process axum server. A single process-wide instance is shared
//! across all integration test binaries that include this module.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use bsv::auth::peer::Peer;
use bsv::primitives::private_key::PrivateKey;
use bsv_auth_axum_middleware::{ActixTransport, AuthLayer, AuthMiddlewareConfigBuilder, Authenticated};
use bsv_payment_axum_middleware::{Paid, PaymentLayer, PaymentMiddlewareConfigBuilder};
use tokio::net::TcpListener;
use tokio::sync::OnceCell;

use super::mock_wallet::MockWallet;

static TEST_SERVER_URL: OnceCell<String> = OnceCell::const_new();

/// Return the base URL of a process-wide, lazily-started axum test server.
pub async fn get_server_url() -> &'static str {
    super::init_tracing();
    TEST_SERVER_URL
        .get_or_init(|| async { create_test_server().await })
        .await
}

async fn create_test_server() -> String {
    // Bind the port *now* in the current async context so the port is reserved
    // before we return the URL.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    listener.set_nonblocking(true).expect("set_nonblocking");
    let addr: SocketAddr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{}", addr);

    let server_key = PrivateKey::from_random().expect("failed to generate server key");
    let server_wallet = MockWallet::new(server_key);

    // Auth layer — mirror auth-axum's test_server.rs setup exactly.
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(tokio::sync::Mutex::new(Peer::new(
        server_wallet.clone(),
        transport.clone(),
    )));

    let auth_config = AuthMiddlewareConfigBuilder::new()
        .wallet(server_wallet.clone())
        .allow_unauthenticated(false)
        .build()
        .expect("failed to build auth middleware config");

    let auth_layer = AuthLayer::from_config(auth_config, peer.clone(), transport.clone()).await;

    // Payment layer.
    let pay_config = PaymentMiddlewareConfigBuilder::new()
        .wallet(server_wallet)
        .calculate_request_price(|parts| {
            let path = parts.uri.path().to_string();
            Box::pin(async move {
                match path.as_str() {
                    "/free" => 0,
                    "/expensive" => 1000,
                    "/panic" => panic!("intentional price panic"),
                    _ => 10,
                }
            })
        })
        .build()
        .expect("failed to build payment middleware config");

    let pay_layer = PaymentLayer::from_config(pay_config);

    let app = Router::new()
        .route("/weather", get(weather_handler))
        .route("/free", get(free_handler))
        .route("/expensive", get(expensive_handler))
        .route("/panic", get(weather_handler))
        .route("/echo-paid", get(echo_paid_handler))
        .layer(pay_layer)
        .layer(auth_layer);

    println!("Payment test server started at {}", base_url);

    // Spawn a dedicated background thread with its own Tokio runtime.
    // The thread is leaked (never joined) so the server lives for the process
    // lifetime, matching the auth-axum pattern.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("create server runtime");
        rt.block_on(async move {
            let tokio_listener =
                TcpListener::from_std(listener).expect("convert to tokio listener");
            axum::serve(tokio_listener, app)
                .await
                .expect("test server serve");
        });
    });

    base_url
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

async fn weather_handler(_auth: Authenticated, _paid: Paid) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "temp_f": 72 }))
}

async fn free_handler(_auth: Authenticated, paid: Paid) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "satoshisPaid": paid.satoshis_paid,
        "hasTx": paid.tx_base64.is_some(),
    }))
}

async fn expensive_handler(_auth: Authenticated, paid: Paid) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "satoshisPaid": paid.satoshis_paid }))
}

async fn echo_paid_handler(_auth: Authenticated, paid: Paid) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "satoshisPaid": paid.satoshis_paid,
        "accepted": paid.accepted,
        "hasTx": paid.tx_base64.is_some(),
    }))
}
