//! End-to-end integration tests: real axum server, stacked auth + payment
//! middleware, AuthFetch client with manual 402-retry loop.
//!
//! AuthFetch handles BRC-31 mutual authentication automatically. The BSV
//! payment 402 retry is a separate layer: the test receives the 402, reads
//! the derivation-prefix nonce from the response headers, constructs a
//! BsvPaymentHeader JSON, and retries with the `x-bsv-payment` header.
//!
//! The server's MockWallet.internalize_action accepts any payment (test stub),
//! so the transaction field can be any base64 value.

#[path = "common/mod.rs"]
mod common;

use std::collections::HashMap;

use bsv::auth::clients::AuthFetch;
use bsv::primitives::private_key::PrivateKey;
use serde_json::Value;

use common::{get_server_url, MockWallet};

/// Dummy base64-encoded payload used as a fake transaction and derivation suffix.
/// The server's MockWallet.internalize_action ignores the actual bytes.
const DUMMY_TX_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const DUMMY_SUFFIX_B64: &str = "c3VmZml4";

/// Build the `x-bsv-payment` header JSON value given the derivation prefix
/// returned by the server's 402 response.
fn payment_header(derivation_prefix: &str) -> String {
    serde_json::json!({
        "derivationPrefix": derivation_prefix,
        "derivationSuffix": DUMMY_SUFFIX_B64,
        "transaction": DUMMY_TX_B64,
    })
    .to_string()
}

#[tokio::test]
async fn happy_path_paid_route() {
    let base_url = get_server_url().await;
    let client_key = PrivateKey::from_random().unwrap();
    let client_wallet = MockWallet::new(client_key);
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let url = format!("{}/weather", base_url);

    // --- Step 1: initial request, expect 402 ---
    let resp_402 = auth_fetch
        .fetch(&url, "GET", None, None)
        .await
        .expect("first fetch should succeed at the HTTP layer (AuthFetch returns 402 as-is)");

    assert_eq!(
        resp_402.status, 402,
        "first request to a priced route should return 402"
    );

    let derivation_prefix = resp_402
        .headers
        .get("x-bsv-payment-derivation-prefix")
        .cloned()
        .expect("402 must carry x-bsv-payment-derivation-prefix");

    let satoshis_required = resp_402
        .headers
        .get("x-bsv-payment-satoshis-required")
        .and_then(|v| v.parse::<u64>().ok())
        .expect("402 must carry x-bsv-payment-satoshis-required");

    println!(
        "[happy_path] 402 received: satoshis_required={}, prefix={}",
        satoshis_required, derivation_prefix
    );

    // --- Step 2: retry with payment header ---
    let pay_hdr = payment_header(&derivation_prefix);
    let mut headers = HashMap::new();
    headers.insert("x-bsv-payment".to_string(), pay_hdr);

    let resp_200 = auth_fetch
        .fetch(&url, "GET", None, Some(headers))
        .await
        .expect("second fetch with payment header should succeed");

    println!("[happy_path] retry status={}", resp_200.status);

    assert_eq!(resp_200.status, 200, "paid retry should return 200");

    assert_eq!(
        resp_200
            .headers
            .get("x-bsv-payment-satoshis-paid")
            .map(|s| s.as_str()),
        Some("10"),
        "server should echo satoshis_paid=10 header on successful payment"
    );

    let body: Value = serde_json::from_slice(&resp_200.body).unwrap();
    assert_eq!(body["temp_f"], 72, "weather handler should return temp_f=72");
}
