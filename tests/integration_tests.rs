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

#[tokio::test]
async fn free_route_bypasses_payment() {
    let base_url = get_server_url().await;
    let client_wallet = MockWallet::new(PrivateKey::from_random().unwrap());
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let url = format!("{}/free", base_url);
    let resp = auth_fetch
        .fetch(&url, "GET", None, None)
        .await
        .expect("free route should succeed without payment");

    assert_eq!(resp.status, 200, "free route should return 200 on first hit");
    assert!(
        !resp.headers.contains_key("x-bsv-payment-satoshis-paid"),
        "free route should NOT set the satoshis-paid header; got: {:?}",
        resp.headers.get("x-bsv-payment-satoshis-paid")
    );
    let body: Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body["satoshisPaid"], 0);
    assert_eq!(body["hasTx"], false);
}

#[tokio::test]
async fn paid_extractor_fields_populated() {
    let base_url = get_server_url().await;
    let client_wallet = MockWallet::new(PrivateKey::from_random().unwrap());
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let url = format!("{}/echo-paid", base_url);

    // 1st fetch — expect 402, capture prefix.
    let resp = auth_fetch.fetch(&url, "GET", None, None).await.unwrap();
    assert_eq!(resp.status, 402);
    let prefix = resp
        .headers
        .get("x-bsv-payment-derivation-prefix")
        .expect("402 must carry derivation prefix")
        .clone();

    // 2nd fetch — retry with x-bsv-payment header.
    let headers = HashMap::from([("x-bsv-payment".to_string(), payment_header(&prefix))]);
    let resp = auth_fetch
        .fetch(&url, "GET", None, Some(headers))
        .await
        .unwrap();

    assert_eq!(resp.status, 200);
    let body: Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body["satoshisPaid"], 10, "echo-paid uses default price 10");
    assert_eq!(body["accepted"], true);
    assert_eq!(body["hasTx"], true);
}

#[tokio::test]
async fn different_prices_per_route() {
    // /free = 0 (covered by free_route_bypasses_payment)
    // /weather = 10 (covered by happy_path_paid_route)
    // /expensive = 1000 — assert here
    let base_url = get_server_url().await;
    let client_wallet = MockWallet::new(PrivateKey::from_random().unwrap());
    let mut auth_fetch = AuthFetch::new(client_wallet);

    let url = format!("{}/expensive", base_url);

    // 1st fetch — expect 402 with satoshis-required: 1000.
    let resp = auth_fetch.fetch(&url, "GET", None, None).await.unwrap();
    assert_eq!(resp.status, 402);
    assert_eq!(
        resp.headers
            .get("x-bsv-payment-satoshis-required")
            .map(|s| s.as_str()),
        Some("1000"),
        "/expensive should demand 1000 sats"
    );
    let prefix = resp
        .headers
        .get("x-bsv-payment-derivation-prefix")
        .unwrap()
        .clone();

    // 2nd fetch — succeed.
    let headers = HashMap::from([("x-bsv-payment".to_string(), payment_header(&prefix))]);
    let resp = auth_fetch
        .fetch(&url, "GET", None, Some(headers))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers
            .get("x-bsv-payment-satoshis-paid")
            .map(|s| s.as_str()),
        Some("1000")
    );
}
