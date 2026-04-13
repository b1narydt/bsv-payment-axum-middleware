//! TS-parity tests for PaymentMiddlewareError -> HTTP response conversion.

use axum::body::to_bytes;
use axum::response::IntoResponse;
use http::StatusCode;
use serde_json::Value;

use bsv_payment_axum_middleware::PaymentMiddlewareError;

async fn parse_body(resp: axum::response::Response) -> (StatusCode, http::HeaderMap, Value) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, headers, json)
}

#[tokio::test]
async fn server_misconfigured_is_500_with_ts_body() {
    let (status, _, json) =
        parse_body(PaymentMiddlewareError::ServerMisconfigured.into_response()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json["status"], "error");
    assert_eq!(json["code"], "ERR_SERVER_MISCONFIGURED");
    assert_eq!(
        json["description"],
        "The payment middleware must be executed after the Auth middleware."
    );
}

#[tokio::test]
async fn price_calculation_failed_is_500_with_ts_body() {
    let (status, _, json) =
        parse_body(PaymentMiddlewareError::PriceCalculationFailed.into_response()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json["code"], "ERR_PAYMENT_INTERNAL");
    assert_eq!(
        json["description"],
        "An internal error occurred while determining the payment required for this request."
    );
}

#[tokio::test]
async fn payment_required_is_402_with_headers_and_body() {
    let err = PaymentMiddlewareError::PaymentRequired {
        satoshis: 100,
        derivation_prefix: "somebase64=".to_string(),
    };
    let (status, headers, json) = parse_body(err.into_response()).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(headers.get("x-bsv-payment-version").unwrap(), "1.0");
    assert_eq!(
        headers.get("x-bsv-payment-satoshis-required").unwrap(),
        "100"
    );
    assert_eq!(
        headers.get("x-bsv-payment-derivation-prefix").unwrap(),
        "somebase64="
    );
    assert_eq!(json["code"], "ERR_PAYMENT_REQUIRED");
    assert_eq!(json["satoshisRequired"], 100);
    assert_eq!(
        json["description"],
        "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
    );
}

#[tokio::test]
async fn malformed_payment_is_400_with_ts_body() {
    let (status, _, json) =
        parse_body(PaymentMiddlewareError::MalformedPayment.into_response()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "ERR_MALFORMED_PAYMENT");
    assert_eq!(
        json["description"],
        "The X-BSV-Payment header is not valid JSON."
    );
}

#[tokio::test]
async fn invalid_derivation_prefix_is_400_with_ts_body() {
    let (status, _, json) =
        parse_body(PaymentMiddlewareError::InvalidDerivationPrefix.into_response()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "ERR_INVALID_DERIVATION_PREFIX");
    assert_eq!(
        json["description"],
        "The X-BSV-Payment-Derivation-Prefix header is not valid."
    );
}

#[tokio::test]
async fn payment_failed_passes_through_wallet_code_and_description() {
    let err = PaymentMiddlewareError::PaymentFailed {
        code: "ERR_INSUFFICIENT_FUNDS".to_string(),
        description: "Wallet said no".to_string(),
    };
    let (status, _, json) = parse_body(err.into_response()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "ERR_INSUFFICIENT_FUNDS");
    assert_eq!(json["description"], "Wallet said no");
}
