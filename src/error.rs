//! Error type for the payment middleware with TS-parity HTTP responses.

use axum::response::{IntoResponse, Response};
use http::{header::HeaderValue, StatusCode};

/// Unified error type emitted by the payment middleware.
///
/// Each variant maps to an exact HTTP status code and JSON body matching the
/// TypeScript `payment-express-middleware` wire format byte-for-byte.
#[derive(Debug, thiserror::Error)]
pub enum PaymentMiddlewareError {
    /// 500 — `Authenticated` extension missing (middleware mounted without auth).
    #[error("The payment middleware must be executed after the Auth middleware.")]
    ServerMisconfigured,

    /// 500 — price-calculation closure panicked or errored.
    #[error("An internal error occurred while determining the payment required for this request.")]
    PriceCalculationFailed,

    /// 402 — no payment header, client must pay `satoshis` and retry.
    #[error("Payment required: {satoshis} satoshis")]
    PaymentRequired {
        /// Price in satoshis.
        satoshis: u64,
        /// Base64 nonce returned to the client as the derivation prefix.
        derivation_prefix: String,
    },

    /// 400 — `x-bsv-payment` header not valid JSON or missing fields.
    #[error("The X-BSV-Payment header is not valid JSON.")]
    MalformedPayment,

    /// 400 — nonce verification failed or base64 prefix malformed.
    #[error("The X-BSV-Payment-Derivation-Prefix header is not valid.")]
    InvalidDerivationPrefix,

    /// 400 — `wallet.internalize_action` rejected the payment.
    #[error("{description}")]
    PaymentFailed {
        /// Wire code surfaced in `code`. Defaults to `"ERR_PAYMENT_FAILED"` for unmapped wallet errors.
        code: String,
        /// Description of the failure.
        description: String,
    },

    /// 500 — HMAC / nonce creation failed internally. Should not happen in practice.
    #[error("internal nonce error: {0}")]
    NonceError(#[from] bsv::auth::AuthError),
}

impl IntoResponse for PaymentMiddlewareError {
    fn into_response(self) -> Response {
        match self {
            PaymentMiddlewareError::ServerMisconfigured => json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_SERVER_MISCONFIGURED",
                "The payment middleware must be executed after the Auth middleware.",
            ),
            PaymentMiddlewareError::PriceCalculationFailed => json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_PAYMENT_INTERNAL",
                "An internal error occurred while determining the payment required for this request.",
            ),
            PaymentMiddlewareError::PaymentRequired { satoshis, derivation_prefix } => {
                payment_required_response(satoshis, &derivation_prefix)
            }
            PaymentMiddlewareError::MalformedPayment => json_error_response(
                StatusCode::BAD_REQUEST,
                "ERR_MALFORMED_PAYMENT",
                "The X-BSV-Payment header is not valid JSON.",
            ),
            PaymentMiddlewareError::InvalidDerivationPrefix => json_error_response(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_DERIVATION_PREFIX",
                "The X-BSV-Payment-Derivation-Prefix header is not valid.",
            ),
            PaymentMiddlewareError::PaymentFailed { code, description } => {
                // code already includes any wallet-side classification.
                json_error_response(StatusCode::BAD_REQUEST, &code, &description)
            }
            PaymentMiddlewareError::NonceError(e) => json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_PAYMENT_INTERNAL",
                &e.to_string(),
            ),
        }
    }
}

fn json_error_response(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({
            "status": "error",
            "code": code,
            "description": description,
        })),
    )
        .into_response()
}

/// Build the 402 Payment Required response with TS-parity headers and body.
fn payment_required_response(satoshis: u64, derivation_prefix: &str) -> Response {
    let mut resp = (
        StatusCode::PAYMENT_REQUIRED,
        axum::Json(serde_json::json!({
            "status": "error",
            "code": "ERR_PAYMENT_REQUIRED",
            "satoshisRequired": satoshis,
            "description": "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
        })),
    )
        .into_response();

    let headers = resp.headers_mut();
    headers.insert("x-bsv-payment-version", HeaderValue::from_static(crate::PAYMENT_VERSION));
    headers.insert(
        "x-bsv-payment-satoshis-required",
        HeaderValue::from_str(&satoshis.to_string())
            .expect("u64 to_string is always valid ASCII"),
    );
    headers.insert(
        "x-bsv-payment-derivation-prefix",
        HeaderValue::from_str(derivation_prefix)
            .expect("base64 nonces contain only HTTP-header-safe characters"),
    );
    resp
}
