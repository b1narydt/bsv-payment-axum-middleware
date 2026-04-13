//! `Paid` request extractor.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::PaymentMiddlewareError;

/// Evidence that the request passed the payment gate.
///
/// Inserted into request extensions by the middleware on both free and paid
/// routes. Handlers extract via axum's `FromRequestParts`.
///
/// - Free routes: `satoshis_paid = 0`, `accepted = true`, `tx_base64 = None`.
/// - Paid routes: `satoshis_paid = <price>`, `accepted = <wallet result>`, `tx_base64 = Some(...)`.
#[derive(Clone, Debug)]
pub struct Paid {
    /// How many satoshis were paid for this request.
    pub satoshis_paid: u64,
    /// Whether the wallet accepted the payment transaction (always `true` on free routes).
    pub accepted: bool,
    /// Base64-encoded payment transaction as the client sent it (None on free routes).
    pub tx_base64: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for Paid {
    type Rejection = PaymentMiddlewareError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Paid>()
            .cloned()
            .ok_or(PaymentMiddlewareError::ServerMisconfigured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use http::Request;

    #[tokio::test]
    async fn extractor_returns_paid_when_extension_present() {
        let paid = Paid {
            satoshis_paid: 42,
            accepted: true,
            tx_base64: Some("tx".into()),
        };
        let mut req = Request::builder().uri("/").body(()).unwrap();
        req.extensions_mut().insert(paid.clone());
        let (mut parts, _) = req.into_parts();

        let out = Paid::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(out.satoshis_paid, 42);
        assert!(out.accepted);
        assert_eq!(out.tx_base64.as_deref(), Some("tx"));
    }

    #[tokio::test]
    async fn extractor_rejects_when_extension_missing() {
        let req = Request::builder().uri("/").body(()).unwrap();
        let (mut parts, _) = req.into_parts();

        let rejection = Paid::from_request_parts(&mut parts, &()).await.unwrap_err();
        // Rejection is an IntoResponse-producing PaymentMiddlewareError::ServerMisconfigured.
        // Verify by converting to a response and checking the status.
        use axum::response::IntoResponse;
        let resp = rejection.into_response();
        assert_eq!(resp.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    }
}
