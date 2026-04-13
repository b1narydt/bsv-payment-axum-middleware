//! Core payment state machine (framework-agnostic).

use std::panic::AssertUnwindSafe;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bsv::auth::utils::nonce::{create_nonce, verify_nonce};
use bsv::primitives::public_key::PublicKey;
use bsv::wallet::interfaces::{
    InternalizeActionArgs, InternalizeOutput, Payment, WalletInterface,
};
use bsv::wallet::types::BooleanDefaultTrue;
use futures_util::FutureExt;
use http::request::Parts;

use crate::config::PaymentMiddlewareConfig;
use crate::error::PaymentMiddlewareError;
use crate::extractor::Paid;
use crate::headers::{BsvPaymentHeader, X_BSV_PAYMENT};

/// Result of running the state machine for one request.
#[derive(Debug, Clone)]
#[allow(dead_code)] // consumed by Task 7 middleware glue
pub(crate) enum Outcome {
    /// Request passes through — handler sees `Paid { satoshis_paid: 0, .. }`.
    Free(Paid),
    /// Payment accepted — handler sees `Paid { satoshis_paid: <price>, .. }`;
    /// caller must inject the `x-bsv-payment-satoshis-paid` response header.
    #[allow(dead_code)] // consumed by Task 7 middleware glue
    PaidSuccess { paid: Paid, satoshis_paid_header: u64 },
}

/// Run the payment state machine.
///
/// See `docs/superpowers/specs/2026-04-12-bsv-payment-axum-middleware-design.md`
/// Section "Request flow" for the full branch table.
#[allow(dead_code)] // called by Task 7 middleware glue
pub(crate) async fn process_payment<W: WalletInterface + Send + Sync + 'static>(
    parts: &Parts,
    identity_key: &str,
    config: &PaymentMiddlewareConfig<W>,
) -> Result<Outcome, PaymentMiddlewareError> {
    // Step 1: Compute price (panics → PriceCalculationFailed, logged).
    let price_fut = (config.calculate_request_price)(parts);
    let price = match AssertUnwindSafe(price_fut).catch_unwind().await {
        Ok(p) => p,
        Err(_) => {
            tracing::error!("price calculation closure panicked");
            return Err(PaymentMiddlewareError::PriceCalculationFailed);
        }
    };

    // Step 2: Free path.
    if price == 0 {
        return Ok(Outcome::Free(Paid {
            satoshis_paid: 0,
            accepted: true,
            tx_base64: None,
        }));
    }

    // Step 3: Look for payment header.
    let header_val = parts
        .headers
        .get(X_BSV_PAYMENT)
        .and_then(|v| v.to_str().ok());

    let Some(header_str) = header_val else {
        // Generate fresh nonce, return 402.
        let prefix = create_nonce(&config.wallet).await?;
        tracing::debug!(price, "402 payment required, issued derivation prefix");
        return Err(PaymentMiddlewareError::PaymentRequired {
            satoshis: price,
            derivation_prefix: prefix,
        });
    };

    // Step 4: Parse JSON body of header.
    let hdr: BsvPaymentHeader = serde_json::from_str(header_str)
        .map_err(|_| PaymentMiddlewareError::MalformedPayment)?;

    // Step 5: Verify nonce. Collapse Ok(false) and Err(_) to InvalidDerivationPrefix
    // (matches TS try { if (!valid) throw } catch).
    match verify_nonce(&config.wallet, &hdr.derivation_prefix).await {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            return Err(PaymentMiddlewareError::InvalidDerivationPrefix);
        }
    }

    // Step 6: Decode base64 fields for the wallet call.
    let prefix_bytes = STANDARD
        .decode(&hdr.derivation_prefix)
        .map_err(|_| PaymentMiddlewareError::MalformedPayment)?;
    let suffix_bytes = STANDARD
        .decode(&hdr.derivation_suffix)
        .map_err(|_| PaymentMiddlewareError::MalformedPayment)?;
    let tx_bytes = STANDARD
        .decode(&hdr.transaction)
        .map_err(|_| PaymentMiddlewareError::MalformedPayment)?;

    let sender_identity_key = PublicKey::from_string(identity_key)
        .map_err(|_| PaymentMiddlewareError::ServerMisconfigured)?;

    let args = InternalizeActionArgs {
        tx: tx_bytes,
        description: "Payment for request".to_string(),
        labels: vec![],
        seek_permission: BooleanDefaultTrue::default(),
        outputs: vec![InternalizeOutput::WalletPayment {
            output_index: 0,
            payment: Payment {
                derivation_prefix: prefix_bytes,
                derivation_suffix: suffix_bytes,
                sender_identity_key,
            },
        }],
    };

    // Step 7: Internalize. Any failure → PaymentFailed.
    match config.wallet.internalize_action(args, None).await {
        Ok(result) => {
            tracing::debug!(price, "payment accepted by wallet");
            Ok(Outcome::PaidSuccess {
                paid: Paid {
                    satoshis_paid: price,
                    accepted: result.accepted,
                    tx_base64: Some(hdr.transaction),
                },
                satoshis_paid_header: price,
            })
        }
        Err(e) => {
            tracing::warn!(error = %e, "wallet.internalize_action rejected payment");
            Err(PaymentMiddlewareError::PaymentFailed {
                code: "ERR_PAYMENT_FAILED".to_string(),
                description: e.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PaymentMiddlewareConfig, PaymentMiddlewareConfigBuilder};
    use base64::engine::general_purpose::STANDARD;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::error::WalletError;
    use bsv::wallet::interfaces::{
        AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult,
        Certificate, CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult,
        CreateSignatureArgs, CreateSignatureResult, DecryptArgs, DecryptResult,
        DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult,
        EncryptArgs, EncryptResult, GetHeaderArgs, GetHeaderResult, GetHeightResult,
        GetNetworkResult, GetPublicKeyArgs, GetPublicKeyResult, GetVersionResult,
        InternalizeActionArgs, InternalizeActionResult, ListActionsArgs, ListActionsResult,
        ListCertificatesArgs, ListCertificatesResult, ListOutputsArgs, ListOutputsResult,
        ProveCertificateArgs, ProveCertificateResult, RelinquishCertificateArgs,
        RelinquishCertificateResult, RelinquishOutputArgs, RelinquishOutputResult,
        RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult,
        RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult, SignActionArgs,
        SignActionResult, VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs,
        VerifySignatureResult, WalletInterface,
    };
    use bsv::wallet::proto_wallet::ProtoWallet;
    use std::sync::Arc;

    // ---------------------------------------------------------------------------
    // TestWallet: Clone + WalletInterface wrapper around ProtoWallet.
    // Delegates only create_hmac and verify_hmac (needed for nonce ops).
    // All other methods unimplemented — they panic if called.
    // ---------------------------------------------------------------------------

    #[derive(Clone)]
    struct TestWallet(Arc<ProtoWallet>);

    impl TestWallet {
        fn new(pk: PrivateKey) -> Self {
            TestWallet(Arc::new(ProtoWallet::new(pk)))
        }

        /// Identity key as a DER-hex string (the format `process_payment` expects).
        fn identity_key_hex(&self) -> String {
            self.0
                .get_public_key_sync(
                    &bsv::wallet::types::Protocol { security_level: 0, protocol: String::new() },
                    "",
                    &bsv::wallet::types::Counterparty::default(),
                    false,
                    true, // identity_key = true
                )
                .unwrap()
                .to_der_hex()
        }
    }

    macro_rules! unimpl {
        ($name:literal) => {
            unimplemented!(concat!($name, " not needed for payment tests"))
        };
    }

    #[async_trait::async_trait]
    impl WalletInterface for TestWallet {
        async fn create_action(
            &self, _args: CreateActionArgs, _orig: Option<&str>,
        ) -> Result<CreateActionResult, WalletError> { unimpl!("create_action") }

        async fn sign_action(
            &self, _args: SignActionArgs, _orig: Option<&str>,
        ) -> Result<SignActionResult, WalletError> { unimpl!("sign_action") }

        async fn abort_action(
            &self, _args: AbortActionArgs, _orig: Option<&str>,
        ) -> Result<AbortActionResult, WalletError> { unimpl!("abort_action") }

        async fn list_actions(
            &self, _args: ListActionsArgs, _orig: Option<&str>,
        ) -> Result<ListActionsResult, WalletError> { unimpl!("list_actions") }

        async fn internalize_action(
            &self, _args: InternalizeActionArgs, _orig: Option<&str>,
        ) -> Result<InternalizeActionResult, WalletError> { unimpl!("internalize_action") }

        async fn list_outputs(
            &self, _args: ListOutputsArgs, _orig: Option<&str>,
        ) -> Result<ListOutputsResult, WalletError> { unimpl!("list_outputs") }

        async fn relinquish_output(
            &self, _args: RelinquishOutputArgs, _orig: Option<&str>,
        ) -> Result<RelinquishOutputResult, WalletError> { unimpl!("relinquish_output") }

        async fn get_public_key(
            &self, _args: GetPublicKeyArgs, _orig: Option<&str>,
        ) -> Result<GetPublicKeyResult, WalletError> { unimpl!("get_public_key") }

        async fn reveal_counterparty_key_linkage(
            &self, _args: RevealCounterpartyKeyLinkageArgs, _orig: Option<&str>,
        ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> { unimpl!("reveal_counterparty") }

        async fn reveal_specific_key_linkage(
            &self, _args: RevealSpecificKeyLinkageArgs, _orig: Option<&str>,
        ) -> Result<RevealSpecificKeyLinkageResult, WalletError> { unimpl!("reveal_specific") }

        async fn encrypt(
            &self, _args: EncryptArgs, _orig: Option<&str>,
        ) -> Result<EncryptResult, WalletError> { unimpl!("encrypt") }

        async fn decrypt(
            &self, _args: DecryptArgs, _orig: Option<&str>,
        ) -> Result<DecryptResult, WalletError> { unimpl!("decrypt") }

        async fn create_hmac(
            &self, args: CreateHmacArgs, _orig: Option<&str>,
        ) -> Result<CreateHmacResult, WalletError> {
            let hmac = self.0.create_hmac_sync(
                &args.data,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(CreateHmacResult { hmac })
        }

        async fn verify_hmac(
            &self, args: VerifyHmacArgs, _orig: Option<&str>,
        ) -> Result<VerifyHmacResult, WalletError> {
            let valid = self.0.verify_hmac_sync(
                &args.data,
                &args.hmac,
                &args.protocol_id,
                &args.key_id,
                &args.counterparty,
            )?;
            Ok(VerifyHmacResult { valid })
        }

        async fn create_signature(
            &self, _args: CreateSignatureArgs, _orig: Option<&str>,
        ) -> Result<CreateSignatureResult, WalletError> { unimpl!("create_signature") }

        async fn verify_signature(
            &self, _args: VerifySignatureArgs, _orig: Option<&str>,
        ) -> Result<VerifySignatureResult, WalletError> { unimpl!("verify_signature") }

        async fn acquire_certificate(
            &self, _args: AcquireCertificateArgs, _orig: Option<&str>,
        ) -> Result<Certificate, WalletError> { unimpl!("acquire_certificate") }

        async fn list_certificates(
            &self, _args: ListCertificatesArgs, _orig: Option<&str>,
        ) -> Result<ListCertificatesResult, WalletError> { unimpl!("list_certificates") }

        async fn prove_certificate(
            &self, _args: ProveCertificateArgs, _orig: Option<&str>,
        ) -> Result<ProveCertificateResult, WalletError> { unimpl!("prove_certificate") }

        async fn relinquish_certificate(
            &self, _args: RelinquishCertificateArgs, _orig: Option<&str>,
        ) -> Result<RelinquishCertificateResult, WalletError> { unimpl!("relinquish_cert") }

        async fn discover_by_identity_key(
            &self, _args: DiscoverByIdentityKeyArgs, _orig: Option<&str>,
        ) -> Result<DiscoverCertificatesResult, WalletError> { unimpl!("discover_by_identity") }

        async fn discover_by_attributes(
            &self, _args: DiscoverByAttributesArgs, _orig: Option<&str>,
        ) -> Result<DiscoverCertificatesResult, WalletError> { unimpl!("discover_by_attrs") }

        async fn is_authenticated(
            &self, _orig: Option<&str>,
        ) -> Result<AuthenticatedResult, WalletError> { unimpl!("is_authenticated") }

        async fn wait_for_authentication(
            &self, _orig: Option<&str>,
        ) -> Result<AuthenticatedResult, WalletError> { unimpl!("wait_for_auth") }

        async fn get_height(
            &self, _orig: Option<&str>,
        ) -> Result<GetHeightResult, WalletError> { unimpl!("get_height") }

        async fn get_header_for_height(
            &self, _args: GetHeaderArgs, _orig: Option<&str>,
        ) -> Result<GetHeaderResult, WalletError> { unimpl!("get_header") }

        async fn get_network(
            &self, _orig: Option<&str>,
        ) -> Result<GetNetworkResult, WalletError> { unimpl!("get_network") }

        async fn get_version(
            &self, _orig: Option<&str>,
        ) -> Result<GetVersionResult, WalletError> { unimpl!("get_version") }
    }

    // ---------------------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------------------

    fn make_parts(uri: &str, payment_header: Option<&str>) -> http::request::Parts {
        let mut b = http::Request::builder().uri(uri);
        if let Some(v) = payment_header {
            b = b.header("x-bsv-payment", v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn test_wallet() -> TestWallet {
        TestWallet::new(PrivateKey::from_random().unwrap())
    }

    fn free_config(w: TestWallet) -> PaymentMiddlewareConfig<TestWallet> {
        PaymentMiddlewareConfigBuilder::new()
            .wallet(w)
            .calculate_request_price(|_| Box::pin(async { 0 }))
            .build()
            .unwrap()
    }

    fn paid_config(w: TestWallet, price: u64) -> PaymentMiddlewareConfig<TestWallet> {
        PaymentMiddlewareConfigBuilder::new()
            .wallet(w)
            .calculate_request_price(move |_| Box::pin(async move { price }))
            .build()
            .unwrap()
    }

    // ---------------------------------------------------------------------------
    // Tests (branches that don't reach wallet.internalize_action)
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn zero_price_returns_free_outcome() {
        let w = test_wallet();
        let id = w.identity_key_hex();
        let cfg = free_config(w);
        let parts = make_parts("/free", None);
        let outcome = process_payment(&parts, &id, &cfg).await.unwrap();
        match outcome {
            Outcome::Free(paid) => {
                assert_eq!(paid.satoshis_paid, 0);
                assert!(paid.accepted);
                assert!(paid.tx_base64.is_none());
            }
            _ => panic!("expected Free, got {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn paid_with_no_header_returns_payment_required() {
        let w = test_wallet();
        let id = w.identity_key_hex();
        let cfg = paid_config(w, 50);
        let parts = make_parts("/paid", None);
        let err = process_payment(&parts, &id, &cfg).await.unwrap_err();
        match err {
            crate::PaymentMiddlewareError::PaymentRequired { satoshis, derivation_prefix } => {
                assert_eq!(satoshis, 50);
                assert!(!derivation_prefix.is_empty());
                // Prefix must be valid base64.
                assert!(STANDARD.decode(&derivation_prefix).is_ok());
            }
            other => panic!("expected PaymentRequired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn paid_with_malformed_json_returns_malformed() {
        let w = test_wallet();
        let id = w.identity_key_hex();
        let cfg = paid_config(w, 10);
        let parts = make_parts("/paid", Some("{not json"));
        let err = process_payment(&parts, &id, &cfg).await.unwrap_err();
        assert!(matches!(err, crate::PaymentMiddlewareError::MalformedPayment));
    }

    #[tokio::test]
    async fn paid_with_tampered_prefix_returns_invalid_prefix() {
        let w = test_wallet();
        let id = w.identity_key_hex();
        let cfg = paid_config(w, 10);
        // 32 zero bytes as base64 — valid base64 but HMAC won't verify.
        let body = r#"{"derivationPrefix":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","derivationSuffix":"c2ZmZg==","transaction":"dHg="}"#;
        let parts = make_parts("/paid", Some(body));
        let err = process_payment(&parts, &id, &cfg).await.unwrap_err();
        assert!(matches!(err, crate::PaymentMiddlewareError::InvalidDerivationPrefix));
    }
}
