//! Smoke test: PaymentLayer + inner handler. End-to-end auth flow is in
//! integration_tests; this just proves the tower glue invokes the state
//! machine and injects the Paid extension.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use bsv::primitives::private_key::PrivateKey;
use bsv::wallet::error::WalletError;
use bsv::wallet::interfaces::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult, Certificate,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult, GetPublicKeyArgs,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsArgs, ListOutputsResult, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult, SignActionArgs, SignActionResult,
    VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult, WalletInterface,
};
use bsv::wallet::proto_wallet::ProtoWallet;
use bsv::wallet::types::Counterparty;
use bsv::wallet::types::Protocol;
use bsv_auth_axum_middleware::Authenticated;
use bsv_payment_axum_middleware::{Paid, PaymentLayer, PaymentMiddlewareConfigBuilder};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// SmokeWallet: minimal WalletInterface wrapper around ProtoWallet.
// Mirrors the TestWallet in src/payment.rs — all 29 methods satisfied.
// Only create_hmac / verify_hmac delegate to ProtoWallet; all others panic.
// The smoke tests only exercise the free path (price=0) and the
// missing-auth path — neither invokes any wallet method.
// ---------------------------------------------------------------------------

macro_rules! unimpl {
    ($name:literal) => {
        unimplemented!(concat!($name, " not needed for smoke tests"))
    };
}

#[derive(Clone)]
struct SmokeWallet(Arc<ProtoWallet>);

impl SmokeWallet {
    fn new(pk: PrivateKey) -> Self {
        SmokeWallet(Arc::new(ProtoWallet::new(pk)))
    }

    /// Identity key as a DER-hex string (the format the middleware expects).
    /// Mirrors `TestWallet::identity_key_hex` in src/payment.rs.
    fn identity_key_hex(&self) -> String {
        self.0
            .get_public_key_sync(
                &Protocol {
                    security_level: 0,
                    protocol: String::new(),
                },
                "",
                &Counterparty::default(),
                false,
                true, // identity_key = true
            )
            .unwrap()
            .to_der_hex()
    }
}

#[async_trait::async_trait]
impl WalletInterface for SmokeWallet {
    async fn create_action(
        &self,
        _args: CreateActionArgs,
        _orig: Option<&str>,
    ) -> Result<CreateActionResult, WalletError> {
        unimpl!("create_action")
    }

    async fn sign_action(
        &self,
        _args: SignActionArgs,
        _orig: Option<&str>,
    ) -> Result<SignActionResult, WalletError> {
        unimpl!("sign_action")
    }

    async fn abort_action(
        &self,
        _args: AbortActionArgs,
        _orig: Option<&str>,
    ) -> Result<AbortActionResult, WalletError> {
        unimpl!("abort_action")
    }

    async fn list_actions(
        &self,
        _args: ListActionsArgs,
        _orig: Option<&str>,
    ) -> Result<ListActionsResult, WalletError> {
        unimpl!("list_actions")
    }

    async fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
        _orig: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError> {
        unimpl!("internalize_action")
    }

    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _orig: Option<&str>,
    ) -> Result<ListOutputsResult, WalletError> {
        unimpl!("list_outputs")
    }

    async fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
        _orig: Option<&str>,
    ) -> Result<RelinquishOutputResult, WalletError> {
        unimpl!("relinquish_output")
    }

    async fn get_public_key(
        &self,
        _args: GetPublicKeyArgs,
        _orig: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        unimpl!("get_public_key")
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        _args: RevealCounterpartyKeyLinkageArgs,
        _orig: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        unimpl!("reveal_counterparty")
    }

    async fn reveal_specific_key_linkage(
        &self,
        _args: RevealSpecificKeyLinkageArgs,
        _orig: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        unimpl!("reveal_specific")
    }

    async fn encrypt(
        &self,
        _args: EncryptArgs,
        _orig: Option<&str>,
    ) -> Result<EncryptResult, WalletError> {
        unimpl!("encrypt")
    }

    async fn decrypt(
        &self,
        _args: DecryptArgs,
        _orig: Option<&str>,
    ) -> Result<DecryptResult, WalletError> {
        unimpl!("decrypt")
    }

    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        _orig: Option<&str>,
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
        &self,
        args: VerifyHmacArgs,
        _orig: Option<&str>,
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
        &self,
        _args: CreateSignatureArgs,
        _orig: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError> {
        unimpl!("create_signature")
    }

    async fn verify_signature(
        &self,
        _args: VerifySignatureArgs,
        _orig: Option<&str>,
    ) -> Result<VerifySignatureResult, WalletError> {
        unimpl!("verify_signature")
    }

    async fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
        _orig: Option<&str>,
    ) -> Result<Certificate, WalletError> {
        unimpl!("acquire_certificate")
    }

    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _orig: Option<&str>,
    ) -> Result<ListCertificatesResult, WalletError> {
        unimpl!("list_certificates")
    }

    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _orig: Option<&str>,
    ) -> Result<ProveCertificateResult, WalletError> {
        unimpl!("prove_certificate")
    }

    async fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
        _orig: Option<&str>,
    ) -> Result<RelinquishCertificateResult, WalletError> {
        unimpl!("relinquish_cert")
    }

    async fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
        _orig: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        unimpl!("discover_by_identity")
    }

    async fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
        _orig: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        unimpl!("discover_by_attrs")
    }

    async fn is_authenticated(
        &self,
        _orig: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        unimpl!("is_authenticated")
    }

    async fn wait_for_authentication(
        &self,
        _orig: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        unimpl!("wait_for_auth")
    }

    async fn get_height(&self, _orig: Option<&str>) -> Result<GetHeightResult, WalletError> {
        unimpl!("get_height")
    }

    async fn get_header_for_height(
        &self,
        _args: GetHeaderArgs,
        _orig: Option<&str>,
    ) -> Result<GetHeaderResult, WalletError> {
        unimpl!("get_header")
    }

    async fn get_network(&self, _orig: Option<&str>) -> Result<GetNetworkResult, WalletError> {
        unimpl!("get_network")
    }

    async fn get_version(&self, _orig: Option<&str>) -> Result<GetVersionResult, WalletError> {
        unimpl!("get_version")
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn free_handler(paid: Paid) -> String {
    format!(
        "paid={} tx={}",
        paid.satoshis_paid,
        paid.tx_base64.is_some()
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn free_route_injects_paid_extension() {
    let wallet = SmokeWallet::new(PrivateKey::from_random().unwrap());
    let identity_key = wallet.identity_key_hex();

    let cfg = PaymentMiddlewareConfigBuilder::new()
        .wallet(wallet)
        .calculate_request_price(|_| Box::pin(async { 0 }))
        .build()
        .unwrap();

    let app = Router::new()
        .route("/", get(free_handler))
        .layer(PaymentLayer::from_config(cfg));

    let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
    req.extensions_mut().insert(Authenticated {
        identity_key: identity_key.clone(),
    });

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"paid=0 tx=false");
}

#[tokio::test]
async fn missing_auth_extension_is_500() {
    let wallet = SmokeWallet::new(PrivateKey::from_random().unwrap());
    let cfg = PaymentMiddlewareConfigBuilder::new()
        .wallet(wallet)
        .build()
        .unwrap();

    let app = Router::new()
        .route("/", get(free_handler))
        .layer(PaymentLayer::from_config(cfg));

    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
