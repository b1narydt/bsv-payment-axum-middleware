//! Minimal runnable example: an authenticated, paid `/weather` endpoint.
//!
//! Run:
//! ```sh
//! cargo run --example paid_endpoint
//! ```
//!
//! Then hit it with an AuthFetch-equipped BSV client (e.g. the TS SDK's
//! `AuthFetch` wrapper with a payment plugin). The server listens on
//! `http://127.0.0.1:3000`.
//!
//! Routes:
//! - `GET /weather` — requires auth + 100 satoshi payment
//! - `GET /free`    — requires auth, no payment
//!
//! # Note on the wallet
//!
//! `bsv::wallet::proto_wallet::ProtoWallet` is NOT `Clone`, so `Arc<ProtoWallet>`
//! does not satisfy the `WalletInterface` trait bound that both middlewares
//! require (the SDK provides no blanket `impl<W> WalletInterface for Arc<W>`).
//!
//! This example defines `ExampleWallet` — a thin `Arc<ProtoWallet>` newtype
//! that is both `Clone` and `WalletInterface`. It delegates every crypto method
//! to the inner `ProtoWallet` via the trait and overrides `internalize_action`
//! to log + accept every payment.
//!
//! In a real deployment you would replace `ExampleWallet` with whichever wallet
//! implementation your stack uses (e.g. an HTTP client talking to a local wallet
//! daemon, or a full `bsv-wallet` instance).

use std::sync::Arc;

use async_trait::async_trait;
use axum::routing::get;
use axum::Router;
use bsv::auth::peer::Peer;
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
use bsv_auth_axum_middleware::{ActixTransport, AuthLayer, AuthMiddlewareConfigBuilder, Authenticated};
use bsv_payment_axum_middleware::{Paid, PaymentLayer, PaymentMiddlewareConfigBuilder};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// ExampleWallet — Clone + WalletInterface wrapper around ProtoWallet.
//
// Delegates all methods to the inner ProtoWallet via the WalletInterface trait.
// Overrides `internalize_action` to accept every payment (log + Ok).
//
// Replace this type with your production wallet in a real deployment.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ExampleWallet(Arc<ProtoWallet>);

impl ExampleWallet {
    fn new(pk: PrivateKey) -> Self {
        ExampleWallet(Arc::new(ProtoWallet::new(pk)))
    }
}

#[async_trait]
impl WalletInterface for ExampleWallet {
    async fn create_action(
        &self, args: CreateActionArgs, orig: Option<&str>,
    ) -> Result<CreateActionResult, WalletError> {
        WalletInterface::create_action(&*self.0, args, orig).await
    }

    async fn sign_action(
        &self, args: SignActionArgs, orig: Option<&str>,
    ) -> Result<SignActionResult, WalletError> {
        WalletInterface::sign_action(&*self.0, args, orig).await
    }

    async fn abort_action(
        &self, args: AbortActionArgs, orig: Option<&str>,
    ) -> Result<AbortActionResult, WalletError> {
        WalletInterface::abort_action(&*self.0, args, orig).await
    }

    async fn list_actions(
        &self, args: ListActionsArgs, orig: Option<&str>,
    ) -> Result<ListActionsResult, WalletError> {
        WalletInterface::list_actions(&*self.0, args, orig).await
    }

    /// Accept every inbound payment. A production wallet would validate the
    /// transaction, check the output value matches the price, and persist it.
    async fn internalize_action(
        &self, args: InternalizeActionArgs, _orig: Option<&str>,
    ) -> Result<InternalizeActionResult, WalletError> {
        println!(
            "[ExampleWallet] internalize_action: accepting payment ({} outputs)",
            args.outputs.len()
        );
        Ok(InternalizeActionResult { accepted: true })
    }

    async fn list_outputs(
        &self, args: ListOutputsArgs, orig: Option<&str>,
    ) -> Result<ListOutputsResult, WalletError> {
        WalletInterface::list_outputs(&*self.0, args, orig).await
    }

    async fn relinquish_output(
        &self, args: RelinquishOutputArgs, orig: Option<&str>,
    ) -> Result<RelinquishOutputResult, WalletError> {
        WalletInterface::relinquish_output(&*self.0, args, orig).await
    }

    async fn get_public_key(
        &self, args: GetPublicKeyArgs, orig: Option<&str>,
    ) -> Result<GetPublicKeyResult, WalletError> {
        WalletInterface::get_public_key(&*self.0, args, orig).await
    }

    async fn reveal_counterparty_key_linkage(
        &self, args: RevealCounterpartyKeyLinkageArgs, orig: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        WalletInterface::reveal_counterparty_key_linkage(&*self.0, args, orig).await
    }

    async fn reveal_specific_key_linkage(
        &self, args: RevealSpecificKeyLinkageArgs, orig: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        WalletInterface::reveal_specific_key_linkage(&*self.0, args, orig).await
    }

    async fn encrypt(
        &self, args: EncryptArgs, orig: Option<&str>,
    ) -> Result<EncryptResult, WalletError> {
        WalletInterface::encrypt(&*self.0, args, orig).await
    }

    async fn decrypt(
        &self, args: DecryptArgs, orig: Option<&str>,
    ) -> Result<DecryptResult, WalletError> {
        WalletInterface::decrypt(&*self.0, args, orig).await
    }

    async fn create_hmac(
        &self, args: CreateHmacArgs, orig: Option<&str>,
    ) -> Result<CreateHmacResult, WalletError> {
        WalletInterface::create_hmac(&*self.0, args, orig).await
    }

    async fn verify_hmac(
        &self, args: VerifyHmacArgs, orig: Option<&str>,
    ) -> Result<VerifyHmacResult, WalletError> {
        WalletInterface::verify_hmac(&*self.0, args, orig).await
    }

    async fn create_signature(
        &self, args: CreateSignatureArgs, orig: Option<&str>,
    ) -> Result<CreateSignatureResult, WalletError> {
        WalletInterface::create_signature(&*self.0, args, orig).await
    }

    async fn verify_signature(
        &self, args: VerifySignatureArgs, orig: Option<&str>,
    ) -> Result<VerifySignatureResult, WalletError> {
        WalletInterface::verify_signature(&*self.0, args, orig).await
    }

    async fn acquire_certificate(
        &self, args: AcquireCertificateArgs, orig: Option<&str>,
    ) -> Result<Certificate, WalletError> {
        WalletInterface::acquire_certificate(&*self.0, args, orig).await
    }

    async fn list_certificates(
        &self, args: ListCertificatesArgs, orig: Option<&str>,
    ) -> Result<ListCertificatesResult, WalletError> {
        WalletInterface::list_certificates(&*self.0, args, orig).await
    }

    async fn prove_certificate(
        &self, args: ProveCertificateArgs, orig: Option<&str>,
    ) -> Result<ProveCertificateResult, WalletError> {
        WalletInterface::prove_certificate(&*self.0, args, orig).await
    }

    async fn relinquish_certificate(
        &self, args: RelinquishCertificateArgs, orig: Option<&str>,
    ) -> Result<RelinquishCertificateResult, WalletError> {
        WalletInterface::relinquish_certificate(&*self.0, args, orig).await
    }

    async fn discover_by_identity_key(
        &self, args: DiscoverByIdentityKeyArgs, orig: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        WalletInterface::discover_by_identity_key(&*self.0, args, orig).await
    }

    async fn discover_by_attributes(
        &self, args: DiscoverByAttributesArgs, orig: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        WalletInterface::discover_by_attributes(&*self.0, args, orig).await
    }

    async fn is_authenticated(
        &self, orig: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        WalletInterface::is_authenticated(&*self.0, orig).await
    }

    async fn wait_for_authentication(
        &self, orig: Option<&str>,
    ) -> Result<AuthenticatedResult, WalletError> {
        WalletInterface::wait_for_authentication(&*self.0, orig).await
    }

    async fn get_height(&self, orig: Option<&str>) -> Result<GetHeightResult, WalletError> {
        WalletInterface::get_height(&*self.0, orig).await
    }

    async fn get_header_for_height(
        &self, args: GetHeaderArgs, orig: Option<&str>,
    ) -> Result<GetHeaderResult, WalletError> {
        WalletInterface::get_header_for_height(&*self.0, args, orig).await
    }

    async fn get_network(&self, orig: Option<&str>) -> Result<GetNetworkResult, WalletError> {
        WalletInterface::get_network(&*self.0, orig).await
    }

    async fn get_version(&self, orig: Option<&str>) -> Result<GetVersionResult, WalletError> {
        WalletInterface::get_version(&*self.0, orig).await
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let key = PrivateKey::from_random().expect("random key");
    let wallet = ExampleWallet::new(key);

    // Auth layer — uses the same wallet for HMAC-based request signing.
    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(Mutex::new(Peer::new(wallet.clone(), transport.clone())));
    let auth_cfg = AuthMiddlewareConfigBuilder::new()
        .wallet(wallet.clone())
        .allow_unauthenticated(false)
        .build()
        .expect("auth cfg");
    let auth_layer = AuthLayer::from_config(auth_cfg, peer, transport).await;

    // Payment layer — price function determines cost per route.
    let pay_cfg = PaymentMiddlewareConfigBuilder::new()
        .wallet(wallet)
        .calculate_request_price(|parts| {
            let path = parts.uri.path().to_string();
            Box::pin(async move {
                match path.as_str() {
                    "/free" => 0,
                    _ => 100,
                }
            })
        })
        .build()
        .expect("pay cfg");
    let pay_layer = PaymentLayer::from_config(pay_cfg);

    // Stack: auth runs first (outer), then payment (inner).
    let app = Router::new()
        .route("/weather", get(weather))
        .route("/free", get(free))
        .layer(pay_layer)
        .layer(auth_layer);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("bind");
    println!("listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await.expect("serve");
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Paid weather endpoint — requires a 100-satoshi BSV payment per request.
async fn weather(_auth: Authenticated, paid: Paid) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "temp_f": 72,
        "satoshis_paid": paid.satoshis_paid,
    }))
}

/// Free endpoint — requires auth but no payment.
async fn free(_auth: Authenticated, _paid: Paid) -> &'static str {
    "free content\n"
}
