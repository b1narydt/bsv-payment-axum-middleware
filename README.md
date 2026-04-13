# bsv-payment-axum-middleware

HTTP 402 BSV payment middleware for axum. Port of [`payment-express-middleware`](https://github.com/bitcoin-sv/payment-express-middleware) (TypeScript, v2.0.1). Bit-compatible on the wire with the TS server — existing `AuthFetch` clients work unchanged.

Mount **after** `bsv-auth-axum-middleware`. This middleware reads the verified identity key from the auth layer's `Authenticated` request extension.

## Usage

```rust,no_run
use std::sync::Arc;
use axum::{routing::get, Router};
use bsv::{primitives::private_key::PrivateKey, wallet::proto_wallet::ProtoWallet};
use bsv_auth_axum_middleware::{AuthLayer, AuthMiddlewareConfigBuilder, Authenticated, ActixTransport};
use bsv_payment_axum_middleware::{Paid, PaymentLayer, PaymentMiddlewareConfigBuilder};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    let wallet = /* your Clone + WalletInterface wallet, see below */;

    let transport = Arc::new(ActixTransport::new());
    let peer = Arc::new(Mutex::new(bsv::auth::peer::Peer::new(wallet.clone(), transport.clone())));
    let auth_cfg = AuthMiddlewareConfigBuilder::new()
        .wallet(wallet.clone())
        .allow_unauthenticated(false)
        .build().unwrap();
    let auth_layer = AuthLayer::from_config(auth_cfg, peer, transport).await;

    let pay_cfg = PaymentMiddlewareConfigBuilder::new()
        .wallet(wallet)
        .calculate_request_price(|parts| {
            let p = parts.uri.path().to_string();
            Box::pin(async move { if p == "/free" { 0 } else { 100 } })
        })
        .build().unwrap();
    let pay_layer = PaymentLayer::from_config(pay_cfg);

    let app = Router::new()
        .route("/weather", get(weather))
        .layer(pay_layer)
        .layer(auth_layer);
    // ... serve ...
}

async fn weather(_a: Authenticated, paid: Paid) -> String {
    format!("{{\"paid_sats\": {}}}", paid.satoshis_paid)
}
```

See `examples/paid_endpoint.rs` for a complete runnable example including a minimal `ExampleWallet` that satisfies `WalletInterface` by delegating to `ProtoWallet`.

## Wallet requirement

Both `AuthLayer` and `PaymentLayer` accept a generic `W: WalletInterface + Clone + Send + Sync + 'static`. Because `Arc<ProtoWallet>` does **not** automatically implement `WalletInterface`, you must supply a `Clone`-able wrapper. Options:

- **Wrap `Arc<ProtoWallet>` in a newtype** that implements `WalletInterface` by delegation. See `examples/paid_endpoint.rs` for the pattern.
- **Use `bsv::wallet::substrates::HttpWalletJson`** (from bsv-sdk with `network` feature), which is `Clone` and talks JSON-RPC to an external wallet daemon.
- **Implement your own** wallet type tuned to your production deployment.

## HTTP 402 wire protocol

### No payment → 402

```
HTTP/1.1 402 Payment Required
x-bsv-payment-version: 1.0
x-bsv-payment-satoshis-required: 100
x-bsv-payment-derivation-prefix: <base64 nonce>
Content-Type: application/json

{"status":"error","code":"ERR_PAYMENT_REQUIRED","satoshisRequired":100,"description":"A BSV payment is required to complete this request. Provide the X-BSV-Payment header."}
```

### Retry with payment

```
GET /weather
x-bsv-payment: {"derivationPrefix":"<b64>","derivationSuffix":"<b64>","transaction":"<b64 AtomicBEEF>"}
... auth headers ...
```

### Success

```
HTTP/1.1 200 OK
x-bsv-payment-satoshis-paid: 100
```

### Error responses

| Status | Code | When |
|---|---|---|
| 500 | `ERR_SERVER_MISCONFIGURED` | Auth middleware didn't run first |
| 500 | `ERR_PAYMENT_INTERNAL` | Price-calculation closure panicked |
| 400 | `ERR_MALFORMED_PAYMENT` | `x-bsv-payment` header not valid JSON |
| 400 | `ERR_INVALID_DERIVATION_PREFIX` | Nonce verification failed |
| 400 | `ERR_PAYMENT_FAILED` | `wallet.internalize_action` rejected the tx |

Bodies always have shape `{"status":"error","code":<code>,"description":<string>}`.

## Security considerations

**Replay protection is the wallet's responsibility.** The middleware itself does not track which `(derivation_prefix, derivation_suffix, transaction)` tuples have been seen before. Your wallet's `internalize_action` implementation **must** reject duplicate payments. This matches the TypeScript middleware's contract.

## License

[Open BSV License](./LICENSE).
