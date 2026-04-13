//! Configuration and builder for PaymentLayer.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::request::Parts;

/// Future produced by a `calculate_request_price` closure.
pub type PriceFuture = Pin<Box<dyn Future<Output = u64> + Send + 'static>>;

/// Erased closure that computes the required price for a request.
///
/// Sees request `&Parts` (method, URI, headers) only — not the body. Closures
/// must clone out anything they need from `Parts` before returning the future.
pub type PriceFn = Arc<dyn Fn(&Parts) -> PriceFuture + Send + Sync + 'static>;

/// Configuration errors surfaced by the builder.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `.wallet(...)` was not called on the builder.
    #[error("wallet is required")]
    WalletNotSet,
}

/// Immutable config consumed by `PaymentLayer::from_config`.
pub struct PaymentMiddlewareConfig<W> {
    /// The wallet used to create/verify nonces and internalize payment transactions.
    pub wallet: W,
    /// Price-calculation closure.
    pub calculate_request_price: PriceFn,
}

/// Builder for `PaymentMiddlewareConfig`.
pub struct PaymentMiddlewareConfigBuilder<W> {
    wallet: Option<W>,
    calculate_request_price: Option<PriceFn>,
}

impl<W> Default for PaymentMiddlewareConfigBuilder<W> {
    fn default() -> Self {
        Self {
            wallet: None,
            calculate_request_price: None,
        }
    }
}

impl<W: Clone + Send + Sync + 'static> PaymentMiddlewareConfigBuilder<W> {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the wallet (required).
    pub fn wallet(mut self, wallet: W) -> Self {
        self.wallet = Some(wallet);
        self
    }

    /// Set the price-calculation closure. Defaults to `|_| 100` (matches TS).
    pub fn calculate_request_price<F>(mut self, f: F) -> Self
    where
        F: Fn(&Parts) -> PriceFuture + Send + Sync + 'static,
    {
        self.calculate_request_price = Some(Arc::new(f));
        self
    }

    /// Finalize the builder.
    pub fn build(self) -> Result<PaymentMiddlewareConfig<W>, ConfigError> {
        let wallet = self.wallet.ok_or(ConfigError::WalletNotSet)?;
        let calculate_request_price = self
            .calculate_request_price
            .unwrap_or_else(|| Arc::new(|_: &Parts| -> PriceFuture { Box::pin(async { 100 }) }));
        Ok(PaymentMiddlewareConfig {
            wallet,
            calculate_request_price,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv::primitives::private_key::PrivateKey;
    use bsv::wallet::proto_wallet::ProtoWallet;
    use std::sync::Arc;

    fn test_wallet() -> Arc<ProtoWallet> {
        let key = PrivateKey::from_random().unwrap();
        Arc::new(ProtoWallet::new(key))
    }

    #[tokio::test]
    async fn builder_requires_wallet() {
        let result = PaymentMiddlewareConfigBuilder::<Arc<ProtoWallet>>::new().build();
        assert!(matches!(result, Err(ConfigError::WalletNotSet)));
    }

    #[tokio::test]
    async fn default_price_fn_is_100() {
        let config = PaymentMiddlewareConfigBuilder::new()
            .wallet(test_wallet())
            .build()
            .unwrap();

        let parts = http::Request::builder()
            .uri("/")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let price = (config.calculate_request_price)(&parts).await;
        assert_eq!(price, 100);
    }

    #[tokio::test]
    async fn custom_price_fn_is_used() {
        let config = PaymentMiddlewareConfigBuilder::new()
            .wallet(test_wallet())
            .calculate_request_price(|parts| {
                let path = parts.uri.path().to_string();
                Box::pin(async move {
                    if path == "/free" {
                        0
                    } else {
                        42
                    }
                })
            })
            .build()
            .unwrap();

        let free = http::Request::builder()
            .uri("/free")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let paid = http::Request::builder()
            .uri("/paid")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert_eq!((config.calculate_request_price)(&free).await, 0);
        assert_eq!((config.calculate_request_price)(&paid).await, 42);
    }
}
