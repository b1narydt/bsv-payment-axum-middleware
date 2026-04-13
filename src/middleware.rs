//! Tower `Layer` / `Service` glue wrapping the core payment state machine.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use bsv::wallet::interfaces::WalletInterface;
use bsv_auth_axum_middleware::Authenticated;
use http::{HeaderValue, Request};
use tower::{Layer, Service};

use crate::config::PaymentMiddlewareConfig;
use crate::error::PaymentMiddlewareError;
use crate::headers::X_BSV_PAYMENT_SATOSHIS_PAID;
use crate::payment::{process_payment, Outcome};

/// Tower `Layer` for the payment middleware.
#[derive(Clone)]
pub struct PaymentLayer<W> {
    inner: Arc<PaymentMiddlewareConfig<W>>,
}

impl<W: WalletInterface + Clone + Send + Sync + 'static> PaymentLayer<W> {
    /// Build from a finalized config.
    pub fn from_config(config: PaymentMiddlewareConfig<W>) -> Self {
        Self {
            inner: Arc::new(config),
        }
    }
}

impl<S, W> Layer<S> for PaymentLayer<W>
where
    W: WalletInterface + Clone + Send + Sync + 'static,
{
    type Service = PaymentService<S, W>;

    fn layer(&self, inner: S) -> Self::Service {
        PaymentService {
            inner,
            config: self.inner.clone(),
        }
    }
}

/// Tower `Service` produced by [`PaymentLayer::layer`].
#[derive(Clone)]
pub struct PaymentService<S, W> {
    inner: S,
    config: Arc<PaymentMiddlewareConfig<W>>,
}

impl<S, W> Service<Request<Body>> for PaymentService<S, W>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send,
    W: WalletInterface + Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let config = self.config.clone();
        // Standard tower pattern: clone inner, swap so self.inner is the
        // "backup" and `inner` (the clone) is the one we drive the future on.
        // This ensures poll_ready was called on the service we actually use.
        let mut inner = self.inner.clone();
        std::mem::swap(&mut inner, &mut self.inner);

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();

            // Pull identity key from auth extension.
            let identity_key = match parts.extensions.get::<Authenticated>() {
                Some(a) => a.identity_key.clone(),
                None => {
                    return Ok(PaymentMiddlewareError::ServerMisconfigured.into_response());
                }
            };

            match process_payment(&parts, &identity_key, &config).await {
                Ok(Outcome::Free(paid)) => {
                    parts.extensions.insert(paid);
                    let req = Request::from_parts(parts, body);
                    inner.call(req).await
                }
                Ok(Outcome::PaidSuccess {
                    paid,
                    satoshis_paid_header,
                }) => {
                    parts.extensions.insert(paid);
                    let req = Request::from_parts(parts, body);
                    let mut resp = inner.call(req).await?;
                    resp.headers_mut().insert(
                        http::HeaderName::from_static(X_BSV_PAYMENT_SATOSHIS_PAID),
                        HeaderValue::from_str(&satoshis_paid_header.to_string())
                            .expect("u64 to_string is always valid ASCII"),
                    );
                    Ok(resp)
                }
                Err(e) => Ok(e.into_response()),
            }
        })
    }
}
