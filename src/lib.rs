//! HTTP 402 BSV payment middleware for axum.
//!
//! Port of the TypeScript `payment-express-middleware`. Bit-compatible on the
//! wire so existing `AuthFetch` clients work unchanged.
//!
//! Mount after `bsv-auth-axum-middleware` — this middleware reads the verified
//! identity from the auth layer's `Authenticated` request extension.
//!
//! See the crate README for full usage and the HTTP 402 wire protocol.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Fixed protocol version string emitted on the `x-bsv-payment-version` header.
pub const PAYMENT_VERSION: &str = "1.0";
