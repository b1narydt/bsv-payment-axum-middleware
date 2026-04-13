# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-12

### Added
- Initial release of `bsv-payment-axum-middleware`.
- Port of TypeScript `payment-express-middleware` v2.0.1 to axum 0.8 + tower 0.5.
- `PaymentMiddlewareConfig` + `PaymentMiddlewareConfigBuilder` with `wallet` (required) and `calculate_request_price` (default `|_| 100` — matches TS).
- `PaymentLayer::from_config(config)` factory.
- `Paid` extractor (`FromRequestParts`) exposing `{ satoshis_paid, accepted, tx_base64 }`.
- `PaymentMiddlewareError` variants `ServerMisconfigured`, `PriceCalculationFailed`, `PaymentRequired`, `MalformedPayment`, `InvalidDerivationPrefix`, `PaymentFailed`, `NonceError`; `IntoResponse` emits TS-exact wire bodies.
- Integration tests (10): happy path (AuthFetch), free path, echo-paid extractor, different prices per route, 402 first hit, malformed header, invalid derivation prefix, price panic, missing auth, concurrent prefix uniqueness.
- Runnable `examples/paid_endpoint.rs`.
