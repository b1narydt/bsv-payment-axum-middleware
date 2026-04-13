//! Header name constants and BsvPaymentHeader JSON struct.

use serde::{Deserialize, Serialize};

/// Request header carrying the signed payment payload.
pub const X_BSV_PAYMENT: &str = "x-bsv-payment";
/// Response header announcing the protocol version on 402.
pub const X_BSV_PAYMENT_VERSION: &str = "x-bsv-payment-version";
/// Response header with the required satoshis on 402.
pub const X_BSV_PAYMENT_SATOSHIS_REQUIRED: &str = "x-bsv-payment-satoshis-required";
/// Response header with the server-HMAC nonce on 402.
pub const X_BSV_PAYMENT_DERIVATION_PREFIX: &str = "x-bsv-payment-derivation-prefix";
/// Response header echoed after a successful payment, on the handler's response.
pub const X_BSV_PAYMENT_SATOSHIS_PAID: &str = "x-bsv-payment-satoshis-paid";

/// Parsed JSON body of the `x-bsv-payment` request header.
///
/// All three fields are base64 strings. `transaction` is a base64-encoded
/// AtomicBEEF payment transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BsvPaymentHeader {
    /// Server-supplied nonce from the preceding 402 response.
    pub derivation_prefix: String,
    /// Client-generated counterpart nonce.
    pub derivation_suffix: String,
    /// Base64-encoded AtomicBEEF payment transaction.
    pub transaction: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_name_constants_are_lowercase() {
        assert_eq!(X_BSV_PAYMENT, "x-bsv-payment");
        assert_eq!(X_BSV_PAYMENT_VERSION, "x-bsv-payment-version");
        assert_eq!(X_BSV_PAYMENT_SATOSHIS_REQUIRED, "x-bsv-payment-satoshis-required");
        assert_eq!(X_BSV_PAYMENT_DERIVATION_PREFIX, "x-bsv-payment-derivation-prefix");
        assert_eq!(X_BSV_PAYMENT_SATOSHIS_PAID, "x-bsv-payment-satoshis-paid");
    }

    #[test]
    fn bsv_payment_header_parses_camelcase_json() {
        let json = r#"{"derivationPrefix":"pfx","derivationSuffix":"sfx","transaction":"tx"}"#;
        let parsed: BsvPaymentHeader = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.derivation_prefix, "pfx");
        assert_eq!(parsed.derivation_suffix, "sfx");
        assert_eq!(parsed.transaction, "tx");
    }

    #[test]
    fn bsv_payment_header_rejects_missing_fields() {
        let json = r#"{"derivationPrefix":"pfx"}"#;
        let err = serde_json::from_str::<BsvPaymentHeader>(json);
        assert!(err.is_err());
    }
}
