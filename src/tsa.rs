//! Minimal RFC 3161 Time-Stamp Protocol (TSP) client for XAdES-T.
//!
//! XAdES-T (the "T" profile, ETSI TS 101 903 §7.3) extends a basic
//! XAdES-BES signature with a `<xades:SignatureTimeStamp>` block
//! that proves the signature existed at a particular time. The
//! timestamp token is obtained by sending the SHA-256 of the
//! canonical `<ds:SignatureValue>` element to a Time-Stamp
//! Authority over HTTP per RFC 3161, and embedding the returned
//! `TimeStampToken` (a CMS SignedData blob) base64-encoded in
//! `<xades:EncapsulatedTimeStamp>`.
//!
//! libdigidocpp (DigiDoc4) **requires** XAdES-T as a minimum
//! before it will validate a container — XAdES-BES is structurally
//! complete but DigiDoc4 reports `QualifyingProperties block
//! 'UnsignedProperties' is missing` when only BES is present.
//!
//! This module ships a hand-rolled DER encoder for the
//! `TimeStampReq` and a minimal parser for `TimeStampResp` so we
//! avoid pulling in a full ASN.1 / CMS dependency tree just for
//! these two structures.

use sha2::{Digest, Sha256};

use crate::der::{decode_unsigned_int, encode_tlv, read_tlv_with_remainder, total_tlv_length};
use crate::error::{Result, SignatureError};

/// Default Estonian RIA TSA — the same endpoint DigiDoc4 itself
/// uses (`TSA_URL` in `https://id.eesti.ee/config.json`). Accepts
/// arbitrary SHA-256 message imprints.
pub const DEFAULT_TSA_URL: &str = "https://eid-dd.ria.ee/ts";

/// SHA-256 OID encoded as a DER OBJECT IDENTIFIER value (without
/// the 0x06 tag and length prefix).
const SHA256_OID_DER: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// Compute the SHA-256 message imprint of the canonicalised
/// `<ds:SignatureValue>` bytes and request an RFC 3161 timestamp
/// token from the given TSA. Returns the raw DER encoding of the
/// `TimeStampToken` (a `ContentInfo` containing `SignedData`),
/// ready to be base64-embedded inside
/// `<xades:EncapsulatedTimeStamp>`.
///
/// The returned bytes start with the `0x30` (SEQUENCE) tag of the
/// `ContentInfo` — that is what
/// libdigidocpp parses out of the EncapsulatedTimeStamp content.
pub async fn fetch_timestamp_token(
    tsa_url: &str,
    canonical_signature_value: &[u8],
) -> Result<Vec<u8>> {
    let imprint = Sha256::digest(canonical_signature_value);
    let request_der = build_timestamp_request(&imprint);

    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .build()
            .expect("reqwest::Client::builder().build() infallible with default config")
    });
    let response = client
        .post(tsa_url)
        .header("Content-Type", "application/timestamp-query")
        .header("Accept", "application/timestamp-reply")
        .body(request_der)
        .send()
        .await
        .map_err(|e| SignatureError::GeneralError(format!("TSA HTTP request failed: {}", e)))?;

    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| SignatureError::GeneralError(format!("TSA response read failed: {}", e)))?;
    if !status.is_success() {
        return Err(SignatureError::GeneralError(format!(
            "TSA returned HTTP {}: {} bytes of body",
            status,
            body.len()
        )));
    }

    extract_timestamp_token(&body)
}

/// Build an RFC 3161 `TimeStampReq` over the given SHA-256
/// imprint. Sets `certReq = TRUE` so the TSA includes its signing
/// certificate inside the response (DigiDoc4 / libdigidocpp need
/// the certificate for signature verification — see
/// libdigidocpp's `TS::verify`).
///
/// ```asn1
/// TimeStampReq ::= SEQUENCE {
///     version          INTEGER  { v1(1) },
///     messageImprint   MessageImprint,
///     reqPolicy        TSAPolicyId  OPTIONAL,
///     nonce            INTEGER      OPTIONAL,
///     certReq          BOOLEAN      DEFAULT FALSE,
///     extensions       [0] IMPLICIT Extensions  OPTIONAL  }
///
/// MessageImprint ::= SEQUENCE {
///     hashAlgorithm   AlgorithmIdentifier,
///     hashedMessage   OCTET STRING }
/// ```
fn build_timestamp_request(imprint_sha256: &[u8]) -> Vec<u8> {
    // hashAlgorithm: AlgorithmIdentifier { algorithm = sha256, parameters = NULL }
    let mut alg_id = Vec::with_capacity(2 + SHA256_OID_DER.len() + 2);
    alg_id.extend(encode_tlv(0x06, SHA256_OID_DER)); // OID
    alg_id.extend(encode_tlv(0x05, &[])); // NULL
    let alg_id_der = encode_tlv(0x30, &alg_id);

    // hashedMessage OCTET STRING
    let hashed_message_der = encode_tlv(0x04, imprint_sha256);

    // MessageImprint SEQUENCE
    let mut message_imprint = Vec::with_capacity(alg_id_der.len() + hashed_message_der.len());
    message_imprint.extend(alg_id_der);
    message_imprint.extend(hashed_message_der);
    let message_imprint_der = encode_tlv(0x30, &message_imprint);

    // version INTEGER 1
    let version_der = encode_tlv(0x02, &[0x01]);
    // certReq BOOLEAN TRUE
    let cert_req_der = encode_tlv(0x01, &[0xff]);

    let mut req_body =
        Vec::with_capacity(version_der.len() + message_imprint_der.len() + cert_req_der.len());
    req_body.extend(version_der);
    req_body.extend(message_imprint_der);
    req_body.extend(cert_req_der);
    encode_tlv(0x30, &req_body)
}

/// Parse an RFC 3161 `TimeStampResp` and return the raw DER bytes
/// of the embedded `timeStampToken` (a `ContentInfo`
/// SEQUENCE), ready to be base64-encoded.
///
/// ```asn1
/// TimeStampResp ::= SEQUENCE {
///     status            PKIStatusInfo,
///     timeStampToken    TimeStampToken  OPTIONAL  }
///
/// PKIStatusInfo ::= SEQUENCE {
///     status        PKIStatus,
///     statusString  PKIFreeText  OPTIONAL,
///     failInfo      PKIFailureInfo  OPTIONAL  }
/// ```
fn extract_timestamp_token(response_der: &[u8]) -> Result<Vec<u8>> {
    let (outer_value, _) = read_tlv_with_remainder(response_der, 0x30)
        .map_err(|e| SignatureError::GeneralError(format!("TSA response not SEQUENCE: {}", e)))?;
    let (status_info, rest) = read_tlv_with_remainder(outer_value, 0x30)
        .map_err(|e| SignatureError::GeneralError(format!("TSA PKIStatusInfo: {}", e)))?;

    // PKIStatusInfo.status is the first INTEGER inside the
    // PKIStatusInfo SEQUENCE. 0 = granted, 1 = grantedWithMods,
    // 2 = rejection, 3 = waiting, 4 = revocationWarning,
    // 5 = revocationNotification. Anything other than 0/1 means
    // the TSA refused. PKIStatusInfo may carry optional
    // `statusString` / `failInfo` after the INTEGER, so use the
    // remainder-aware reader and ignore trailing bytes.
    let (status_value, _) = read_tlv_with_remainder(status_info, 0x02)
        .map_err(|e| SignatureError::GeneralError(format!("PKIStatus: {}", e)))?;
    let status_int = decode_unsigned_int(status_value)?;
    if status_int != 0 && status_int != 1 {
        return Err(SignatureError::GeneralError(format!(
            "TSA rejected request, PKIStatus = {}",
            status_int
        )));
    }

    if rest.is_empty() {
        return Err(SignatureError::GeneralError(
            "TSA response missing timeStampToken".into(),
        ));
    }

    // The rest of the outer SEQUENCE is the timeStampToken — a
    // ContentInfo SEQUENCE. Return it verbatim (tag + length +
    // value) since that's the form callers will base64-encode.
    let token_len = total_tlv_length(rest)
        .map_err(|e| SignatureError::GeneralError(format!("timeStampToken length: {}", e)))?;
    Ok(rest[..token_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::{encode_tlv, read_tlv};

    #[test]
    fn timestamp_request_is_well_formed_der() {
        let imprint = [0u8; 32];
        let req = build_timestamp_request(&imprint);

        // Outer SEQUENCE
        assert_eq!(req[0], 0x30);

        // Round-trip: parse it back as nested TLVs and check the
        // imprint OCTET STRING is preserved.
        let outer = read_tlv(&req, 0x30).expect("outer SEQUENCE");
        let (version, after_version) =
            read_tlv_with_remainder(outer, 0x02).expect("version INTEGER");
        assert_eq!(version, &[0x01]);
        let (mi, after_mi) =
            read_tlv_with_remainder(after_version, 0x30).expect("MessageImprint SEQUENCE");
        let (alg_id, after_alg) = read_tlv_with_remainder(mi, 0x30).expect("AlgorithmIdentifier");
        let (oid, _) = read_tlv_with_remainder(alg_id, 0x06).expect("OID");
        assert_eq!(oid, SHA256_OID_DER);
        let (hashed, _) = read_tlv_with_remainder(after_alg, 0x04).expect("hashedMessage");
        assert_eq!(hashed, &imprint[..]);
        let (cert_req, _) = read_tlv_with_remainder(after_mi, 0x01).expect("certReq BOOLEAN");
        assert_eq!(cert_req, &[0xff]);
    }

    #[test]
    fn extract_timestamp_token_rejects_failure_status() {
        // Build a fake response: status = 2 (rejection), no token.
        let pki_status = encode_tlv(0x02, &[0x02]); // INTEGER 2
        let pki_status_info = encode_tlv(0x30, &pki_status);
        let response = encode_tlv(0x30, &pki_status_info);
        let err = extract_timestamp_token(&response).unwrap_err();
        assert!(err.to_string().contains("PKIStatus"));
    }

    #[test]
    fn extract_timestamp_token_returns_token_bytes() {
        let pki_status = encode_tlv(0x02, &[0x00]); // INTEGER 0 (granted)
        let pki_status_info = encode_tlv(0x30, &pki_status);
        // Fake token = SEQUENCE { OCTET STRING "tsa" }
        let token_inner = encode_tlv(0x04, b"tsa");
        let token = encode_tlv(0x30, &token_inner);
        let mut response_value = Vec::new();
        response_value.extend(&pki_status_info);
        response_value.extend(&token);
        let response = encode_tlv(0x30, &response_value);
        let extracted = extract_timestamp_token(&response).expect("extract token");
        assert_eq!(extracted, token);
    }
}
