//! Minimal RFC 6960 OCSP client for XAdES-LT.
//!
//! XAdES-LT (the "LT" profile, ETSI TS 101 903 §7.5) extends a
//! XAdES-T signature with the issuer certificate of the signer
//! and an OCSP response covering the signer cert. libdigidocpp's
//! `SignatureXAdES_LT::extendSignatureProfile` builds the
//! equivalent shape and refuses LT-level validation when
//! `<xades:RevocationValues>` is absent.
//!
//! Like [`super::tsa`] this module hand-rolls the DER for the
//! request/response so we don't need a full ASN.1 / OCSP
//! dependency tree. It only handles the minimum needed for SK ID
//! Solutions' OCSP responder (id-pkix-ocsp-basic, SHA-1 CertID,
//! no nonce) — extend as needed for other CAs.
//!
//! The output is the inner `BasicOCSPResponse` DER (the value of
//! the OCSP response's `responseBytes.response` OCTET STRING),
//! which is what XAdES embeds in
//! `<xades:EncapsulatedOCSPValue>`.

use sha1::{Digest as Sha1Digest, Sha1};
use x509_parser::prelude::*;

use super::der::{decode_unsigned_int, encode_tlv, read_tlv, read_tlv_with_remainder};
use crate::error::{Result, SignatureError};

/// OID for `id-sha1` (1.3.14.3.2.26) — the hash algorithm used
/// in the OCSP `CertID` for SK and most other CAs. RFC 6960
/// allows SHA-256 too but SHA-1 is the de-facto interoperable
/// choice.
const SHA1_OID_DER: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];

/// OID for `id-pkix-ocsp-basic` (1.3.6.1.5.5.7.48.1.1) — the
/// `responseType` we expect in the OCSP response's
/// `responseBytes`.
const OCSP_BASIC_OID_DER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

/// Fetch an RFC 6960 OCSP response for `subject_cert_der` from
/// `ocsp_url`, signed using the issuer cert (or the subject cert
/// itself if self-signed) to derive the `CertID` issuer hashes.
/// Returns the raw DER bytes of the embedded `BasicOCSPResponse`,
/// ready to be base64-embedded inside
/// `<xades:EncapsulatedOCSPValue>`.
pub async fn fetch_ocsp_response(
    ocsp_url: &str,
    subject_cert_der: &[u8],
    issuer_cert_der: &[u8],
) -> Result<Vec<u8>> {
    let request_der = build_ocsp_request(subject_cert_der, issuer_cert_der)?;

    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest::Client::builder().build() infallible with default config")
    });
    let response = client
        .post(ocsp_url)
        .header("Content-Type", "application/ocsp-request")
        .header("Accept", "application/ocsp-response")
        .body(request_der)
        .send()
        .await
        .map_err(|e| SignatureError::GeneralError(format!("OCSP HTTP request failed: {}", e)))?;

    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| SignatureError::GeneralError(format!("OCSP response read failed: {}", e)))?;
    if !status.is_success() {
        return Err(SignatureError::GeneralError(format!(
            "OCSP responder returned HTTP {}: {} bytes of body",
            status,
            body.len()
        )));
    }

    extract_basic_ocsp_response(&body)
}

/// Build an unsigned RFC 6960 OCSP request asking about
/// `subject_cert`. The `CertID` uses SHA-1 of the issuer's
/// distinguished name and the issuer's public-key BIT STRING
/// content.
///
/// ```asn1
/// OCSPRequest ::= SEQUENCE {
///     tbsRequest         TBSRequest,
///     optionalSignature  [0] EXPLICIT Signature OPTIONAL  -- omitted
/// }
///
/// TBSRequest ::= SEQUENCE {
///     version            [0] EXPLICIT Version DEFAULT v1,  -- omitted
///     requestorName      [1] EXPLICIT GeneralName OPTIONAL,
///     requestList        SEQUENCE OF Request,
///     requestExtensions  [2] EXPLICIT Extensions OPTIONAL  -- omitted
/// }
///
/// Request ::= SEQUENCE {
///     reqCert                  CertID,
///     singleRequestExtensions  [0] EXPLICIT Extensions OPTIONAL
/// }
///
/// CertID ::= SEQUENCE {
///     hashAlgorithm   AlgorithmIdentifier,
///     issuerNameHash  OCTET STRING,
///     issuerKeyHash   OCTET STRING,
///     serialNumber    INTEGER
/// }
/// ```
fn build_ocsp_request(subject_cert_der: &[u8], issuer_cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, subject) = X509Certificate::from_der(subject_cert_der)
        .map_err(|e| SignatureError::GeneralError(format!("OCSP: parse subject cert: {}", e)))?;
    let (_, issuer) = X509Certificate::from_der(issuer_cert_der)
        .map_err(|e| SignatureError::GeneralError(format!("OCSP: parse issuer cert: {}", e)))?;

    // CertID.hashAlgorithm = AlgorithmIdentifier { sha-1, NULL }
    let mut alg_id_inner = Vec::with_capacity(SHA1_OID_DER.len() + 4);
    alg_id_inner.extend(encode_tlv(0x06, SHA1_OID_DER));
    alg_id_inner.extend(encode_tlv(0x05, &[]));
    let alg_id_der = encode_tlv(0x30, &alg_id_inner);

    // CertID.issuerNameHash = SHA-1(issuer DN DER)
    let issuer_name_hash = Sha1::digest(issuer.tbs_certificate.subject.as_raw());
    let issuer_name_hash_der = encode_tlv(0x04, &issuer_name_hash);

    // CertID.issuerKeyHash = SHA-1(issuer subjectPublicKey BIT STRING contents)
    let issuer_key_hash = Sha1::digest(
        issuer
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref(),
    );
    let issuer_key_hash_der = encode_tlv(0x04, &issuer_key_hash);

    // CertID.serialNumber INTEGER (raw DER)
    let serial_der = subject.tbs_certificate.raw_serial();
    let serial_int_der = encode_tlv(0x02, serial_der);

    let mut cert_id = Vec::with_capacity(
        alg_id_der.len()
            + issuer_name_hash_der.len()
            + issuer_key_hash_der.len()
            + serial_int_der.len(),
    );
    cert_id.extend(alg_id_der);
    cert_id.extend(issuer_name_hash_der);
    cert_id.extend(issuer_key_hash_der);
    cert_id.extend(serial_int_der);
    let cert_id_der = encode_tlv(0x30, &cert_id);

    // Request ::= SEQUENCE { reqCert CertID }
    let request_der = encode_tlv(0x30, &cert_id_der);

    // requestList SEQUENCE OF Request — exactly one entry here
    let request_list_der = encode_tlv(0x30, &request_der);

    // TBSRequest ::= SEQUENCE { requestList } — version/extensions omitted
    let tbs_request_der = encode_tlv(0x30, &request_list_der);

    // OCSPRequest ::= SEQUENCE { tbsRequest } — optionalSignature omitted
    Ok(encode_tlv(0x30, &tbs_request_der))
}

/// Extract the inner `BasicOCSPResponse` DER from the raw OCSP
/// response. Returns the bytes that XAdES embeds in
/// `<xades:EncapsulatedOCSPValue>` (libdigidocpp's
/// `OCSP::OCSP(const std::vector<unsigned char>&)` parses these
/// bytes directly).
///
/// ```asn1
/// OCSPResponse ::= SEQUENCE {
///     responseStatus   OCSPResponseStatus,
///     responseBytes    [0] EXPLICIT ResponseBytes OPTIONAL
/// }
///
/// ResponseBytes ::= SEQUENCE {
///     responseType   OBJECT IDENTIFIER,  -- id-pkix-ocsp-basic
///     response       OCTET STRING        -- DER of BasicOCSPResponse
/// }
/// ```
fn extract_basic_ocsp_response(response_der: &[u8]) -> Result<Vec<u8>> {
    let (outer, _) = read_tlv_with_remainder(response_der, 0x30)
        .map_err(|e| SignatureError::GeneralError(format!("OCSP response not SEQUENCE: {}", e)))?;

    // responseStatus ENUMERATED — 0 = successful. Anything else
    // means the responder refused (1=malformedRequest,
    // 2=internalError, 3=tryLater, 5=sigRequired,
    // 6=unauthorized).
    let (status_value, after_status) = read_tlv_with_remainder(outer, 0x0a)
        .map_err(|e| SignatureError::GeneralError(format!("OCSPResponseStatus: {}", e)))?;
    let status_int = decode_unsigned_int(status_value)?;
    if status_int != 0 {
        return Err(SignatureError::GeneralError(format!(
            "OCSP responder rejected request, OCSPResponseStatus = {}",
            status_int
        )));
    }

    // responseBytes is `[0] EXPLICIT` → tag = 0xA0, contains a
    // ResponseBytes SEQUENCE.
    let response_bytes_outer = read_tlv(after_status, 0xa0).map_err(|e| {
        SignatureError::GeneralError(format!("OCSP responseBytes [0] EXPLICIT: {}", e))
    })?;
    let response_bytes = read_tlv(response_bytes_outer, 0x30)
        .map_err(|e| SignatureError::GeneralError(format!("OCSP ResponseBytes SEQUENCE: {}", e)))?;

    // ResponseBytes.responseType OID — must be id-pkix-ocsp-basic.
    let (response_type, after_type) = read_tlv_with_remainder(response_bytes, 0x06)
        .map_err(|e| SignatureError::GeneralError(format!("OCSP responseType: {}", e)))?;
    if response_type != OCSP_BASIC_OID_DER {
        return Err(SignatureError::GeneralError(format!(
            "OCSP unexpected responseType OID ({} bytes): {:02x?}",
            response_type.len(),
            response_type
        )));
    }

    // ResponseBytes.response OCTET STRING — its contents are the
    // BasicOCSPResponse DER. XAdES embeds those bytes verbatim
    // inside <xades:EncapsulatedOCSPValue>.
    let basic = read_tlv(after_type, 0x04)
        .map_err(|e| SignatureError::GeneralError(format!("OCSP response OCTET STRING: {}", e)))?;
    Ok(basic.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::der::encode_tlv;

    #[test]
    fn extract_basic_response_rejects_failure_status() {
        // Build a fake response: responseStatus = 6 (unauthorized).
        let status = encode_tlv(0x0a, &[0x06]); // ENUMERATED 6
        let response = encode_tlv(0x30, &status);
        let err = extract_basic_ocsp_response(&response).unwrap_err();
        assert!(err.to_string().contains("OCSPResponseStatus"));
    }

    #[test]
    fn extract_basic_response_returns_octet_contents() {
        // status=0 + responseBytes [0] EXPLICIT { responseType, OCTET STRING "basic" }
        let status = encode_tlv(0x0a, &[0x00]);
        let oid = encode_tlv(0x06, OCSP_BASIC_OID_DER);
        let octet = encode_tlv(0x04, b"basic");
        let mut rb_inner = Vec::new();
        rb_inner.extend(&oid);
        rb_inner.extend(&octet);
        let rb = encode_tlv(0x30, &rb_inner);
        let rb_explicit = encode_tlv(0xa0, &rb);
        let mut value = Vec::new();
        value.extend(&status);
        value.extend(&rb_explicit);
        let response = encode_tlv(0x30, &value);
        let extracted = extract_basic_ocsp_response(&response).expect("extract");
        assert_eq!(extracted, b"basic");
    }
}
