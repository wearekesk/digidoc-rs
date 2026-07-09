//! Container read path: [`DigiDocReader`] parses an ASiC-E ZIP, extracts
//! the data files and signatures, and validates each signature against the
//! signer certificate. The `xml_serde`/`quick_xml`-shaped types at the
//! bottom of this file model the on-disk XAdES/manifest documents.

use std::fs::File;
use std::io::Read;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;
use x509_parser::prelude::*;

use super::DigiDocFile;
use crate::error::SignatureError;
use crate::xmldsig::{PublicKeyType, verify_signature};

pub struct DigiDocReader<'a> {
    document_path: &'a str,
}

#[derive(Debug, Clone)]
pub struct DigiDocSignatureInfo {
    pub certificate: Vec<u8>,
    pub signature_value: Vec<u8>,
    pub signed_info: String,
    pub signing_time: DateTime<Utc>,
    pub signer_info: DigiDocSignerInfo,
    pub signature_algorithm: String,
    pub digest_algorithm: String,
    pub is_valid: bool,
}

#[derive(Debug, Clone)]
pub struct DigiDocSignerInfo {
    pub common_name: String,
    pub serial_number: String,
    pub issuer: String,
    pub subject: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DigiDocValidationResult {
    pub is_valid: bool,
    pub signatures: Vec<DigiDocSignatureInfo>,
    pub files: Vec<DigiDocFile>,
    pub validation_errors: Vec<String>,
    pub validation_warnings: Vec<String>,
}

impl<'a> DigiDocReader<'a> {
    pub fn new(document_path: &'a str) -> Self {
        Self { document_path }
    }

    /// Parses and validates the DigiDoc/ASiC-E container.
    ///
    /// # Errors
    /// Returns a hard `Err(anyhow::Error)` for fatal preconditions where the archive
    /// is physically corrupt or unreadable:
    /// - Failure to open the file (`File::open`)
    /// - Failure to parse the ZIP structure (`ZipArchive::new`)
    /// - Missing or unreadable `manifest.xml` file
    /// - Structural zip entry reading/indexing errors
    ///
    /// Non-fatal issues (like missing files, invalid signatures, expired certificates,
    /// or incorrect mimetypes) are collected into the returned `DigiDocValidationResult`.
    pub fn parse_document(&self) -> Result<DigiDocValidationResult, anyhow::Error> {
        let document_zip_file = File::open(self.document_path)?;
        debug!("Parsing: {}", &self.document_path);
        let mut zip = zip::ZipArchive::new(document_zip_file)?;

        let mut validation_errors = Vec::new();
        let mut validation_warnings = Vec::new();

        // Validate MIME type
        let mut mimetype = String::new();
        match zip.by_name("mimetype") {
            Ok(mut f) => {
                f.read_to_string(&mut mimetype)?;
                if mimetype != "application/vnd.etsi.asic-e+zip" {
                    validation_errors
                        .push(format!("Unsupported document with mimetype: {}", mimetype));
                }
            }
            Err(e) => validation_errors.push(format!("Missing mimetype file: {}", e)),
        }

        let manifest_content = {
            let mut content = String::new();
            let mut zf = zip
                .by_name("META-INF/manifest.xml")
                .map_err(|e| anyhow!("Missing manifest.xml: {}", e))?;
            zf.read_to_string(&mut content)?;
            content
        };

        let manifest: DigiDocManifest = xml_serde::from_str(&manifest_content)
            .map_err(|e| anyhow!("Error parsing manifest: {}", e))?;

        debug!("{:?}", manifest);

        // Extract data files
        let mut files = Vec::new();
        for file_entry in &manifest.manifest.file_entries {
            match zip.by_name(&file_entry.full_path) {
                Ok(mut file) => {
                    let mut content = Vec::new();
                    file.read_to_end(&mut content)?;
                    files.push(DigiDocFile {
                        name: file_entry.full_path.clone(),
                        content,
                        mime_type: file_entry.media_type.clone(),
                    });
                }
                Err(e) => validation_warnings.push(format!(
                    "Could not read file {}: {}",
                    file_entry.full_path, e
                )),
            }
        }

        // Parse and validate signatures
        let mut signatures = Vec::new();
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            let zip_file_name = entry.name().to_owned();
            if !entry.is_file() || !zip_file_name.starts_with("META-INF/signatures") {
                continue;
            }
            debug!("Found signature file: {}", zip_file_name);
            let mut signature_content = String::new();
            entry.read_to_string(&mut signature_content)?;

            match parse_signature(signature_content) {
                Ok(mut sig_info) => {
                    // Validate signature
                    match self.validate_signature(&sig_info, &files) {
                        Ok(is_valid) => {
                            sig_info.is_valid = is_valid;
                            if !is_valid {
                                validation_errors.push(format!(
                                    "Signature by {} is invalid",
                                    sig_info.signer_info.common_name
                                ));
                            }
                        }
                        Err(e) => {
                            validation_errors.push(format!("Signature validation failed: {}", e));
                            sig_info.is_valid = false;
                        }
                    }

                    // Check certificate validity against signing time
                    // (not the current time) — archived documents
                    // remain valid even after the signing cert expires.
                    let signing_time = sig_info.signing_time;
                    if signing_time < sig_info.signer_info.not_before {
                        validation_errors.push(format!(
                            "Certificate not yet valid at signing time for {}",
                            sig_info.signer_info.common_name
                        ));
                    }
                    if signing_time > sig_info.signer_info.not_after {
                        validation_errors.push(format!(
                            "Certificate expired at signing time for {}",
                            sig_info.signer_info.common_name
                        ));
                    }

                    signatures.push(sig_info);
                }
                Err(e) => validation_errors.push(format!("Failed to parse signature: {}", e)),
            }
        }

        let is_valid = validation_errors.is_empty()
            && !signatures.is_empty()
            && signatures.iter().all(|s| s.is_valid);

        Ok(DigiDocValidationResult {
            is_valid,
            signatures,
            files,
            validation_errors,
            validation_warnings,
        })
    }

    fn validate_signature(
        &self,
        signature_info: &DigiDocSignatureInfo,
        files: &[DigiDocFile],
    ) -> Result<bool, anyhow::Error> {
        let (_, cert) = X509Certificate::from_der(&signature_info.certificate)?;

        let public_key = match cert.public_key().algorithm.algorithm.to_string().as_str() {
            "1.2.840.113549.1.1.1" => {
                use rsa::pkcs1::DecodeRsaPublicKey;
                let rsa_key =
                    rsa::RsaPublicKey::from_pkcs1_der(&cert.public_key().subject_public_key.data)?;
                PublicKeyType::Rsa(rsa_key)
            }
            "1.2.840.10045.2.1" => {
                let parameters = cert
                    .public_key()
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or_else(|| anyhow!("ECDSA missing parameters"))?;
                let oid = parameters
                    .as_oid()
                    .map_err(|e| anyhow!("Failed to parse ECDSA curve OID: {}", e))?;
                match oid.to_string().as_str() {
                    "1.2.840.10045.3.1.7" => {
                        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(
                            &cert.public_key().subject_public_key.data,
                        )?;
                        PublicKeyType::P256(key)
                    }
                    "1.3.132.0.10" => {
                        let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(
                            &cert.public_key().subject_public_key.data,
                        )?;
                        PublicKeyType::K256(key)
                    }
                    alg => return Err(anyhow!("Unsupported ECDSA curve: {}", alg)),
                }
            }
            alg => return Err(anyhow!("Unsupported public key algorithm: {}", alg)),
        };

        let file_resolver = |uri: &str| -> Result<Vec<u8>, SignatureError> {
            for file in files {
                if file.name == uri.trim_start_matches('#') {
                    return Ok(file.content.clone());
                }
            }
            Err(SignatureError::ReferenceNotFound(uri.to_string()))
        };

        match verify_signature(
            signature_info.signed_info.as_bytes(),
            &public_key,
            Some(file_resolver),
        ) {
            Ok(()) => Ok(true),
            Err(e) => {
                debug!("Signature verification failed: {:?}", e);
                Ok(false)
            }
        }
    }
}

/// Strip well-known namespace prefixes (`ds:`, `asic:`, `xades:`) from
/// XML **element and attribute names only**, leaving text content and
/// attribute values untouched.
///
/// The approach: scan byte-by-byte; when inside a `<…>` region we
/// replace occurrences of the prefix. Outside of tags the bytes are
/// copied verbatim — this prevents corrupting URIs or element text that
/// happen to contain the substring.
fn strip_tag_prefixes(xml: &str) -> String {
    const PREFIXES: &[&str] = &["ds:", "asic:", "xades:"];
    let mut out = String::with_capacity(xml.len());
    let mut inside_tag = false;
    let bytes = xml.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        let ch = bytes[i];

        if ch == b'<' {
            inside_tag = true;
            out.push('<');
            i += 1;
            continue;
        }
        if ch == b'>' {
            inside_tag = false;
            out.push('>');
            i += 1;
            continue;
        }

        if inside_tag {
            let mut matched = false;
            for prefix in PREFIXES {
                let pb = prefix.as_bytes();
                if i + pb.len() <= len && &bytes[i..i + pb.len()] == pb {
                    i += pb.len();
                    matched = true;
                    break;
                }
            }
            if !matched {
                out.push(ch as char);
                i += 1;
            }
        } else {
            out.push(ch as char);
            i += 1;
        }
    }
    out
}

fn parse_signature(signature_content: String) -> Result<DigiDocSignatureInfo, anyhow::Error> {
    // Strip well-known namespace prefixes from XML tags and attributes
    // only — a naive global `.replace("ds:", "")` would corrupt URIs,
    // element text, or attribute values that happen to contain the
    // substring.  We target only tag-position occurrences:
    //   opening tags:  <ds:Foo  →  <Foo
    //   closing tags:  </ds:Foo →  </Foo
    //   attributes:    xmlns:ds →  xmlns:ds  (left alone — quick_xml
    //                  handles the duplicate `xmlns` attrs gracefully)
    let signature_xml = strip_tag_prefixes(&signature_content);
    debug!("Signature XML: {}", signature_xml);
    let signature: XAdEsSignatures = quick_xml::de::from_str(&signature_xml)?;

    let cert_b64 = &signature.signature.key_info.x509_data.x509_certificate;
    let cert_der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, cert_b64)?;
    let (_, cert) = X509Certificate::from_der(&cert_der)?;

    let signature_value_b64 = &signature.signature.signature_value.text;
    let signature_value = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        signature_value_b64,
    )?;

    let signing_time_str = &signature
        .signature
        .object
        .qualifying_properties
        .signed_properties
        .signed_signature_properties
        .signing_time;
    let signing_time = chrono::DateTime::parse_from_rfc3339(signing_time_str)
        .map_err(|e| anyhow!("Failed to parse signing time: {}", e))?
        .with_timezone(&chrono::Utc);

    let signer_cert_info = DigiDocSignerInfo {
        common_name: extract_common_name(&cert)?,
        serial_number: format!("{:X}", cert.serial),
        issuer: cert.issuer().to_string(),
        subject: cert.subject().to_string(),
        not_before: x509_time_to_chrono(&cert.validity().not_before)?,
        not_after: x509_time_to_chrono(&cert.validity().not_after)?,
    };

    Ok(DigiDocSignatureInfo {
        certificate: cert_der,
        signature_value,
        signed_info: signature_content,
        signing_time,
        signer_info: signer_cert_info,
        signature_algorithm: signature.signature.signed_info.signature_method.algorithm,
        digest_algorithm: signature
            .signature
            .signed_info
            .reference
            .first()
            .map(|r| r.digest_method.algorithm.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        is_valid: false,
    })
}

fn extract_common_name(cert: &X509Certificate) -> Result<String, anyhow::Error> {
    for rdn in cert.subject().iter() {
        for attr_tv in rdn.iter() {
            if attr_tv.attr_type().to_string() == "2.5.4.3"
                && let Ok(cn_str) = attr_tv.attr_value().as_str()
            {
                return Ok(cn_str.to_string());
            }
        }
    }
    Ok("Unknown".to_string())
}

fn x509_time_to_chrono(
    x509_time: &x509_parser::time::ASN1Time,
) -> Result<DateTime<Utc>, anyhow::Error> {
    let timestamp = x509_time.timestamp();
    DateTime::from_timestamp(timestamp, 0).ok_or_else(|| anyhow!("Invalid timestamp"))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DigiDocManifest {
    #[serde(rename = "{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}manifest:manifest")]
    manifest: FileEntriesManifest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntriesManifest {
    #[serde(rename = "{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}manifest:file-entry")]
    file_entries: Vec<FileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    #[serde(
        rename = "$attr:{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}manifest:full-path"
    )]
    full_path: String,

    #[serde(
        rename = "$attr:{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}manifest:media-type"
    )]
    media_type: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "XAdESSignatures")]
pub struct XAdEsSignatures {
    #[serde(rename = "Signature")]
    signature: Signature,

    #[serde(rename = "@xmlns:asic")]
    xmlns_asic: String,

    #[serde(rename = "@xmlns:ds")]
    xmlns_ds: String,

    #[serde(rename = "@xmlns:xades")]
    xmlns_xades: String,
}

#[derive(Serialize, Deserialize)]
pub struct Signature {
    #[serde(rename = "SignedInfo")]
    signed_info: SignedInfo,

    #[serde(rename = "SignatureValue")]
    signature_value: SignatureValue,

    #[serde(rename = "KeyInfo")]
    key_info: KeyInfo,

    #[serde(rename = "Object")]
    object: Object,

    #[serde(rename = "@Id")]
    id: String,
}

#[derive(Serialize, Deserialize)]
pub struct KeyInfo {
    #[serde(rename = "X509Data")]
    x509_data: X509Data,
}

#[derive(Serialize, Deserialize)]
pub struct X509Data {
    #[serde(rename = "X509Certificate")]
    x509_certificate: String,
}

#[derive(Serialize, Deserialize)]
pub struct Object {
    #[serde(rename = "QualifyingProperties")]
    qualifying_properties: QualifyingProperties,
}

#[derive(Serialize, Deserialize)]
pub struct QualifyingProperties {
    #[serde(rename = "SignedProperties")]
    signed_properties: SignedProperties,

    #[serde(rename = "UnsignedProperties")]
    unsigned_properties: Option<UnsignedProperties>,

    #[serde(rename = "@Target")]
    target: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignedProperties {
    #[serde(rename = "SignedSignatureProperties")]
    signed_signature_properties: SignedSignatureProperties,

    #[serde(rename = "SignedDataObjectProperties")]
    signed_data_object_properties: SignedDataObjectProperties,

    #[serde(rename = "@Id")]
    id: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignedDataObjectProperties {
    #[serde(rename = "DataObjectFormat")]
    data_object_format: DataObjectFormat,
}

#[derive(Serialize, Deserialize)]
pub struct DataObjectFormat {
    #[serde(rename = "MimeType")]
    mime_type: String,

    #[serde(rename = "@ObjectReference")]
    object_reference: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignedSignatureProperties {
    #[serde(rename = "SigningTime")]
    signing_time: String,

    #[serde(rename = "SigningCertificate")]
    signing_certificate: SigningCertificate,
}

#[derive(Serialize, Deserialize)]
pub struct SigningCertificate {
    #[serde(rename = "Cert")]
    cert: Cert,
}

#[derive(Serialize, Deserialize)]
pub struct Cert {
    #[serde(rename = "CertDigest")]
    cert_digest: CertDigest,

    #[serde(rename = "IssuerSerial")]
    issuer_serial: IssuerSerial,
}

#[derive(Serialize, Deserialize)]
pub struct CertDigest {
    #[serde(rename = "DigestMethod")]
    digest_method: Method,

    #[serde(rename = "DigestValue")]
    digest_value: String,
}

#[derive(Serialize, Deserialize)]
pub struct Method {
    #[serde(rename = "@Algorithm")]
    algorithm: String,
}

#[derive(Serialize, Deserialize)]
pub struct IssuerSerial {
    #[serde(rename = "X509IssuerName")]
    x509_issuer_name: String,

    #[serde(rename = "X509SerialNumber")]
    x509_serial_number: String,
}

#[derive(Serialize, Deserialize)]
pub struct UnsignedProperties {
    #[serde(rename = "UnsignedSignatureProperties")]
    unsigned_signature_properties: UnsignedSignatureProperties,
}

#[derive(Serialize, Deserialize)]
pub struct UnsignedSignatureProperties {
    #[serde(rename = "SignatureTimeStamp")]
    pub signature_time_stamp: Option<SignatureTimeStamp>,

    #[serde(rename = "CertificateValues")]
    pub certificate_values: Option<CertificateValues>,

    #[serde(rename = "RevocationValues")]
    pub revocation_values: Option<RevocationValues>,
}

#[derive(Serialize, Deserialize)]
pub struct CertificateValues {
    #[serde(rename = "EncapsulatedX509Certificate")]
    encapsulated_x509_certificate: SignatureValue,
}

#[derive(Serialize, Deserialize)]
pub struct SignatureValue {
    #[serde(rename = "@Id")]
    id: String,

    #[serde(rename = "$value")]
    text: String,
}

#[derive(Serialize, Deserialize)]
pub struct RevocationValues {
    #[serde(rename = "OCSPValues")]
    ocsp_values: OcspValues,
}

#[derive(Serialize, Deserialize)]
pub struct OcspValues {
    #[serde(rename = "EncapsulatedOCSPValue")]
    encapsulated_ocsp_value: SignatureValue,
}

#[derive(Serialize, Deserialize)]
pub struct SignatureTimeStamp {
    #[serde(rename = "CanonicalizationMethod")]
    canonicalization_method: Method,

    #[serde(rename = "EncapsulatedTimeStamp")]
    encapsulated_time_stamp: String,

    #[serde(rename = "@Id")]
    id: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignedInfo {
    #[serde(rename = "CanonicalizationMethod")]
    canonicalization_method: Method,

    #[serde(rename = "SignatureMethod")]
    signature_method: Method,

    #[serde(rename = "Reference")]
    reference: Vec<Reference>,
}

#[derive(Serialize, Deserialize)]
pub struct Reference {
    #[serde(rename = "DigestMethod")]
    digest_method: Method,

    #[serde(rename = "DigestValue")]
    digest_value: String,

    #[serde(rename = "@Id")]
    id: String,

    #[serde(rename = "@URI")]
    uri: String,

    #[serde(rename = "@Type")]
    reference_type: Option<String>,
}
