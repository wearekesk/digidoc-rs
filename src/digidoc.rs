use std::fs::{File, create_dir_all};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use x509_parser::prelude::*;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::FileOptions};

use crate::error::SignatureError;
use crate::xmldsig::{
    PublicKeyType, Signer as XmldsigSigner, XadesDataFile, XadesProductionPlace,
    XadesSignatureInputs, build_xades_basic_signature, upgrade_xades_bes_to_t,
    upgrade_xades_t_to_lt, verify_signature,
};

// BDOC container format
// Based on https://open-eid.github.io/libdigidocpp/manual.html
// Only supports BDOC 2.1 digitally signed file formats.
// The ETSI standard TS 102 918 called Associated Signature Containers (ASiC) defines format of container for encapsulation of signed files and signatures with extra information. The ETSI TS 103 174 "ASiC Baseline Profile" profiles in further on. The container type used in case of BDOC 2.1 documents is Associated Signature Extended form (ASiC-E).
// ASiC-E container is a ZIP file consisting of the following objects:
// a file named "mimetype", containing only the following value: application/vnd.etsi.asic-e+zip
// data files in original format.
// META-INF subdirectory, consisting of:
// manifest.xml – a file containing list of all files in the container. The list does not contain the "mimetype" file and files in META-INF subdirectory.
// signatures*.xml – one file for each signature, ‘*’ in the file’s name denotes the sequence number of a signature (counting starts from zero). The signatures*.xml file also incorporates certificates, validity confirmation and meta-data about the signer.
// When BDOC 2.1 container is signed then all files in the container are signed, except of the mimetype file and files in META-INF subdirectory.
pub struct DigiDocReader<'a> {
    document_path: &'a str,
}

#[derive(Debug, Clone)]
pub struct DigiDocFile {
    pub name: String,
    pub content: Vec<u8>,
    pub mime_type: String,
}

/// A pre-computed signature embedded into the container as-is.
///
/// **Deprecated** in favour of [`DigiDocBuilder::add_signer`] which
/// computes the per-file digests, certificate digest, and
/// SignedProperties digest and signs the canonical `SignedInfo`
/// bytes itself — the result actually verifies. This struct
/// shipped a `signed_info: String` field that the old builder
/// then discarded in favour of a placeholder template with empty
/// `<ds:DigestValue>` elements, which is why containers built
/// through `add_signature` were never accepted by any real XAdES
/// verifier (e.g. Estonian DigiDoc4).
#[derive(Debug, Clone)]
pub struct DigiDocSignature {
    pub certificate: Vec<u8>,
    pub signature_value: Vec<u8>,
    pub signed_info: String,
    pub signing_time: DateTime<Utc>,
}

/// Inputs for building a signature in `add_signer` mode — the
/// builder owns the canonical-XML / digest-computation flow and
/// only delegates the raw `sign(canonical_signed_info_bytes)`
/// step to the supplied signer. Works with anything that
/// implements [`crate::xmldsig::Signer`] — software keys
/// (RSA / P-256 / K-256) today, hardware-token wrappers later.
pub struct DigiDocSignerInput {
    pub signer: Box<dyn XmldsigSigner>,
    /// X.509 certificate in DER encoding. Issuer name and serial
    /// number are parsed out of this for the
    /// `<xades:IssuerSerial>` block; the bytes themselves are
    /// SHA-256'd for `<xades:CertDigest>` and base64-embedded as
    /// `<ds:X509Certificate>`.
    pub certificate_der: Vec<u8>,
    pub signing_time: DateTime<Utc>,
    /// Optional `<xades:SignatureProductionPlace>` block —
    /// DigiDoc4's "Role and address" panel renders these as the
    /// City / State / Country / Zip rows. Each field is
    /// independently optional; omitted ones are skipped.
    pub production_place: Option<DigiDocProductionPlace>,
    /// Optional list of claimed roles — each entry becomes one
    /// `<xades:ClaimedRole>` and surfaces in DigiDoc4's "Role /
    /// resolution" field. Empty → block omitted.
    pub claimed_roles: Vec<String>,
    /// Optional RFC 3161 Time-Stamp Authority URL. When set,
    /// `create_container` upgrades the signature from XAdES-BES
    /// to XAdES-T by sending the canonicalised
    /// `<ds:SignatureValue>` to the TSA, embedding the returned
    /// token in `<xades:UnsignedProperties>`. DigiDoc4 requires
    /// at least XAdES-T before reporting a signature as valid.
    /// `None` → BES only (structurally complete, but DigiDoc4
    /// reports `'UnsignedProperties' is missing`).
    pub tsa_url: Option<String>,
    /// Optional RFC 6960 OCSP responder URL. When set (and
    /// `tsa_url` is also set), `create_container` upgrades the
    /// signature from XAdES-T to XAdES-LT by fetching an OCSP
    /// response for the signer cert and embedding it +
    /// the issuer cert under `<xades:UnsignedSignatureProperties>`.
    /// DigiDoc4 requires LT for "valid" status — `T` reports
    /// `RevocationValues object is missing`.
    /// `None` (or `tsa_url == None`) → no LT upgrade.
    pub ocsp_url: Option<String>,
    /// Optional DER bytes of the issuer (CA) certificate that
    /// signed the signer cert. Required for the XAdES-LT
    /// upgrade — the OCSP `CertID` is built from issuer DN +
    /// public-key hashes, and libdigidocpp expects the issuer
    /// cert under `<xades:CertificateValues>`. For self-signed
    /// signer certs, leave `None` and the builder uses
    /// `certificate_der` as its own issuer.
    pub issuer_cert_der: Option<Vec<u8>>,
}

/// Caller-supplied production place — mirrors
/// [`crate::xmldsig::XadesProductionPlace`] but owns its strings
/// so the `DigiDocBuilder` can keep the inputs across the build
/// step.
#[derive(Default, Debug, Clone)]
pub struct DigiDocProductionPlace {
    pub city: Option<String>,
    pub state_or_province: Option<String>,
    pub postal_code: Option<String>,
    pub country_name: Option<String>,
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

/// Serde-only mirror of the ASIC-E manifest schema, used purely
/// for serialisation by [`DigiDocBuilder::create_manifest`]. Lives
/// alongside the existing `DigiDocManifest` further down the file
/// (which is `xml_serde`-shaped for the READER path); kept
/// separate because quick_xml and xml_serde disagree about how
/// namespace-prefixed attributes are encoded in serde renames.
#[derive(Serialize, Debug)]
#[serde(rename = "manifest:manifest")]
struct ManifestRoot<'a> {
    #[serde(rename = "@xmlns:manifest")]
    xmlns_manifest: &'a str,
    #[serde(rename = "manifest:file-entry")]
    entries: Vec<ManifestFileEntry<'a>>,
}

#[derive(Serialize, Debug)]
struct ManifestFileEntry<'a> {
    #[serde(rename = "@manifest:full-path")]
    full_path: &'a str,
    #[serde(rename = "@manifest:media-type")]
    media_type: &'a str,
}

pub struct DigiDocBuilder {
    files: Vec<DigiDocFile>,
    /// Pre-computed signatures (deprecated entry point — kept for
    /// API compatibility, but `create_container` flags any present
    /// here as malformed).
    signatures: Vec<DigiDocSignature>,
    /// Active signing inputs — the builder runs the full XAdES
    /// dance (file digests, cert digest, SignedProperties digest,
    /// SignedInfo canonicalisation, then signer.sign()) for each
    /// of these on `create_container`.
    signers: Vec<DigiDocSignerInput>,
}

impl DigiDocBuilder {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            signatures: Vec::new(),
            signers: Vec::new(),
        }
    }

    /// Attach a software / hardware signer that the builder will
    /// drive end-to-end during `create_container`. Use this in
    /// preference to [`Self::add_signature`] — that legacy entry
    /// point can't produce containers that actually verify.
    pub fn add_signer(mut self, input: DigiDocSignerInput) -> Self {
        self.signers.push(input);
        self
    }

    pub fn add_file<P: AsRef<Path>>(
        mut self,
        file_path: P,
        mime_type: &str,
    ) -> Result<Self, anyhow::Error> {
        let path = file_path.as_ref();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("Invalid file name"))?
            .to_string();

        let content = std::fs::read(path)?;

        self.files.push(DigiDocFile {
            name,
            content,
            mime_type: mime_type.to_string(),
        });

        Ok(self)
    }

    pub fn add_file_content(mut self, name: String, content: Vec<u8>, mime_type: &str) -> Self {
        self.files.push(DigiDocFile {
            name,
            content,
            mime_type: mime_type.to_string(),
        });
        self
    }

    pub fn add_signature(mut self, signature: DigiDocSignature) -> Self {
        self.signatures.push(signature);
        self
    }

    pub async fn create_container<P: AsRef<Path>>(
        &self,
        output_path: P,
    ) -> Result<(), anyhow::Error> {
        let path = output_path.as_ref();

        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }

        let file = File::create(path)?;
        let mut zip = ZipWriter::new(file);

        // Add mimetype file (must be first and uncompressed)
        let options: FileOptions<()> =
            FileOptions::default().compression_method(CompressionMethod::Stored);
        zip.start_file("mimetype", options)?;
        zip.write_all(b"application/vnd.etsi.asic-e+zip")?;

        // Add data files
        let options: FileOptions<()> =
            FileOptions::default().compression_method(CompressionMethod::Deflated);

        for file in &self.files {
            zip.start_file(&file.name, options)?;
            zip.write_all(&file.content)?;
        }

        // Create manifest.xml
        let manifest = self.create_manifest()?;
        zip.start_file("META-INF/manifest.xml", options)?;
        zip.write_all(manifest.as_bytes())?;

        // Add signature files
        let mut sig_index = 0usize;
        for signature in &self.signatures {
            let signature_xml = self.create_signature_xml(signature, sig_index)?;
            zip.start_file(format!("META-INF/signatures{}.xml", sig_index), options)?;
            zip.write_all(signature_xml.as_bytes())?;
            sig_index += 1;
        }
        for input in &self.signers {
            let signature_xml = self.build_xades_signature(input, sig_index).await?;
            zip.start_file(format!("META-INF/signatures{}.xml", sig_index), options)?;
            zip.write_all(signature_xml.as_bytes())?;
            sig_index += 1;
        }

        zip.finish()?;
        info!("DigiDoc container created at: {}", path.display());
        Ok(())
    }

    async fn build_xades_signature(
        &self,
        input: &DigiDocSignerInput,
        index: usize,
    ) -> Result<String, anyhow::Error> {
        let data_files: Vec<XadesDataFile<'_>> = self
            .files
            .iter()
            .map(|f| XadesDataFile {
                uri: &f.name,
                mime_type: &f.mime_type,
                content: &f.content,
            })
            .collect();
        let production_place = input
            .production_place
            .as_ref()
            .map(|p| XadesProductionPlace {
                city: p.city.as_deref(),
                state_or_province: p.state_or_province.as_deref(),
                postal_code: p.postal_code.as_deref(),
                country_name: p.country_name.as_deref(),
            });
        let claimed_roles: Vec<&str> = input.claimed_roles.iter().map(String::as_str).collect();
        let bes = build_xades_basic_signature(&XadesSignatureInputs {
            signer: &*input.signer,
            certificate_der: &input.certificate_der,
            signing_time: input.signing_time,
            data_files: &data_files,
            index,
            production_place,
            claimed_roles: &claimed_roles,
        })
        .map_err(|e: SignatureError| anyhow!("xades signature build: {}", e))?;

        let tsa_url = match &input.tsa_url {
            None => return Ok(bes.xml),
            Some(url) => url,
        };

        // BES → T (timestamp the SignatureValue)
        let token = crate::tsa::fetch_timestamp_token(tsa_url, &bes.signature_value_canonical)
            .await
            .map_err(|e: SignatureError| anyhow!("TSA timestamp fetch: {}", e))?;
        let t_xml = upgrade_xades_bes_to_t(&bes, &token)
            .map_err(|e: SignatureError| anyhow!("xades-T upgrade: {}", e))?;

        let ocsp_url = match &input.ocsp_url {
            None => return Ok(t_xml),
            Some(url) => url,
        };

        // T → LT (OCSP-validate the signer cert)
        let issuer_cert = input
            .issuer_cert_der
            .as_deref()
            .unwrap_or(&input.certificate_der);
        let ocsp_response =
            crate::ocsp::fetch_ocsp_response(ocsp_url, &input.certificate_der, issuer_cert)
                .await
                .map_err(|e: SignatureError| anyhow!("OCSP fetch: {}", e))?;
        upgrade_xades_t_to_lt(&t_xml, &bes.signature_id, issuer_cert, &ocsp_response)
            .map_err(|e: SignatureError| anyhow!("xades-LT upgrade: {}", e))
    }

    fn create_manifest(&self) -> Result<String, anyhow::Error> {
        let mut entries: Vec<ManifestFileEntry<'_>> = Vec::with_capacity(self.files.len() + 1);
        entries.push(ManifestFileEntry {
            full_path: "/",
            media_type: "application/vnd.etsi.asic-e+zip",
        });
        for file in &self.files {
            entries.push(ManifestFileEntry {
                full_path: &file.name,
                media_type: &file.mime_type,
            });
        }
        let manifest = ManifestRoot {
            xmlns_manifest: "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0",
            entries,
        };
        let body = quick_xml::se::to_string(&manifest)
            .map_err(|e| anyhow!("manifest serialise: {}", e))?;
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
            body
        ))
    }

    fn create_signature_xml(
        &self,
        signature: &DigiDocSignature,
        index: usize,
    ) -> Result<String, anyhow::Error> {
        let signature_id = format!("S{}", index);
        let signed_properties_id = format!("SP{}", index);

        let cert_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &signature.certificate,
        );
        let sig_value_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &signature.signature_value,
        );

        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<asic:XAdESSignatures xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">\n  <ds:Signature Id=\"{}\">\n    <ds:SignedInfo>\n      <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n      <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n      <ds:Reference URI=\"\">\n        <ds:Transforms>\n          <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n        </ds:Transforms>\n        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n        <ds:DigestValue></ds:DigestValue>\n      </ds:Reference>\n      <ds:Reference URI=\"#{}\" Type=\"http://uri.etsi.org/01903#SignedProperties\">\n        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n        <ds:DigestValue></ds:DigestValue>\n      </ds:Reference>\n    </ds:SignedInfo>\n    <ds:SignatureValue Id=\"{}-SIG\">{}</ds:SignatureValue>\n    <ds:KeyInfo>\n      <ds:X509Data>\n        <ds:X509Certificate>{}</ds:X509Certificate>\n      </ds:X509Data>\n    </ds:KeyInfo>\n    <ds:Object>\n      <xades:QualifyingProperties Target=\"#{}\">\n        <xades:SignedProperties Id=\"{}\">\n          <xades:SignedSignatureProperties>\n            <xades:SigningTime>{}</xades:SigningTime>\n            <xades:SigningCertificate>\n              <xades:Cert>\n                <xades:CertDigest>\n                  <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n                  <ds:DigestValue></ds:DigestValue>\n                </xades:CertDigest>\n                <xades:IssuerSerial>\n                  <ds:X509IssuerName></ds:X509IssuerName>\n                  <ds:X509SerialNumber></ds:X509SerialNumber>\n                </xades:IssuerSerial>\n              </xades:Cert>\n            </xades:SigningCertificate>\n          </xades:SignedSignatureProperties>\n          <xades:SignedDataObjectProperties>\n            <xades:DataObjectFormat ObjectReference=\"\">\n              <xades:MimeType>application/octet-stream</xades:MimeType>\n            </xades:DataObjectFormat>\n          </xades:SignedDataObjectProperties>\n        </xades:SignedProperties>\n      </xades:QualifyingProperties>\n    </ds:Object>\n  </ds:Signature>\n</asic:XAdESSignatures>",
            signature_id,
            signed_properties_id,
            signature_id,
            sig_value_b64,
            cert_b64,
            signature_id,
            signed_properties_id,
            signature.signing_time.to_rfc3339()
        );

        Ok(xml)
    }
}

impl Default for DigiDocBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> DigiDocReader<'a> {
    pub fn new(document_path: &'a str) -> Self {
        Self { document_path }
    }

    pub fn parse_document(&self) -> Result<DigiDocValidationResult, anyhow::Error> {
        let document_zip_file = File::open(self.document_path)?;
        debug!("Parsing: {}", &self.document_path);
        let mut zip = ZipArchive::new(document_zip_file)?;

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

        // Parse manifest
        let mut manifest_content = String::new();
        match zip.by_name("META-INF/manifest.xml") {
            Ok(mut zf) => {
                zf.read_to_string(&mut manifest_content)?;
            }
            Err(e) => validation_errors.push(format!("Missing manifest.xml: {}", e)),
        }

        let manifest: DigiDocManifest = xml_serde::from_str(&manifest_content).map_err(|e| {
            validation_errors.push(format!("Error parsing manifest: {}", e));
            anyhow!("Error parsing manifest: {}", e)
        })?;

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

                    // Check certificate validity
                    let now = chrono::Utc::now();
                    if now < sig_info.signer_info.not_before {
                        validation_errors.push(format!(
                            "Certificate not yet valid for {}",
                            sig_info.signer_info.common_name
                        ));
                    }
                    if now > sig_info.signer_info.not_after {
                        validation_errors.push(format!(
                            "Certificate expired for {}",
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

fn parse_signature(signature_content: String) -> Result<DigiDocSignatureInfo, anyhow::Error> {
    let signature_xml = signature_content
        .replace("ds:", "")
        .replace("asic:", "")
        .replace("xades:", "");
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
    unsigned_properties: UnsignedProperties,

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
    signature_time_stamp: SignatureTimeStamp,

    #[serde(rename = "CertificateValues")]
    certificate_values: CertificateValues,

    #[serde(rename = "RevocationValues")]
    revocation_values: RevocationValues,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::NamedTempFile;

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(fut)
    }

    fn sample_signature() -> DigiDocSignature {
        DigiDocSignature {
            certificate: vec![0xAAu8; 32],
            signature_value: vec![0xBBu8; 64],
            signed_info: "<ds:SignedInfo/>".to_string(),
            signing_time: chrono::Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap(),
        }
    }

    fn build_container(
        files: &[(&str, &[u8], &str)],
        signatures: Vec<DigiDocSignature>,
    ) -> NamedTempFile {
        let mut builder = DigiDocBuilder::new();
        for (name, content, mime) in files {
            builder = builder.add_file_content(name.to_string(), content.to_vec(), mime);
        }
        for sig in signatures {
            builder = builder.add_signature(sig);
        }
        let tmp = NamedTempFile::new().expect("tempfile");
        block_on(builder.create_container(tmp.path())).expect("create_container");
        tmp
    }

    #[test]
    fn container_starts_with_uncompressed_mimetype_entry() {
        let tmp = build_container(&[("request.xml", b"<doc/>", "application/xml")], vec![]);
        let f = std::fs::File::open(tmp.path()).unwrap();
        let mut zip = ZipArchive::new(f).unwrap();

        let first_name = zip.by_index(0).unwrap().name().to_owned();
        assert_eq!(first_name, "mimetype");
        let mut entry = zip.by_index(0).unwrap();
        assert_eq!(
            entry.compression(),
            zip::CompressionMethod::Stored,
            "mimetype must be stored uncompressed"
        );
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"application/vnd.etsi.asic-e+zip");
    }

    #[test]
    fn container_writes_data_files_verbatim() {
        let payload: Vec<u8> = (0u8..=255).collect();
        let tmp = build_container(
            &[("payload.bin", &payload, "application/octet-stream")],
            vec![],
        );
        let f = std::fs::File::open(tmp.path()).unwrap();
        let mut zip = ZipArchive::new(f).unwrap();
        let mut entry = zip.by_name("payload.bin").expect("data file present");
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, payload);
    }

    #[test]
    fn container_emits_manifest_listing_data_files_only() {
        let tmp = build_container(
            &[
                ("request.xml", b"<a/>", "application/xml"),
                ("attachment.pdf", b"%PDF", "application/pdf"),
            ],
            vec![],
        );
        let f = std::fs::File::open(tmp.path()).unwrap();
        let mut zip = ZipArchive::new(f).unwrap();
        let mut entry = zip
            .by_name("META-INF/manifest.xml")
            .expect("manifest present");
        let mut s = String::new();
        entry.read_to_string(&mut s).unwrap();

        assert!(s.contains("manifest:full-path=\"request.xml\""));
        assert!(s.contains("manifest:media-type=\"application/xml\""));
        assert!(s.contains("manifest:full-path=\"attachment.pdf\""));
        assert!(s.contains("manifest:media-type=\"application/pdf\""));
        assert!(
            !s.contains("full-path=\"mimetype\""),
            "manifest must not list the mimetype file: {}",
            s
        );
        assert!(
            !s.contains("META-INF/"),
            "manifest must not list META-INF/* entries: {}",
            s
        );
    }

    #[test]
    fn container_writes_one_signatures_xml_per_signature() {
        let sig0 = sample_signature();
        let mut sig1 = sample_signature();
        sig1.certificate = vec![0xCCu8; 32];
        sig1.signature_value = vec![0xDDu8; 64];
        let tmp = build_container(
            &[("request.xml", b"<a/>", "application/xml")],
            vec![sig0.clone(), sig1.clone()],
        );

        let f = std::fs::File::open(tmp.path()).unwrap();
        let mut zip = ZipArchive::new(f).unwrap();

        for (idx, sig) in [&sig0, &sig1].iter().enumerate() {
            let path = format!("META-INF/signatures{}.xml", idx);
            let mut entry = zip
                .by_name(&path)
                .unwrap_or_else(|_| panic!("expected {} in archive", path));
            let mut s = String::new();
            entry.read_to_string(&mut s).unwrap();

            assert!(
                s.contains(&format!("Id=\"S{}\"", idx)),
                "signatures{}.xml should declare Id=\"S{}\", got: {}",
                idx,
                idx,
                s
            );
            let cert_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &sig.certificate,
            );
            let sig_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &sig.signature_value,
            );
            assert!(
                s.contains(&cert_b64),
                "signatures{}.xml should embed the certificate in base64",
                idx
            );
            assert!(
                s.contains(&sig_b64),
                "signatures{}.xml should embed the signature value in base64",
                idx
            );
        }
    }

    #[test]
    fn container_omits_signatures_directory_when_no_signatures_added() {
        let tmp = build_container(&[("request.xml", b"<a/>", "application/xml")], vec![]);
        let f = std::fs::File::open(tmp.path()).unwrap();
        let mut zip = ZipArchive::new(f).unwrap();

        let n = zip.len();
        for i in 0..n {
            let entry = zip.by_index(i).unwrap();
            assert!(
                !entry.name().starts_with("META-INF/signatures"),
                "no signatures*.xml entry should appear without signatures, got: {}",
                entry.name()
            );
        }
    }

    #[test]
    fn add_file_reads_from_disk_and_preserves_bytes() {
        let mut src = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut src, b"on-disk-payload").unwrap();
        let builder = DigiDocBuilder::new()
            .add_file(src.path(), "text/plain")
            .expect("add_file");
        let out = NamedTempFile::new().unwrap();
        block_on(builder.create_container(out.path())).expect("create_container");

        let f = std::fs::File::open(out.path()).unwrap();
        let mut zip = ZipArchive::new(f).unwrap();
        let entry_name = src
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mut entry = zip.by_name(&entry_name).expect("disk-backed file present");
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"on-disk-payload");
    }
}
