//! Container write path: [`DigiDocBuilder`] assembles the ASiC-E ZIP,
//! writes the manifest, and drives the full XAdES signing flow
//! (BES → optional T → optional LT) for each configured signer.

use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::info;
use zip::{CompressionMethod, ZipWriter, write::FileOptions};

use super::DigiDocFile;
use crate::error::SignatureError;
use crate::pki::{fetch_ocsp_response, fetch_timestamp_token};
use crate::xmldsig::{
    Signer as XmldsigSigner, XadesDataFile, XadesProductionPlace, XadesSignatureInputs,
    build_xades_basic_signature, upgrade_xades_bes_to_t, upgrade_xades_t_to_lt,
};

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

/// Serde-only mirror of the ASIC-E manifest schema, used purely
/// for serialisation by [`DigiDocBuilder::create_manifest`]. The
/// reader path uses its own `xml_serde`-shaped types; kept
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
            signers: Vec::new(),
        }
    }

    /// Attach a software / hardware signer that the builder will
    /// drive end-to-end during `create_container`.
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
        for (sig_index, input) in self.signers.iter().enumerate() {
            let signature_xml = self.build_xades_signature(input, sig_index).await?;
            zip.start_file(format!("META-INF/signatures{}.xml", sig_index), options)?;
            zip.write_all(signature_xml.as_bytes())?;
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
        let token = fetch_timestamp_token(tsa_url, &bes.signature_value_canonical)
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
            fetch_ocsp_response(ocsp_url, &input.certificate_der, issuer_cert)
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
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", body))
    }
}

impl Default for DigiDocBuilder {
    fn default() -> Self {
        Self::new()
    }
}
