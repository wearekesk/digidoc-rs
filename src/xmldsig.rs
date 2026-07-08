use base64::{Engine as _, engine::general_purpose};
use quick_xml::se::to_string;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{
        Signature as RsaSignature, SigningKey as RsaSigningKey,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str;

// Use specific ECDSA signing/verifying key types and traits
use k256::ecdsa::{
    Signature as K256Signature, SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};

use crate::error::{Result, SignatureError};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename(serialize = "ds:SignedInfo", deserialize = "SignedInfo"))]
pub struct SignedInfo {
    #[serde(
        rename(serialize = "@xmlns:asic", deserialize = "@xmlns:asic"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    xmlns_asic: Option<String>,
    #[serde(
        rename(serialize = "@xmlns:ds", deserialize = "@xmlns:ds"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    xmlns_ds: Option<String>,
    #[serde(
        rename(serialize = "@xmlns:xades", deserialize = "@xmlns:xades"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    xmlns_xades: Option<String>,
    #[serde(rename(
        serialize = "ds:CanonicalizationMethod",
        deserialize = "CanonicalizationMethod"
    ))]
    canonicalization_method: CanonicalizationMethod,
    #[serde(rename(serialize = "ds:SignatureMethod", deserialize = "SignatureMethod"))]
    signature_method: SignatureMethod,
    #[serde(rename(serialize = "ds:Reference", deserialize = "Reference"))]
    references: Vec<Reference>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename(
    serialize = "ds:CanonicalizationMethod",
    deserialize = "CanonicalizationMethod"
))]
pub struct CanonicalizationMethod {
    #[serde(rename = "@Algorithm")]
    algorithm: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename(serialize = "ds:SignatureMethod", deserialize = "SignatureMethod"))]
pub struct SignatureMethod {
    #[serde(rename = "@Algorithm")]
    algorithm: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename(serialize = "ds:Reference", deserialize = "Reference"))]
pub struct Reference {
    #[serde(rename = "@Id", default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "@Type", default, skip_serializing_if = "Option::is_none")]
    reference_type: Option<String>,
    #[serde(rename = "@URI")]
    uri: String,
    #[serde(
        rename(serialize = "ds:Transforms", deserialize = "Transforms"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    transforms: Option<Transforms>,
    #[serde(rename(serialize = "ds:DigestMethod", deserialize = "DigestMethod"))]
    digest_method: DigestMethod,
    #[serde(rename(serialize = "ds:DigestValue", deserialize = "DigestValue"))]
    digest_value: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename(serialize = "ds:Transforms", deserialize = "Transforms"))]
pub struct Transforms {
    #[serde(rename(serialize = "ds:Transform", deserialize = "Transform"))]
    transform: Vec<Transform>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename(serialize = "ds:Transform", deserialize = "Transform"))]
pub struct Transform {
    #[serde(rename = "@Algorithm")]
    algorithm: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename(serialize = "ds:DigestMethod", deserialize = "DigestMethod"))]
pub struct DigestMethod {
    #[serde(rename = "@Algorithm")]
    algorithm: String,
}

#[derive(Serialize, Debug)]
#[serde(rename = "asic:XAdESSignatures")]
struct XadesSignaturesEnvelope<'a> {
    #[serde(rename = "@xmlns:asic")]
    xmlns_asic: &'a str,
    #[serde(rename = "@xmlns:ds")]
    xmlns_ds: &'a str,
    #[serde(rename = "@xmlns:xades")]
    xmlns_xades: &'a str,
    #[serde(rename = "ds:Signature")]
    signature: XadesSignatureElement<'a>,
}

#[derive(Serialize, Debug)]
struct XadesSignatureElement<'a> {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "ds:SignedInfo")]
    signed_info: SignedInfo,
    #[serde(rename = "ds:SignatureValue")]
    signature_value: SignatureValueElement,
    #[serde(rename = "ds:KeyInfo")]
    key_info: KeyInfoX509,
    #[serde(rename = "ds:Object")]
    object: XadesObjectElement<'a>,
}

#[derive(Serialize, Debug)]
struct SignatureValueElement {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "$text")]
    value: String,
}

#[derive(Serialize, Debug)]
struct KeyInfoX509 {
    #[serde(rename = "ds:X509Data")]
    x509_data: X509DataElement,
}

#[derive(Serialize, Debug)]
struct X509DataElement {
    #[serde(rename = "ds:X509Certificate")]
    x509_certificate: String,
}

#[derive(Serialize, Debug)]
struct XadesObjectElement<'a> {
    #[serde(rename = "xades:QualifyingProperties")]
    qualifying_properties: XadesQualifyingProperties<'a>,
}

#[derive(Serialize, Debug)]
struct XadesQualifyingProperties<'a> {
    #[serde(rename = "@Target")]
    target: String,
    #[serde(rename = "xades:SignedProperties")]
    signed_properties: XadesSignedProperties<'a>,
}

#[derive(Serialize, Debug)]
#[serde(rename = "xades:SignedProperties")]
struct XadesSignedProperties<'a> {
    #[serde(rename = "@xmlns:asic")]
    xmlns_asic: &'a str,
    #[serde(rename = "@xmlns:ds")]
    xmlns_ds: &'a str,
    #[serde(rename = "@xmlns:xades")]
    xmlns_xades: &'a str,
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "xades:SignedSignatureProperties")]
    signed_signature_properties: XadesSignedSignatureProperties<'a>,
    #[serde(rename = "xades:SignedDataObjectProperties")]
    signed_data_object_properties: XadesSignedDataObjectProperties<'a>,
}

#[derive(Serialize, Debug)]
struct XadesSignedSignatureProperties<'a> {
    #[serde(rename = "xades:SigningTime")]
    signing_time: String,
    #[serde(rename = "xades:SigningCertificate")]
    signing_certificate: XadesSigningCertificate,
    #[serde(
        rename = "xades:SignatureProductionPlace",
        skip_serializing_if = "Option::is_none"
    )]
    production_place: Option<XadesProductionPlaceXml<'a>>,
    #[serde(rename = "xades:SignerRole", skip_serializing_if = "Option::is_none")]
    signer_role: Option<XadesSignerRoleXml<'a>>,
}

#[derive(Serialize, Debug)]
struct XadesProductionPlaceXml<'a> {
    #[serde(rename = "xades:City", skip_serializing_if = "Option::is_none")]
    city: Option<&'a str>,
    #[serde(
        rename = "xades:StateOrProvince",
        skip_serializing_if = "Option::is_none"
    )]
    state_or_province: Option<&'a str>,
    #[serde(rename = "xades:PostalCode", skip_serializing_if = "Option::is_none")]
    postal_code: Option<&'a str>,
    #[serde(rename = "xades:CountryName", skip_serializing_if = "Option::is_none")]
    country_name: Option<&'a str>,
}

#[derive(Serialize, Debug)]
struct XadesSignerRoleXml<'a> {
    #[serde(rename = "xades:ClaimedRoles")]
    claimed_roles: XadesClaimedRolesXml<'a>,
}

#[derive(Serialize, Debug)]
struct XadesClaimedRolesXml<'a> {
    #[serde(rename = "xades:ClaimedRole")]
    role: Vec<&'a str>,
}

#[derive(Serialize, Debug)]
struct XadesSigningCertificate {
    #[serde(rename = "xades:Cert")]
    cert: XadesCert,
}

#[derive(Serialize, Debug)]
struct XadesCert {
    #[serde(rename = "xades:CertDigest")]
    cert_digest: XadesCertDigest,
    #[serde(rename = "xades:IssuerSerial")]
    issuer_serial: XadesIssuerSerial,
}

#[derive(Serialize, Debug)]
struct XadesCertDigest {
    #[serde(rename = "ds:DigestMethod")]
    digest_method: DigestMethod,
    #[serde(rename = "ds:DigestValue")]
    digest_value: String,
}

#[derive(Serialize, Debug)]
struct XadesIssuerSerial {
    #[serde(rename = "ds:X509IssuerName")]
    issuer_name: String,
    #[serde(rename = "ds:X509SerialNumber")]
    serial_number: String,
}

#[derive(Serialize, Debug)]
struct XadesSignedDataObjectProperties<'a> {
    #[serde(rename = "xades:DataObjectFormat")]
    data_object_formats: Vec<XadesDataObjectFormat<'a>>,
}

#[derive(Serialize, Debug)]
struct XadesDataObjectFormat<'a> {
    #[serde(rename = "@ObjectReference")]
    object_reference: String,
    #[serde(rename = "xades:MimeType")]
    mime_type: &'a str,
}

#[derive(Serialize, Debug)]
#[serde(rename = "ds:SignatureValue")]
struct CanonicalSignatureValue<'a> {
    #[serde(rename = "@xmlns:asic")]
    xmlns_asic: &'a str,
    #[serde(rename = "@xmlns:ds")]
    xmlns_ds: &'a str,
    #[serde(rename = "@xmlns:xades")]
    xmlns_xades: &'a str,
    #[serde(rename = "@Id")]
    id: &'a str,
    #[serde(rename = "$text")]
    value: &'a str,
}

#[derive(Serialize, Debug)]
#[serde(rename = "xades:UnsignedProperties")]
struct XadesUnsignedProperties {
    #[serde(rename = "xades:UnsignedSignatureProperties")]
    unsigned_signature_properties: XadesUnsignedSignatureProperties,
}

#[derive(Serialize, Debug)]
struct XadesUnsignedSignatureProperties {
    #[serde(rename = "xades:SignatureTimeStamp")]
    signature_time_stamp: XadesSignatureTimeStamp,
}

#[derive(Serialize, Debug)]
struct XadesSignatureTimeStamp {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "ds:CanonicalizationMethod")]
    canonicalization_method: CanonicalizationMethod,
    #[serde(rename = "xades:EncapsulatedTimeStamp")]
    encapsulated_time_stamp: String,
}

#[derive(Serialize, Debug)]
#[serde(rename = "xades:CertificateValues")]
struct XadesCertificateValues {
    #[serde(rename = "xades:EncapsulatedX509Certificate")]
    encapsulated_x509_certificate: XadesEncapsulatedX509Certificate,
}

#[derive(Serialize, Debug)]
struct XadesEncapsulatedX509Certificate {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "$text")]
    value: String,
}

#[derive(Serialize, Debug)]
#[serde(rename = "xades:RevocationValues")]
struct XadesRevocationValues {
    #[serde(rename = "xades:OCSPValues")]
    ocsp_values: XadesOcspValues,
}

#[derive(Serialize, Debug)]
struct XadesOcspValues {
    #[serde(rename = "xades:EncapsulatedOCSPValue")]
    encapsulated_ocsp_value: XadesEncapsulatedOcspValue,
}

#[derive(Serialize, Debug)]
struct XadesEncapsulatedOcspValue {
    #[serde(rename = "@Id")]
    id: String,
    #[serde(rename = "$text")]
    value: String,
}

pub struct XadesDataFile<'a> {
    pub uri: &'a str,
    pub mime_type: &'a str,
    pub content: &'a [u8],
}

pub struct XadesSignatureInputs<'a> {
    pub signer: &'a dyn Signer,
    pub certificate_der: &'a [u8],
    pub signing_time: chrono::DateTime<chrono::Utc>,
    pub data_files: &'a [XadesDataFile<'a>],
    pub index: usize,
    pub production_place: Option<XadesProductionPlace<'a>>,
    pub claimed_roles: &'a [&'a str],
}

#[derive(Default, Debug, Clone)]
pub struct XadesProductionPlace<'a> {
    pub city: Option<&'a str>,
    pub state_or_province: Option<&'a str>,
    pub postal_code: Option<&'a str>,
    pub country_name: Option<&'a str>,
}

pub struct XadesBesResult {
    pub xml: String,
    pub signature_id: String,
    pub signature_value_canonical: Vec<u8>,
}

pub trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn signature_method_uri(&self) -> &'static str;
    fn digest_method_uri(&self) -> &'static str;
    fn verifying_key(&self) -> Result<PublicKeyType>;
}

pub enum SigningKeyType {
    Rsa(Box<RsaPrivateKey>),
    P256(P256SigningKey),
    K256(K256SigningKey),
}

#[derive(Clone)]
pub enum PublicKeyType {
    Rsa(RsaPublicKey),
    P256(P256VerifyingKey),
    K256(K256VerifyingKey),
}

impl Signer for SigningKeyType {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            SigningKeyType::Rsa(key) => {
                use rsa::signature::{SignatureEncoding, hazmat::PrehashSigner};
                let hashed = Sha256::digest(data);
                let signer = RsaSigningKey::<Sha256>::new_unprefixed(key.as_ref().clone());
                let signature: RsaSignature = signer
                    .sign_prehash(&hashed)
                    .map_err(|e| SignatureError::SigningError(e.to_string()))?;
                Ok(signature.to_vec())
            }
            SigningKeyType::P256(key) => {
                use p256::ecdsa::signature::Signer;
                let signature: P256Signature = key.sign(data);
                Ok(signature.to_vec())
            }
            SigningKeyType::K256(key) => {
                use k256::ecdsa::signature::Signer;
                let signature: K256Signature = key.sign(data);
                Ok(signature.to_vec())
            }
        }
    }

    fn signature_method_uri(&self) -> &'static str {
        match self {
            SigningKeyType::Rsa(_) => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            SigningKeyType::P256(_) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            SigningKeyType::K256(_) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        }
    }

    fn digest_method_uri(&self) -> &'static str {
        "http://www.w3.org/2001/04/xmlenc#sha256"
    }

    fn verifying_key(&self) -> Result<PublicKeyType> {
        match self {
            SigningKeyType::Rsa(private_key) => {
                Ok(PublicKeyType::Rsa(private_key.as_ref().to_public_key()))
            }
            SigningKeyType::P256(signing_key) => {
                Ok(PublicKeyType::P256(*signing_key.verifying_key()))
            }
            SigningKeyType::K256(signing_key) => {
                Ok(PublicKeyType::K256(*signing_key.verifying_key()))
            }
        }
    }
}

pub fn verify_signature<F>(
    xml_data: &[u8],
    public_key: &PublicKeyType,
    external_data_resolver: Option<F>,
) -> Result<()>
where
    F: Fn(&str) -> Result<Vec<u8>>,
{
    let xml_str = std::str::from_utf8(xml_data)?;
    let doc = roxmltree::Document::parse(xml_str)
        .map_err(|e| SignatureError::XmlStructureError(e.to_string()))?;

    let signature_node = doc.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .ok_or_else(|| SignatureError::MissingElement("Signature".to_string()))?;

    let signed_info_node = signature_node.children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .ok_or_else(|| SignatureError::MissingElement("SignedInfo".to_string()))?;

    let signature_value_node = signature_node.children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignatureValue")
        .ok_or_else(|| SignatureError::MissingElement("SignatureValue".to_string()))?;

    let signed_info = xml_sec::xmldsig::parse::parse_signed_info(signed_info_node)
        .map_err(|e| SignatureError::XmlStructureError(e.to_string()))?;

    let resolver = xml_sec::xmldsig::uri::UriReferenceResolver::new(&doc);
    let resolver_ref = external_data_resolver.as_ref();

    for reference in &signed_info.references {
        let uri = reference.uri.as_deref()
            .ok_or_else(|| SignatureError::MissingElement("Reference URI".to_string()))?;

        let referenced_data_bytes = if uri.starts_with('#') {
            let resolved = resolver.dereference(uri)
                .map_err(|e| SignatureError::ReferenceNotFound(format!("ID lookup failed for {}: {}", uri, e)))?;
            xml_sec::xmldsig::transforms::execute_transforms(signature_node, resolved, &reference.transforms)
                .map_err(|e| SignatureError::CanonicalizationError(e.to_string()))?
        } else if let Some(resolver_fn) = resolver_ref {
            resolver_fn(uri)?
        } else {
            return Err(SignatureError::ReferenceNotFound(format!(
                "External URI '{}' needs resolver",
                uri
            )));
        };

        let calculated_digest = xml_sec::xmldsig::digest::compute_digest(reference.digest_method, &referenced_data_bytes);
        if !xml_sec::xmldsig::digest::constant_time_eq(&calculated_digest, &reference.digest_value) {
            return Err(SignatureError::DigestMismatch(uri.to_string()));
        }
    }

    let signed_info_subtree: std::collections::HashSet<_> = signed_info_node
        .descendants()
        .map(|node| node.id())
        .collect();
    let mut canonical_signed_info = Vec::new();
    let c14n_algo = xml_sec::c14n::C14nAlgorithm::from_uri(signed_info.c14n_method.uri())
        .ok_or_else(|| SignatureError::UnsupportedError(format!("Unsupported C14N URI: {}", signed_info.c14n_method.uri())))?;
    xml_sec::c14n::canonicalize(
        &doc,
        Some(&|node| signed_info_subtree.contains(&node.id())),
        &c14n_algo,
        &mut canonical_signed_info,
    ).map_err(|e| SignatureError::CanonicalizationError(e.to_string()))?;

    let signature_value_text = signature_value_node.text().unwrap_or_default().trim();
    let signature_value_clean: String = signature_value_text.chars().filter(|c| !c.is_whitespace()).collect();
    let signature_value_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &signature_value_clean)?;

    let spki_der = match public_key {
        PublicKeyType::Rsa(vk) => {
            use rsa::pkcs8::{EncodePublicKey, der::Encode};
            vk.to_public_key_der().map_err(|e| SignatureError::KeyParsingError(e.to_string()))?.to_der()
                .map_err(|e| SignatureError::KeyParsingError(e.to_string()))?
        }
        PublicKeyType::P256(vk) => {
            use p256::pkcs8::{EncodePublicKey, der::Encode};
            vk.to_public_key_der().map_err(|e| SignatureError::KeyParsingError(e.to_string()))?.to_der()
                .map_err(|e| SignatureError::KeyParsingError(e.to_string()))?
        }
        PublicKeyType::K256(vk) => {
            use k256::pkcs8::{EncodePublicKey, der::Encode};
            vk.to_public_key_der().map_err(|e| SignatureError::KeyParsingError(e.to_string()))?.to_der()
                .map_err(|e| SignatureError::KeyParsingError(e.to_string()))?
        }
    };

    let sig_valid = match public_key {
        PublicKeyType::Rsa(_) => {
            xml_sec::xmldsig::signature::verify_rsa_signature_spki(
                signed_info.signature_method,
                &spki_der,
                &canonical_signed_info,
                &signature_value_bytes,
            ).map_err(|e| SignatureError::CryptoVerificationError(e.to_string()))?
        }
        PublicKeyType::P256(_) | PublicKeyType::K256(_) => {
            xml_sec::xmldsig::signature::verify_ecdsa_signature_spki(
                signed_info.signature_method,
                &spki_der,
                &canonical_signed_info,
                &signature_value_bytes,
            ).map_err(|e| SignatureError::CryptoVerificationError(e.to_string()))?
        }
    };

    if !sig_valid {
        return Err(SignatureError::CryptoVerificationError("Signature mismatch".to_string()));
    }

    Ok(())
}

pub fn build_xades_basic_signature(input: &XadesSignatureInputs<'_>) -> Result<XadesBesResult> {
    use x509_parser::prelude::*;

    let signature_id = format!("S{}", input.index);
    let signed_properties_id = format!("SP{}-SignedProperties", input.index);
    let signature_value_id = format!("{}-SIG", signature_id);

    let mut references: Vec<Reference> = input
        .data_files
        .iter()
        .enumerate()
        .map(|(i, file)| Reference {
            id: Some(format!("{}-RefId{}", signature_id, i)),
            reference_type: None,
            uri: file.uri.to_string(),
            transforms: None,
            digest_method: DigestMethod {
                algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
            },
            digest_value: general_purpose::STANDARD.encode(Sha256::digest(file.content)),
        })
        .collect();

    let cert_digest = Sha256::digest(input.certificate_der);
    let cert_digest_b64 = general_purpose::STANDARD.encode(cert_digest);
    let cert_b64 = general_purpose::STANDARD.encode(input.certificate_der);
    let (_, parsed_cert) = X509Certificate::from_der(input.certificate_der).map_err(|e| {
        SignatureError::GeneralError(format!("failed to parse certificate DER: {}", e))
    })?;

    let production_place_xml = input
        .production_place
        .as_ref()
        .map(|p| XadesProductionPlaceXml {
            city: p.city,
            state_or_province: p.state_or_province,
            postal_code: p.postal_code,
            country_name: p.country_name,
        });
    let signer_role_xml = if input.claimed_roles.is_empty() {
        None
    } else {
        Some(XadesSignerRoleXml {
            claimed_roles: XadesClaimedRolesXml {
                role: input.claimed_roles.to_vec(),
            },
        })
    };

    let signed_properties = XadesSignedProperties {
        xmlns_asic: "http://uri.etsi.org/02918/v1.2.1#",
        xmlns_ds: "http://www.w3.org/2000/09/xmldsig#",
        xmlns_xades: "http://uri.etsi.org/01903/v1.3.2#",
        id: signed_properties_id.clone(),
        signed_signature_properties: XadesSignedSignatureProperties {
            signing_time: input.signing_time.to_rfc3339(),
            signing_certificate: XadesSigningCertificate {
                cert: XadesCert {
                    cert_digest: XadesCertDigest {
                        digest_method: DigestMethod {
                            algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
                        },
                        digest_value: cert_digest_b64,
                    },
                    issuer_serial: XadesIssuerSerial {
                        issuer_name: parsed_cert.issuer().to_string(),
                        serial_number: parsed_cert.serial.to_string(),
                    },
                },
            },
            production_place: production_place_xml,
            signer_role: signer_role_xml,
        },
        signed_data_object_properties: XadesSignedDataObjectProperties {
            data_object_formats: input
                .data_files
                .iter()
                .enumerate()
                .map(|(i, file)| XadesDataObjectFormat {
                    object_reference: format!("#{}-RefId{}", signature_id, i),
                    mime_type: file.mime_type,
                })
                .collect(),
        },
    };

    let signed_properties_xml_raw = to_string(&signed_properties)
        .map_err(|e| SignatureError::XmlSerializationError(e.to_string()))?;
    let algo = xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Inclusive1_0, false);
    let signed_properties_canonical = xml_sec::c14n::canonicalize_xml(signed_properties_xml_raw.as_bytes(), &algo)
        .map_err(|e| SignatureError::CanonicalizationError(e.to_string()))?;
    let signed_properties_digest = Sha256::digest(&signed_properties_canonical);
    let signed_properties_digest_b64 = general_purpose::STANDARD.encode(signed_properties_digest);

    references.push(Reference {
        id: Some(format!("{}-SignedPropertiesRef", signature_id)),
        reference_type: Some("http://uri.etsi.org/01903#SignedProperties".to_string()),
        uri: format!("#{}", signed_properties_id),
        transforms: None,
        digest_method: DigestMethod {
            algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
        },
        digest_value: signed_properties_digest_b64,
    });

    let signed_info = SignedInfo {
        xmlns_asic: Some("http://uri.etsi.org/02918/v1.2.1#".to_string()),
        xmlns_ds: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
        xmlns_xades: Some("http://uri.etsi.org/01903/v1.3.2#".to_string()),
        canonicalization_method: CanonicalizationMethod {
            algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string(),
        },
        signature_method: SignatureMethod {
            algorithm: input.signer.signature_method_uri().to_string(),
        },
        references,
    };

    let signed_info_xml_raw = to_string(&signed_info)
        .map_err(|e| SignatureError::XmlSerializationError(e.to_string()))?;
    let signed_info_canonical = xml_sec::c14n::canonicalize_xml(signed_info_xml_raw.as_bytes(), &algo)
        .map_err(|e| SignatureError::CanonicalizationError(e.to_string()))?;
    let signature_value_bytes = input.signer.sign(&signed_info_canonical)?;
    let signature_value_b64 = general_purpose::STANDARD.encode(signature_value_bytes);

    let envelope = XadesSignaturesEnvelope {
        xmlns_asic: "http://uri.etsi.org/02918/v1.2.1#",
        xmlns_ds: "http://www.w3.org/2000/09/xmldsig#",
        xmlns_xades: "http://uri.etsi.org/01903/v1.3.2#",
        signature: XadesSignatureElement {
            id: signature_id.clone(),
            signed_info,
            signature_value: SignatureValueElement {
                id: signature_value_id.clone(),
                value: signature_value_b64.clone(),
            },
            key_info: KeyInfoX509 {
                x509_data: X509DataElement {
                    x509_certificate: cert_b64,
                },
            },
            object: XadesObjectElement {
                qualifying_properties: XadesQualifyingProperties {
                    target: format!("#{}", signature_id),
                    signed_properties,
                },
            },
        },
    };
    let body = to_string(&envelope)
        .map_err(|e| SignatureError::XmlSerializationError(e.to_string()))?;
    let xml = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}", body);

    let signature_value_canonical = build_canonical_signature_value(&signature_value_id, &signature_value_b64)?;

    Ok(XadesBesResult {
        xml,
        signature_id,
        signature_value_canonical,
    })
}

pub fn upgrade_xades_bes_to_t(bes: &XadesBesResult, timestamp_token_der: &[u8]) -> Result<String> {
    let unsigned = XadesUnsignedProperties {
        unsigned_signature_properties: XadesUnsignedSignatureProperties {
            signature_time_stamp: XadesSignatureTimeStamp {
                id: format!("{}-T0", bes.signature_id),
                canonicalization_method: CanonicalizationMethod {
                    algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string(),
                },
                encapsulated_time_stamp: general_purpose::STANDARD.encode(timestamp_token_der),
            },
        },
    };
    let unsigned_block = to_string(&unsigned)
        .map_err(|e| SignatureError::XmlSerializationError(e.to_string()))?;
    let close_tag = "</xades:QualifyingProperties>";
    let pos = bes.xml.rfind(close_tag).ok_or_else(|| {
        SignatureError::XmlStructureError("BES XML missing </xades:QualifyingProperties>".into())
    })?;
    let mut out = String::with_capacity(bes.xml.len() + unsigned_block.len());
    out.push_str(&bes.xml[..pos]);
    out.push_str(&unsigned_block);
    out.push_str(&bes.xml[pos..]);
    Ok(out)
}

pub fn upgrade_xades_t_to_lt(
    t_level_xml: &str,
    signature_id: &str,
    issuer_cert_der: &[u8],
    basic_ocsp_response_der: &[u8],
) -> Result<String> {
    let cert_values = XadesCertificateValues {
        encapsulated_x509_certificate: XadesEncapsulatedX509Certificate {
            id: format!("{}-CA-CERT", signature_id),
            value: general_purpose::STANDARD.encode(issuer_cert_der),
        },
    };
    let cert_values_xml = to_string(&cert_values)
        .map_err(|e| SignatureError::XmlSerializationError(e.to_string()))?;

    let ocsp_id = signature_id.replacen('S', "N", 1);
    let revocation_values = XadesRevocationValues {
        ocsp_values: XadesOcspValues {
            encapsulated_ocsp_value: XadesEncapsulatedOcspValue {
                id: ocsp_id,
                value: general_purpose::STANDARD.encode(basic_ocsp_response_der),
            },
        },
    };
    let revocation_values_xml = to_string(&revocation_values)
        .map_err(|e| SignatureError::XmlSerializationError(e.to_string()))?;

    let close_tag = "</xades:UnsignedSignatureProperties>";
    let pos = t_level_xml.rfind(close_tag).ok_or_else(|| {
        SignatureError::XmlStructureError(
            "T-level XML missing </xades:UnsignedSignatureProperties>".into(),
        )
    })?;
    let mut out = String::with_capacity(
        t_level_xml.len() + cert_values_xml.len() + revocation_values_xml.len(),
    );
    out.push_str(&t_level_xml[..pos]);
    out.push_str(&cert_values_xml);
    out.push_str(&revocation_values_xml);
    out.push_str(&t_level_xml[pos..]);
    Ok(out)
}

fn build_canonical_signature_value(id: &str, base64_value: &str) -> Result<Vec<u8>> {
    let raw_xml = format!(
        r#"<ds:SignatureValue xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="{}">{}</ds:SignatureValue>"#,
        id, base64_value
    );
    let algo = xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Inclusive1_0, false);
    let bytes = xml_sec::c14n::canonicalize_xml(raw_xml.as_bytes(), &algo)
        .map_err(|e| SignatureError::CanonicalizationError(e.to_string()))?;
    Ok(bytes)
}
