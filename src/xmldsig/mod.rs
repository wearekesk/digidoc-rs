//! Core XML Digital Signature (XMLDSig) primitives.
//!
//! This module holds the shared `ds:*` element types, the [`Signer`]
//! abstraction over the supported key algorithms, and [`verify_signature`].
//! The higher-level signature profiles are built on top of these:
//!
//! * [`xades`] — XAdES-BES/T/LT signatures for BDOC/ASiC-E containers.
//! * [`envelope`] — enveloping signatures with the payload in a `ds:Object`.

use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Use specific ECDSA signing/verifying key types and traits
use k256::ecdsa::{
    Signature as K256Signature, SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};

use crate::error::{Result, SignatureError};

pub mod envelope;
pub mod xades;

// Re-export the higher-level profile API so `crate::xmldsig::*` paths remain
// stable for downstream modules and the crate root.
pub use envelope::{
    EnvelopingKeyInfo, EnvelopingKeyValue, EnvelopingObject, EnvelopingRsaKeyValue,
    EnvelopingSignature, load_rsa_private_key, sign_enveloping,
};
pub use xades::{
    XadesBesResult, XadesDataFile, XadesProductionPlace, XadesSignatureInputs,
    build_xades_basic_signature, upgrade_xades_bes_to_t, upgrade_xades_t_to_lt,
};

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

pub trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn signature_method_uri(&self) -> &'static str;
    fn digest_method_uri(&self) -> &'static str;
    fn verifying_key(&self) -> Result<PublicKeyType>;
}

#[derive(Clone)]
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
                let signer = RsaSigningKey::<Sha256>::new(key.as_ref().clone());
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

    let signature_node = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Signature")
        .ok_or_else(|| SignatureError::MissingElement("Signature".to_string()))?;

    let signed_info_node = signature_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
        .ok_or_else(|| SignatureError::MissingElement("SignedInfo".to_string()))?;

    let signature_value_node = signature_node
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "SignatureValue")
        .ok_or_else(|| SignatureError::MissingElement("SignatureValue".to_string()))?;

    let signed_info = xml_sec::xmldsig::parse::parse_signed_info(signed_info_node)
        .map_err(|e| SignatureError::XmlStructureError(e.to_string()))?;

    let resolver = xml_sec::xmldsig::uri::UriReferenceResolver::new(&doc);
    let resolver_ref = external_data_resolver.as_ref();

    for reference in &signed_info.references {
        let uri = reference
            .uri
            .as_deref()
            .ok_or_else(|| SignatureError::MissingElement("Reference URI".to_string()))?;

        let referenced_data_bytes = if uri.starts_with('#') {
            let resolved = resolver.dereference(uri).map_err(|e| {
                SignatureError::ReferenceNotFound(format!("ID lookup failed for {}: {}", uri, e))
            })?;
            xml_sec::xmldsig::transforms::execute_transforms(
                signature_node,
                resolved,
                &reference.transforms,
            )
            .map_err(|e| SignatureError::CanonicalizationError(e.to_string()))?
        } else if let Some(resolver_fn) = resolver_ref {
            let raw_bytes = resolver_fn(uri)?;
            // Apply transforms to external references too (e.g.
            // canonicalization) — previously only same-document
            // (#id) URIs ran through the transform pipeline.
            if reference.transforms.is_empty() {
                raw_bytes
            } else {
                xml_sec::xmldsig::transforms::execute_transforms(
                    signature_node,
                    xml_sec::xmldsig::types::TransformData::Binary(raw_bytes),
                    &reference.transforms,
                )
                .map_err(|e| SignatureError::CanonicalizationError(e.to_string()))?
            }
        } else {
            return Err(SignatureError::ReferenceNotFound(format!(
                "External URI '{}' needs resolver",
                uri
            )));
        };
        let calculated_digest = xml_sec::xmldsig::digest::compute_digest(
            reference.digest_method,
            &referenced_data_bytes,
        );
        if !xml_sec::xmldsig::digest::constant_time_eq(&calculated_digest, &reference.digest_value)
        {
            return Err(SignatureError::DigestMismatch(uri.to_string()));
        }
    }

    let signed_info_subtree: std::collections::HashSet<_> = signed_info_node
        .descendants()
        .map(|node| node.id())
        .collect();
    let mut canonical_signed_info = Vec::new();
    let c14n_algo = xml_sec::c14n::C14nAlgorithm::from_uri(signed_info.c14n_method.uri())
        .ok_or_else(|| {
            SignatureError::UnsupportedError(format!(
                "Unsupported C14N URI: {}",
                signed_info.c14n_method.uri()
            ))
        })?;
    xml_sec::c14n::canonicalize(
        signed_info_node.document(),
        Some(&|node| signed_info_subtree.contains(&node.id())),
        &c14n_algo,
        &mut canonical_signed_info,
    )
    .map_err(|e| SignatureError::CanonicalizationError(e.to_string()))?;

    let signature_value_text = signature_value_node
        .text()
        .ok_or_else(|| SignatureError::MissingElement("SignatureValue text content".to_string()))?
        .trim();
    let signature_value_clean: String = signature_value_text
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let signature_value_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &signature_value_clean,
    )?;

    let spki_der = match public_key {
        PublicKeyType::Rsa(vk) => {
            use rsa::pkcs8::{EncodePublicKey, der::Encode};
            vk.to_public_key_der()
                .map_err(|e| SignatureError::KeyParsingError(e.to_string()))?
                .to_der()
                .map_err(|e| SignatureError::KeyParsingError(e.to_string()))?
        }
        PublicKeyType::P256(vk) => {
            use p256::pkcs8::{EncodePublicKey, der::Encode};
            vk.to_public_key_der()
                .map_err(|e| SignatureError::KeyParsingError(e.to_string()))?
                .to_der()
                .map_err(|e| SignatureError::KeyParsingError(e.to_string()))?
        }
        PublicKeyType::K256(vk) => {
            use k256::pkcs8::{EncodePublicKey, der::Encode};
            vk.to_public_key_der()
                .map_err(|e| SignatureError::KeyParsingError(e.to_string()))?
                .to_der()
                .map_err(|e| SignatureError::KeyParsingError(e.to_string()))?
        }
    };

    let sig_valid = match public_key {
        PublicKeyType::Rsa(_) => xml_sec::xmldsig::signature::verify_rsa_signature_spki(
            signed_info.signature_method,
            &spki_der,
            &canonical_signed_info,
            &signature_value_bytes,
        )
        .map_err(|e| SignatureError::CryptoVerificationError(e.to_string()))?,
        PublicKeyType::P256(_) | PublicKeyType::K256(_) => {
            xml_sec::xmldsig::signature::verify_ecdsa_signature_spki(
                signed_info.signature_method,
                &spki_der,
                &canonical_signed_info,
                &signature_value_bytes,
            )
            .map_err(|e| SignatureError::CryptoVerificationError(e.to_string()))?
        }
    };

    if !sig_valid {
        return Err(SignatureError::CryptoVerificationError(
            "Signature mismatch".to_string(),
        ));
    }

    Ok(())
}
