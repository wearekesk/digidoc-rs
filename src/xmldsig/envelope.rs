//! Enveloping XML signatures (`ds:Object` carried inside the signature).
//!
//! Used by integrations such as LHV Connect that expect the signed payload
//! to be embedded in a `ds:Object` within the `ds:Signature` element, rather
//! than the detached/enveloped forms used by BDOC containers.

use base64::{Engine as _, engine::general_purpose};
use quick_xml::se::to_string;
use rsa::RsaPrivateKey;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    CanonicalizationMethod, DigestMethod, Reference, SignatureMethod, SignedInfo, Signer,
    SigningKeyType,
};
use crate::error::{Result, SignatureError};

#[derive(Serialize, Debug, Default)]
#[serde(rename = "ds:Signature")]
pub struct EnvelopingSignature<T: Serialize> {
    #[serde(rename = "@xmlns:ds", skip_serializing_if = "Option::is_none")]
    pub xmlns_ds: Option<String>,
    #[serde(rename = "ds:SignedInfo")]
    pub signed_info: SignedInfo,
    #[serde(rename = "ds:SignatureValue")]
    pub signature_value: String,
    #[serde(rename = "ds:KeyInfo", skip_serializing_if = "Option::is_none")]
    pub key_info: Option<EnvelopingKeyInfo>,
    #[serde(rename = "ds:Object", skip_serializing_if = "Option::is_none")]
    pub object: Option<EnvelopingObject<T>>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename = "ds:Object")]
pub struct EnvelopingObject<T: Serialize> {
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(rename = "@xmlns:ds", skip_serializing_if = "Option::is_none")]
    pub xmlns_ds: Option<String>,
    #[serde(flatten)]
    pub data: T,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename = "ds:KeyInfo")]
pub struct EnvelopingKeyInfo {
    #[serde(rename = "ds:KeyValue")]
    pub key_value: EnvelopingKeyValue,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename = "ds:KeyValue")]
pub struct EnvelopingKeyValue {
    #[serde(rename = "ds:RSAKeyValue", skip_serializing_if = "Option::is_none")]
    pub rsa_key_value: Option<EnvelopingRsaKeyValue>,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename = "ds:RSAKeyValue")]
pub struct EnvelopingRsaKeyValue {
    #[serde(rename = "ds:Modulus")]
    pub modulus: String,
    #[serde(rename = "ds:Exponent")]
    pub exponent: String,
}

pub fn sign_enveloping<T: Serialize + std::fmt::Debug + Clone>(
    data_to_sign: &T,
    data_id: &str,
    signer: &SigningKeyType,
) -> Result<String> {
    fn extract_object(xml: &str, data_id: &str) -> Result<String> {
        let needle = format!("<ds:Object Id=\"{}\"", data_id);
        let start = xml.find(&needle).ok_or_else(|| {
            SignatureError::GeneralError(format!(
                "could not locate <ds:Object Id=\"{}\"> in serialised signature",
                data_id
            ))
        })?;
        let end_marker = "</ds:Object>";
        let end_rel = xml[start..].find(end_marker).ok_or_else(|| {
            SignatureError::GeneralError(
                "<ds:Object> opened but never closed in serialised signature".into(),
            )
        })?;
        Ok(xml[start..start + end_rel + end_marker.len()].to_string())
    }

    let key_info_val = match signer {
        SigningKeyType::Rsa(key) => {
            use rsa::traits::PublicKeyParts;
            let modulus = general_purpose::STANDARD.encode(key.as_ref().n_bytes());
            let exponent = general_purpose::STANDARD.encode(key.as_ref().e_bytes());
            Some(EnvelopingKeyInfo {
                key_value: EnvelopingKeyValue {
                    rsa_key_value: Some(EnvelopingRsaKeyValue { modulus, exponent }),
                },
            })
        }
        _ => {
            return Err(SignatureError::UnsupportedError(
                "Only RSA keys are supported for LHV Connect".to_string(),
            ));
        }
    };

    // This is an *enveloping* signature: the payload lives in a <ds:Object>
    // inside the signature and the reference points straight at it by Id.
    // No enveloped-signature transform is used — that transform excludes the
    // whole <ds:Signature> subtree, which would drop the very <ds:Object>
    // being referenced and digest empty content instead.
    let build_reference = |digest_value: String| Reference {
        id: None,
        reference_type: None,
        uri: format!("#{}", data_id),
        transforms: None,
        digest_method: DigestMethod {
            algorithm: signer.digest_method_uri().into(),
        },
        digest_value,
    };

    let placeholder_signed_info = SignedInfo {
        xmlns_asic: None,
        xmlns_ds: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
        xmlns_xades: None,
        canonicalization_method: CanonicalizationMethod {
            algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".into(),
        },
        signature_method: SignatureMethod {
            algorithm: signer.signature_method_uri().into(),
        },
        references: vec![build_reference(String::new())],
    };

    let placeholder_signature = EnvelopingSignature {
        xmlns_ds: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
        signed_info: placeholder_signed_info,
        signature_value: String::new(),
        key_info: key_info_val.clone(),
        object: Some(EnvelopingObject {
            xmlns_ds: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
            id: data_id.to_string(),
            data: data_to_sign.clone(),
        }),
    };

    let placeholder_xml = to_string(&placeholder_signature)
        .map_err(|e| SignatureError::XmlSerializationError(e.to_string()))?;
    let object_substring = extract_object(&placeholder_xml, data_id)?;

    let algo = xml_sec::c14n::C14nAlgorithm::new(xml_sec::c14n::C14nMode::Inclusive1_0, false);
    let object_canonical = xml_sec::c14n::canonicalize_xml(object_substring.as_bytes(), &algo)
        .map_err(|e| SignatureError::CanonicalizationError(e.to_string()))?;
    let digest = Sha256::digest(&object_canonical);
    let digest_b64 = general_purpose::STANDARD.encode(digest);

    let signed_info = SignedInfo {
        xmlns_asic: None,
        xmlns_ds: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
        xmlns_xades: None,
        canonicalization_method: CanonicalizationMethod {
            algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315".into(),
        },
        signature_method: SignatureMethod {
            algorithm: signer.signature_method_uri().into(),
        },
        references: vec![build_reference(digest_b64)],
    };

    let signed_info_xml_raw = to_string(&signed_info)
        .map_err(|e| SignatureError::XmlSerializationError(e.to_string()))?;

    let signed_info_canonical =
        xml_sec::c14n::canonicalize_xml(signed_info_xml_raw.as_bytes(), &algo)
            .map_err(|e| SignatureError::CanonicalizationError(e.to_string()))?;

    let signature_bytes = signer.sign(&signed_info_canonical)?;
    let signature_b64 = general_purpose::STANDARD.encode(signature_bytes);

    let signature = EnvelopingSignature {
        xmlns_ds: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
        signed_info,
        signature_value: signature_b64,
        key_info: key_info_val,
        object: Some(EnvelopingObject {
            xmlns_ds: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
            id: data_id.to_string(),
            data: data_to_sign.clone(),
        }),
    };
    to_string(&signature).map_err(|e| SignatureError::XmlSerializationError(e.to_string()))
}

pub fn load_rsa_private_key(path: &str) -> Result<RsaPrivateKey> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    let pem = std::fs::read_to_string(path).map_err(|e| {
        SignatureError::KeyParsingError(format!("Failed to read private key: {}", e))
    })?;
    RsaPrivateKey::from_pkcs8_pem(&pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
        .map_err(|e| {
            SignatureError::KeyParsingError(format!("Failed to parse RSA private key: {}", e))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmldsig::{PublicKeyType, verify_signature};
    use rsa::pkcs8::DecodePrivateKey;

    #[test]
    fn test_sign_enveloping_round_trip() {
        let private_key = RsaPrivateKey::from_pkcs8_der(crate::test_keys::TEST_KEY).unwrap();
        let public_key = private_key.to_public_key();
        let signer = SigningKeyType::Rsa(Box::new(private_key));

        #[derive(Serialize, Clone, Debug)]
        #[serde(rename = "Payload")]
        struct Payload {
            #[serde(rename = "Field")]
            field: String,
        }
        let payload = Payload {
            field: "hello".to_string(),
        };
        let signed_xml = sign_enveloping(&payload, "p1", &signer).unwrap();

        let verify_res = verify_signature(
            signed_xml.as_bytes(),
            &PublicKeyType::Rsa(public_key),
            None::<fn(&str) -> Result<Vec<u8>>>,
        );

        assert!(verify_res.is_ok(), "Verification failed: {:?}", verify_res);
    }
}
