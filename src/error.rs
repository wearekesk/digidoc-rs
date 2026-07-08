use thiserror::Error;
use quick_xml::de::DeError;
use std::io;
use std::string::FromUtf8Error;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Failed to load key from file '{0}': {1}")]
    KeyLoadingError(String, Box<dyn std::error::Error + Send + Sync>),
    #[error("Failed to parse key: {0}")]
    KeyParsingError(String),

    #[error("Failed to serialize data to XML: {0}")]
    XmlSerializationError(String),
    #[error("Failed to parse XML: {0}")]
    XmlParsingError(#[from] quick_xml::Error),
    #[error("Failed to deserialize XML: {0}")]
    XmlDeserializationError(#[from] DeError),
    #[error("XML structure error: {0}")]
    XmlStructureError(String),

    #[error("Failed to create signature: {0}")]
    SigningError(String),
    #[error("Signature verification failed: {0}")]
    VerificationError(String),
    #[error("Cryptographic signature check failed: {0}")]
    CryptoVerificationError(String),
    #[error("Digest verification failed for reference URI '{0}'")]
    DigestMismatch(String),

    #[error("Failed to encode/decode Base64: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("Invalid UTF-8 sequence: {0}")]
    Utf8Error(#[from] FromUtf8Error),
    #[error("Invalid UTF-8 sequence: {0}")]
    StrUtf8Error(#[from] std::str::Utf8Error),
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Unsupported algorithm or key type: {0}")]
    UnsupportedError(String),
    #[error("Missing required XML element or attribute: {0}")]
    MissingElement(String),
    #[error("Could not find referenced data for URI: {0}")]
    ReferenceNotFound(String),

    #[error("Canonicalization error: {0}")]
    CanonicalizationError(String),

    #[error("General error: {0}")]
    GeneralError(String),
}

pub type Result<T, E = SignatureError> = std::result::Result<T, E>;
