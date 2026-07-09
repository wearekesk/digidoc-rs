pub mod digidoc;
pub mod error;
pub mod pki;
pub mod xmldsig;

#[cfg(test)]
pub(crate) mod test_keys;

// Re-export major builder and reader types at root level
pub use crate::digidoc::{
    DigiDocBuilder, DigiDocFile, DigiDocProductionPlace, DigiDocReader, DigiDocSignatureInfo,
    DigiDocSignerInfo, DigiDocSignerInput, DigiDocValidationResult,
};
pub use crate::error::{Result, SignatureError};
pub use crate::xmldsig::{
    PublicKeyType, Signer, SigningKeyType, build_xades_basic_signature, load_rsa_private_key,
    sign_enveloping, verify_signature,
};
