pub mod der;
pub mod digidoc;
pub mod error;
pub mod ocsp;
pub mod tsa;
pub mod xmldsig;

// Re-export major builder and reader types at root level
pub use crate::digidoc::{
    DigiDocBuilder, DigiDocFile, DigiDocProductionPlace, DigiDocReader, DigiDocSignature,
    DigiDocSignatureInfo, DigiDocSignerInfo, DigiDocSignerInput, DigiDocValidationResult,
};
pub use crate::error::{Result, SignatureError};
pub use crate::xmldsig::{
    PublicKeyType, Signer, SigningKeyType, build_xades_basic_signature, verify_signature,
};
