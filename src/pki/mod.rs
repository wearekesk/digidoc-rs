//! PKI support building blocks used to upgrade signatures beyond XAdES-BES.
//!
//! * [`der`] — minimal DER (TLV) encode/decode helpers shared by the
//!   OCSP and TSA request/response codecs.
//! * [`ocsp`] — RFC 6960 OCSP request building and response extraction.
//! * [`tsa`] — RFC 3161 timestamp request building and token extraction.

pub(crate) mod der;
pub mod ocsp;
pub mod tsa;

pub use ocsp::fetch_ocsp_response;
pub use tsa::fetch_timestamp_token;
