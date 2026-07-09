# digidoc

A pure Rust client library for reading and writing BDOC/ASiC-E digital signature containers (DigiDoc).

## Features

- **ASiC-E Container Support**: Full support for Associated Signature Extended form (ASiC-E) ZIP containers.
- **XAdES Signature Formats**:
  - **XAdES-BES**: Basic Electronic Signature.
  - **XAdES-T**: Adds timestamping for `SignatureValue` to prove existence time.
  - **XAdES-LT**: Long-Term validation, adding OCSP certificate status validation values.
- **Robust XMLDSig Backend**: Built on top of the standard `xml-sec` crate, migrating away from fragile hand-rolled XML parsing and canonicalization.
- **RSA & ECDSA Support**: Support for signatures using RSA, P-256, and K-256 keys.

## Dependencies

This crate uses:
- `xml-sec` for secure, compliant XML Digital Signatures (XMLDSig) and Canonicalization (C14N).
- `x509-parser` for parsing X.509 certificates.
- `zip` for archive packaging.
- `reqwest` and `tokio` for TSA/OCSP HTTP communications.

## Building and Testing

To run the unit tests:
```bash
cargo test
```

For manual end-to-end testing with real Estonian DigiDoc4 client:
```bash
DIGIDOC_TEST_TSA_URL=https://eid-dd.ria.ee/ts cargo test -- --ignored --nocapture digidoc::tests::generate_signed_asice_for_manual_testing
```

## License

This project is licensed under the MIT License.
