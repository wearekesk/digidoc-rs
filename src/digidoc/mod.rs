//! BDOC / ASiC-E container format support.
//!
//! Based on <https://open-eid.github.io/libdigidocpp/manual.html>. Only the
//! BDOC 2.1 digitally-signed file format is supported.
//!
//! The ETSI standard TS 102 918 ("Associated Signature Containers", ASiC)
//! defines the container used to encapsulate signed files and signatures;
//! TS 103 174 ("ASiC Baseline Profile") profiles it further. BDOC 2.1 uses the
//! Associated Signature Extended form (ASiC-E): a ZIP file consisting of
//!
//! * a `mimetype` file containing only `application/vnd.etsi.asic-e+zip`,
//! * the data files in their original format, and
//! * a `META-INF/` subdirectory holding `manifest.xml` (lists every data file,
//!   excluding `mimetype` and `META-INF/*`) and one `signatures*.xml` per
//!   signature (`*` is a 0-based sequence number). Each `signatures*.xml` also
//!   carries the certificates, validity confirmation, and signer metadata.
//!
//! When a BDOC 2.1 container is signed, every file is signed except the
//! `mimetype` file and the files under `META-INF/`.
//!
//! This module is split into the [`builder`] (write) and [`reader`] (read /
//! validate) paths; the shared [`DigiDocFile`] value type lives here.

mod builder;
mod reader;

pub use builder::{DigiDocBuilder, DigiDocProductionPlace, DigiDocSignerInput};
pub use reader::{
    DigiDocReader, DigiDocSignatureInfo, DigiDocSignerInfo, DigiDocValidationResult,
};

#[derive(Debug, Clone)]
pub struct DigiDocFile {
    pub name: String,
    pub content: Vec<u8>,
    pub mime_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::NamedTempFile;
    use zip::ZipArchive;

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(fut)
    }

    fn build_container(files: &[(&str, &[u8], &str)]) -> NamedTempFile {
        let mut builder = DigiDocBuilder::new();
        for (name, content, mime) in files {
            builder = builder.add_file_content(name.to_string(), content.to_vec(), mime);
        }
        let tmp = NamedTempFile::new().expect("tempfile");
        block_on(builder.create_container(tmp.path())).expect("create_container");
        tmp
    }

    #[test]
    fn container_starts_with_uncompressed_mimetype_entry() {
        let tmp = build_container(&[("request.xml", b"<doc/>", "application/xml")]);
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
        let tmp = build_container(&[("payload.bin", &payload, "application/octet-stream")]);
        let f = std::fs::File::open(tmp.path()).unwrap();
        let mut zip = ZipArchive::new(f).unwrap();
        let mut entry = zip.by_name("payload.bin").expect("data file present");
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, payload);
    }

    #[test]
    fn container_emits_manifest_listing_data_files_only() {
        let tmp = build_container(&[
            ("request.xml", b"<a/>", "application/xml"),
            ("attachment.pdf", b"%PDF", "application/pdf"),
        ]);
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
    fn container_omits_signatures_directory_when_no_signatures_added() {
        let tmp = build_container(&[("request.xml", b"<a/>", "application/xml")]);
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

    #[test]
    fn sign_verify_roundtrip() {
        use crate::test_keys::{TEST_CERT, TEST_KEY};
        use crate::xmldsig::SigningKeyType;
        use rsa::pkcs8::DecodePrivateKey;

        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(TEST_KEY).unwrap();
        let signer = SigningKeyType::Rsa(Box::new(private_key));

        let builder = DigiDocBuilder::new()
            .add_file_content("test.txt".to_string(), b"hello world".to_vec(), "text/plain")
            .add_signer(DigiDocSignerInput {
                signer: Box::new(signer),
                certificate_der: TEST_CERT.to_vec(),
                signing_time: chrono::Utc::now(),
                production_place: None,
                claimed_roles: Vec::new(),
                tsa_url: None,
                ocsp_url: None,
                issuer_cert_der: None,
            });

        let out = NamedTempFile::new().unwrap();
        block_on(builder.create_container(out.path())).expect("create_container");

        let reader = DigiDocReader::new(out.path().to_str().unwrap());
        let res = reader.parse_document().expect("parse_document");
        assert!(res.is_valid, "Validation failed: {:?}", res.validation_errors);
        assert_eq!(res.signatures.len(), 1);
        assert!(res.signatures[0].is_valid);
    }
}
