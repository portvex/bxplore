//! The CMS verifier against signatures produced by OpenSSL (see
//! `tests/fixtures/make.sh`): RSA, ECDSA P-256 and P-384 signers with a
//! two certificate chain, a signer issued by a certificate that is not a CA,
//! and an RFC 3161 timestamp token.

use bxplore::pe::sig::{describe, verify_cms, verify_timestamp_token};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)).unwrap()
}

#[test]
fn rsa_and_ecdsa_signatures_verify() {
    for (file, key) in [("cms_rsa.der", "RSA 2048 bit"), ("cms_p256.der", "ECDSA P-256"), ("cms_p384.der", "ECDSA P-384")] {
        let report = verify_cms(&fixture(file));
        assert!(report.contains("Result: valid"), "{file}:\n{report}");
        assert!(report.contains(key), "{file}:\n{report}");
        assert!(
            report.contains("Signed attributes  OK") && report.contains("Signature          OK") && report.contains("Certificate chain  OK"),
            "{file}:\n{report}"
        );
        assert!(report.contains("self-signed root: signature OK"), "{file}: the chain reaches the test root\n{report}");
    }
}

#[test]
fn a_certificate_issued_by_a_non_ca_fails_the_chain() {
    // The signer's certificate was issued with the key of an end entity
    // certificate, which chains to the test root. Every signature is good.
    let report = verify_cms(&fixture("cms_leaf_issued.der"));
    assert!(report.contains("Signature          OK") && report.contains("self-signed root: signature OK"), "{report}");
    assert!(report.contains("Certificate chain  FAILED") && report.contains("\"CN=cffx test signer rogue\" issued a certificate but is not a CA"), "{report}");
    assert!(report.contains("signature OK (SHA-256), but the issuer is NOT a CA certificate"), "{report}");
    assert!(report.contains("Result: NOT valid"), "{report}");
}

#[test]
fn changes_to_signed_data_are_detected() {
    // Every single-bit change to the signed message or to the signature value
    // must turn the result invalid. (Bytes outside what is signed, such as the
    // root certificate, may change without that being a forgery.)
    let message = fixture("message.txt");
    for file in ["cms_rsa.der", "cms_p256.der", "cms_p384.der"] {
        let good = fixture(file);
        let at = good.windows(message.len()).position(|w| w == &message[..]).expect("the message is embedded");
        let tail = good.len() - 40..good.len();
        for i in (at..at + message.len()).chain(tail) {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            assert!(!verify_cms(&bad).contains("Result: valid"), "{file}: a change at byte {i} went unnoticed");
        }
        // Swapping in another signer's signature does not pass either.
        let other = fixture(if file == "cms_rsa.der" { "cms_p256.der" } else { "cms_rsa.der" });
        let mut spliced = good.clone();
        let n = 32.min(other.len());
        let end = spliced.len();
        spliced[end - n..].copy_from_slice(&other[other.len() - n..]);
        assert!(!verify_cms(&spliced).contains("Result: valid"), "{file}: a foreign signature was accepted");
    }
}

#[test]
fn timestamp_token_covers_its_data() {
    let token = fixture("timestamp_token.der");
    let message = fixture("message.txt");
    let report = verify_timestamp_token(&token, &message);
    assert!(report.contains("Result: valid"), "{report}");
    assert!(report.contains("Message imprint    OK"), "{report}");
    assert!(report.contains("Time: 20"), "the token states when it was issued\n{report}");

    let other = verify_timestamp_token(&token, b"some other data");
    assert!(other.contains("Message imprint    FAILED") && other.contains("Result: NOT valid"), "{other}");
}

/// One DER element: tag, header length and content length.
fn der(b: &[u8]) -> (u8, usize, usize) {
    match b[1] {
        n if n < 0x80 => (b[0], 2, n as usize),
        n => (b[0], 2 + (n & 0x7f) as usize, b[2..2 + (n & 0x7f) as usize].iter().fold(0, |v, x| v << 8 | *x as usize)),
    }
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len().to_be_bytes();
    let len = &len[len.iter().position(|b| *b != 0).unwrap_or(len.len() - 1)..];
    let mut out = vec![tag];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        out.push(0x80 | len.len() as u8);
        out.extend_from_slice(len);
    }
    out.extend_from_slice(content);
    out
}

/// The last element `depth` levels down, and the input with `extra` appended inside it.
fn append_in_last(b: &[u8], depth: usize, extra: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (tag, hdr, len) = der(b);
    let content = &b[hdr..hdr + len];
    if depth == 0 {
        return (b[..hdr + len].to_vec(), der_wrap(tag, &[content, extra].concat()));
    }
    let mut last = 0;
    loop {
        let (_, h, l) = der(&content[last..]);
        if last + h + l >= content.len() {
            break;
        }
        last += h + l;
    }
    let (found, rebuilt) = append_in_last(&content[last..], depth - 1, extra);
    (found, der_wrap(tag, &[&content[..last], &rebuilt[..]].concat()))
}

#[test]
fn only_the_first_timestamps_of_a_signer_are_verified() {
    // ContentInfo > [0] > SignedData > signerInfos > SignerInfo: give the signer
    // 300 counter signatures (copies of itself) as one unauthenticated attribute.
    let good = fixture("cms_p384.der");
    let signer = append_in_last(&good, 4, &[]).0;
    let values = der_wrap(0x31, &signer.repeat(300));
    let attr = der_wrap(0x30, &[&[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06][..], &values[..]].concat());
    let blob = append_in_last(&good, 4, &der_wrap(0xA1, &attr)).1;
    assert!(verify_cms(&blob).contains("Result: valid"), "the unauthenticated attribute does not disturb the signature");

    let file = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/parse_any/tiny.exe")).unwrap();
    let report = describe(&file, &bxplore::pe::Pe::parse(&file).unwrap(), &blob);
    assert_eq!(report.matches("Timestamp (counter signature)").count(), 8, "{report}");
    assert!(report.contains("292 more timestamp(s) were not checked"), "{report}");
    assert!(report.len() < 40_000, "{} bytes of report", report.len());
}

#[test]
fn nested_signatures_and_timestamps_share_one_verification_budget() {
    // The signer gets 8 counter signatures (copies of itself), and that blob is
    // nested 8 times in itself. Each signer costs a signature and two chain
    // steps, so everything together would be 9 x 9 x 3 = 243 verifications.
    let good = fixture("cms_p384.der");
    let signer = append_in_last(&good, 4, &[]).0;
    let attr = |oid: &[u8], value: &[u8]| der_wrap(0x30, &[oid, &der_wrap(0x31, &value.repeat(8))[..]].concat());
    let counter = attr(&[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06], &signer);
    let inner = append_in_last(&good, 4, &der_wrap(0xA1, &counter)).1;
    let nested = attr(&[0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01], &inner);
    let blob = append_in_last(&good, 4, &der_wrap(0xA1, &[counter, nested].concat())).1;

    let file = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/parse_any/tiny.exe")).unwrap();
    let report = describe(&file, &bxplore::pe::Pe::parse(&file).unwrap(), &blob);
    assert_eq!(report.matches("Timestamp (counter signature)").count(), 72, "every signature is still listed\n{report}");
    // Every signature here is good, so each verification that ran left an OK.
    let verified = report.matches("Signature          OK").count() + report.matches("signature OK (").count();
    assert_eq!(verified, 64, "{report}");
    assert!(report.contains("not checked: verification budget used up"), "{report}");
    assert!(report.contains("Signature (Nested signature 8)"), "an unchecked signature is named in the verdict\n{report}");
    assert!(!report.contains("Result: the signature is cryptographically valid"), "{report}");
}
