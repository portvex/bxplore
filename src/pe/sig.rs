//! Authenticode verification: the image digest, the signed attributes, the
//! signer's RSA or ECDSA signature, the embedded certificate chain, nested
//! signatures and timestamps are all checked cryptographically, and every
//! certificate that issued another one must be a CA. What is not decided here is trust: whether the root of
//! the chain is one the operating system trusts, validity periods, and revocation.

use super::Pe;
use crate::model::{hex_bytes, printable};
use num_bigint::BigUint;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

#[derive(Clone, Copy)]
struct Tlv {
    tag: u8,
    start: usize,
    end: usize,
}

fn tlv(b: &[u8], off: usize) -> Option<Tlv> {
    let tag = *b.get(off)?;
    let l0 = *b.get(off + 1)? as usize;
    let (len, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7F;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(off + 2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let start = off + hdr;
    let end = start.checked_add(len)?;
    (end <= b.len()).then_some(Tlv { tag, start, end })
}

fn children(b: &[u8], t: Tlv) -> Vec<Tlv> {
    let mut out = Vec::new();
    let mut off = t.start;
    while off < t.end && out.len() < 4096 {
        match tlv(b, off) {
            Some(c) if c.end <= t.end => {
                off = c.end;
                out.push(c);
            }
            _ => break,
        }
    }
    out
}

fn name_text(b: &[u8], name: Tlv) -> String {
    let mut parts = Vec::new();
    for set in children(b, name) {
        for attr in children(b, set) {
            let kv = children(b, attr);
            if kv.len() < 2 || kv[0].tag != 0x06 {
                continue;
            }
            let oid = &b[kv[0].start..kv[0].end];
            let label = match oid {
                [0x55, 0x04, 0x03] => "CN",
                [0x55, 0x04, 0x0A] => "O",
                [0x55, 0x04, 0x0B] => "OU",
                [0x55, 0x04, 0x06] => "C",
                [0x55, 0x04, 0x07] => "L",
                [0x55, 0x04, 0x08] => "ST",
                _ => continue,
            };
            let raw = &b[kv[1].start..kv[1].end];
            let value = if kv[1].tag == 0x1E {
                let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&units)
            } else {
                String::from_utf8(raw.to_vec()).unwrap_or_else(|_| printable(raw))
            };
            parts.push(format!("{label}={value}"));
        }
    }
    parts.join(", ")
}

fn time_text(b: &[u8], t: Tlv) -> String {
    let s = printable(&b[t.start..t.end]);
    let (year, rest) = if t.tag == 0x17 && s.len() >= 12 {
        let yy: u32 = s[..2].parse().unwrap_or(0);
        (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
    } else if s.len() >= 14 {
        (s[..4].parse().unwrap_or(0), &s[4..])
    } else {
        return s;
    };
    if rest.len() < 10 {
        return s;
    }
    format!("{year:04}-{}-{} {}:{}", &rest[..2], &rest[2..4], &rest[4..6], &rest[6..8])
}

#[derive(Clone, Copy, PartialEq)]
enum Hash {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_digest_oid(oid: &[u8]) -> Option<Hash> {
        Some(match oid {
            [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05] => Hash::Md5,
            [0x2B, 0x0E, 0x03, 0x02, 0x1A] => Hash::Sha1,
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => Hash::Sha256,
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => Hash::Sha384,
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => Hash::Sha512,
            _ => return None,
        })
    }

    /// Hash of an `xxxWithRSAEncryption` signature algorithm.
    fn from_rsa_sig_oid(oid: &[u8]) -> Option<Hash> {
        match oid {
            [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, last] => match last {
                0x04 => Some(Hash::Md5),
                0x05 => Some(Hash::Sha1),
                0x0B => Some(Hash::Sha256),
                0x0C => Some(Hash::Sha384),
                0x0D => Some(Hash::Sha512),
                _ => None,
            },
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Hash::Md5 => "MD5",
            Hash::Sha1 => "SHA-1",
            Hash::Sha256 => "SHA-256",
            Hash::Sha384 => "SHA-384",
            Hash::Sha512 => "SHA-512",
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Md5 => md5::Md5::digest(data).to_vec(),
            Hash::Sha1 => Sha1::digest(data).to_vec(),
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    fn image(self, data: &[u8], pe: &Pe) -> Vec<u8> {
        match self {
            Hash::Md5 => image_hash::<md5::Md5>(data, pe),
            Hash::Sha1 => image_hash::<Sha1>(data, pe),
            Hash::Sha256 => image_hash::<Sha256>(data, pe),
            Hash::Sha384 => image_hash::<Sha384>(data, pe),
            Hash::Sha512 => image_hash::<Sha512>(data, pe),
        }
    }

    /// DER prefix of the DigestInfo structure used by PKCS#1 v1.5.
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Hash::Md5 => &[0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10],
            Hash::Sha1 => &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14],
            Hash::Sha256 => &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
            Hash::Sha384 => &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
            Hash::Sha512 => &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
        }
    }
}

const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_EC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
const OID_SIGNING_TIME: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];
const OID_COUNTER_SIGNATURE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06];
const OID_RFC3161_TOKEN: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01];
const OID_NESTED_SIGNATURE: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01];

/// Hash used by an `ecdsa-with-SHAxxx` signature algorithm.
fn ecdsa_sig_hash(oid: &[u8]) -> Option<Hash> {
    match oid {
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01] => Some(Hash::Sha1),
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02] => Some(Hash::Sha256),
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03] => Some(Hash::Sha384),
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04] => Some(Hash::Sha512),
        _ => None,
    }
}

struct RsaKey {
    n: BigUint,
    e: BigUint,
    bytes: usize,
}

/// PKCS#1 v1.5 signature check: `sig^e mod n` must be the padded DigestInfo.
fn rsa_verify(key: &RsaKey, hash: Hash, digest: &[u8], sig: &[u8]) -> bool {
    let k = key.bytes;
    let prefix = hash.digest_info_prefix();
    if sig.len() > k + 1 || k < prefix.len() + digest.len() + 11 {
        return false;
    }
    let em = BigUint::from_bytes_be(sig).modpow(&key.e, &key.n).to_bytes_be();
    if em.len() > k {
        return false;
    }
    let mut expected = vec![0u8; k];
    expected[1] = 1;
    let t = prefix.len() + digest.len();
    expected[2..k - t - 1].fill(0xFF);
    expected[k - t..k - digest.len()].copy_from_slice(prefix);
    expected[k - digest.len()..].copy_from_slice(digest);
    let mut padded = vec![0u8; k - em.len()];
    padded.extend_from_slice(&em);
    padded == expected
}

enum Key {
    Rsa(RsaKey),
    /// Uncompressed SEC1 point on NIST P-256 or P-384.
    P256(Vec<u8>),
    P384(Vec<u8>),
}

/// Check a signature over an already computed digest.
fn verify(key: &Key, hash: Hash, digest: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    match key {
        Key::Rsa(k) => rsa_verify(k, hash, digest, sig),
        Key::P256(point) => match (p256::ecdsa::VerifyingKey::from_sec1_bytes(point), p256::ecdsa::Signature::from_der(sig)) {
            (Ok(k), Ok(s)) => k.verify_prehash(digest, &s).is_ok(),
            _ => false,
        },
        Key::P384(point) => match (p384::ecdsa::VerifyingKey::from_sec1_bytes(point), p384::ecdsa::Signature::from_der(sig)) {
            (Ok(k), Ok(s)) => k.verify_prehash(digest, &s).is_ok(),
            _ => false,
        },
    }
}

struct Cert {
    /// The whole TBSCertificate element, tag and length included: what the issuer signed.
    tbs: (usize, usize),
    serial: (usize, usize),
    issuer: Tlv,
    subject: Tlv,
    not_before: String,
    not_after: String,
    sig_oid: (usize, usize),
    sig: (usize, usize),
    key: Option<Key>,
    key_note: String,
    /// May sign other certificates: basicConstraints says cA, or this is a
    /// version 1 certificate, which has no extensions to say so.
    ca: bool,
    v1: bool,
}

fn slice(b: &[u8], r: (usize, usize)) -> &[u8] {
    b.get(r.0..r.1).unwrap_or(&[])
}

fn oid_of(b: &[u8], alg: Tlv) -> Option<(usize, usize)> {
    children(b, alg).first().filter(|t| t.tag == 0x06).map(|t| (t.start, t.end))
}

/// `tbs_start` is where the certificate's content, and so its TBS element, begins.
fn parse_cert(b: &[u8], cert: Tlv) -> Option<Cert> {
    let parts = children(b, cert);
    let [tbs, alg, sig, ..] = parts.as_slice() else { return None };
    let mut f = children(b, *tbs);
    // Without the [0] version element the certificate is version 1.
    let v1 = f.first().is_none_or(|t| t.tag != 0xA0);
    if !v1 {
        f.remove(0);
    }
    if f.len() < 6 || sig.tag != 0x03 || sig.end <= sig.start {
        return None;
    }
    let validity = children(b, f[3]);
    let (not_before, not_after) = match validity.as_slice() {
        [a, z, ..] => (time_text(b, *a), time_text(b, *z)),
        _ => (String::new(), String::new()),
    };
    // SubjectPublicKeyInfo: algorithm, then a BIT STRING wrapping the key.
    let spki = children(b, f[5]);
    let mut key = None;
    let mut key_note = "unsupported public key type".to_string();
    if let [key_alg, bits, ..] = spki.as_slice()
        && bits.tag == 0x03
        && bits.end > bits.start
    {
        let alg = children(b, *key_alg);
        let alg_oid = alg.first().map(|t| &b[t.start..t.end]);
        let param = alg.get(1).map(|t| &b[t.start..t.end]);
        if alg_oid == Some(OID_RSA) {
            if let Some(seq) = tlv(b, bits.start + 1)
                && let [n, e, ..] = children(b, seq).as_slice()
            {
                let n = BigUint::from_bytes_be(&b[n.start..n.end]);
                let e_bytes = &b[e.start..e.end];
                let bits = n.bits() as usize;
                // Bounds keep verification cheap even for hostile certificates.
                if (512..=8192).contains(&bits) && e_bytes.iter().skip_while(|x| **x == 0).count() <= 4 {
                    key_note = format!("RSA {bits} bit");
                    key = Some(Key::Rsa(RsaKey { e: BigUint::from_bytes_be(e_bytes), bytes: bits.div_ceil(8), n }));
                } else {
                    key_note = "RSA key with unusual parameters".into();
                }
            }
        } else if alg_oid == Some(OID_EC_KEY) {
            let point = b[bits.start + 1..bits.end].to_vec();
            match param {
                Some(OID_P256) => {
                    key_note = "ECDSA P-256".into();
                    key = Some(Key::P256(point));
                }
                Some(OID_P384) => {
                    key_note = "ECDSA P-384".into();
                    key = Some(Key::P384(point));
                }
                _ => key_note = "elliptic curve key on an unsupported curve".into(),
            }
        }
    }
    // Extensions [3] > SEQUENCE OF { OID, critical?, OCTET STRING }; basicConstraints
    // (2.5.29.19) wraps SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen }.
    let ca = f[6..].iter().filter(|t| t.tag == 0xA3).flat_map(|t| tlv(b, t.start)).flat_map(|list| children(b, list)).any(|ext| {
        let e = children(b, ext);
        e.first().is_some_and(|o| o.tag == 0x06 && b[o.start..o.end] == [0x55, 0x1D, 0x13])
            && e.last()
                .filter(|v| v.tag == 0x04)
                .and_then(|v| tlv(b, v.start))
                .and_then(|bc| children(b, bc).first().copied())
                .is_some_and(|c| c.tag == 0x01 && b[c.start..c.end].iter().any(|x| *x != 0))
    });
    Some(Cert {
        ca,
        v1,
        tbs: (cert.start, tbs.end),
        serial: (f[0].start, f[0].end),
        issuer: f[2],
        subject: f[4],
        not_before,
        not_after,
        sig_oid: oid_of(b, *alg)?,
        sig: (sig.start + 1, sig.end),
        key,
        key_note,
    })
}

fn same(b: &[u8], x: Tlv, y: Tlv) -> bool {
    b[x.start..x.end] == b[y.start..y.end]
}

/// Public key operations one blob may cost. The caps on nested signatures,
/// timestamps and chain length multiply, and a hostile file pays for every
/// one of them with the largest key it can carry; real files need about 20.
const MAX_VERIFICATIONS: usize = 64;
const BUDGET_SPENT: &str = "not checked: verification budget used up";

/// What is left of `MAX_VERIFICATIONS` while one blob is verified.
struct Budget(std::cell::Cell<usize>);

impl Budget {
    fn new() -> Budget {
        Budget(std::cell::Cell::new(MAX_VERIFICATIONS))
    }

    /// Pay for one public key operation; false when nothing is left.
    fn take(&self) -> bool {
        let left = self.0.get();
        self.0.set(left.saturating_sub(1));
        left > 0
    }
}

/// Verify `child`'s signature with `issuer`'s key.
fn cert_signed_by(b: &[u8], child: &Cert, issuer: &Cert, budget: &Budget) -> Result<Hash, String> {
    let oid = slice(b, child.sig_oid);
    let hash = Hash::from_rsa_sig_oid(oid).or_else(|| ecdsa_sig_hash(oid)).ok_or("unsupported signature algorithm, not verified")?;
    let key = issuer.key.as_ref().ok_or_else(|| format!("issuer has a {}", issuer.key_note))?;
    if !budget.take() {
        return Err(BUDGET_SPENT.into());
    }
    if verify(key, hash, &hash.digest(slice(b, child.tbs)), slice(b, child.sig)) { Ok(hash) } else { Err("SIGNATURE INVALID".into()) }
}

struct Signed {
    certs: Vec<Cert>,
    /// Digest algorithm and value of the image, from SpcIndirectDataContent.
    image_digest: Option<(Option<Hash>, (usize, usize))>,
    /// Value bytes of the signed content (what messageDigest covers).
    content: Option<(usize, usize)>,
    signer: Option<Signer>,
}

struct Signer {
    issuer: Tlv,
    serial: (usize, usize),
    hash: Option<Hash>,
    /// The authenticated attributes element, tag and length included.
    attrs: Option<(usize, usize)>,
    message_digest: Option<(usize, usize)>,
    signing_time: Option<String>,
    sig: (usize, usize),
    /// Values of the unauthenticated attributes, by kind.
    counter_signatures: Vec<usize>,
    timestamp_tokens: Vec<Tlv>,
    nested: Vec<Tlv>,
}

/// Parse one SignerInfo that starts at `off`.
fn parse_signer(b: &[u8], off: usize) -> Option<Signer> {
    let info = tlv(b, off)?;
    let fields = children(b, info);
    let mut signer = Signer {
        issuer: info,
        serial: (0, 0),
        hash: None,
        attrs: None,
        message_digest: None,
        signing_time: None,
        sig: (0, 0),
        counter_signatures: Vec::new(),
        timestamp_tokens: Vec::new(),
        nested: Vec::new(),
    };
    let ias = fields.get(1)?;
    if let [issuer, serial, ..] = children(b, *ias).as_slice() {
        signer.issuer = *issuer;
        signer.serial = (serial.start, serial.end);
    }
    signer.hash = fields.get(2).and_then(|a| oid_of(b, *a)).and_then(|o| Hash::from_digest_oid(slice(b, o)));
    // Element start offsets are needed, so track them while walking the fields.
    let mut field_off = info.start;
    for f in &fields {
        if f.tag == 0xA0 {
            signer.attrs = Some((field_off, f.end));
            for attr in children(b, *f) {
                if let [oid, set, ..] = children(b, attr).as_slice()
                    && let Some(v) = children(b, *set).first()
                {
                    match &b[oid.start..oid.end] {
                        OID_MESSAGE_DIGEST => signer.message_digest = Some((v.start, v.end)),
                        OID_SIGNING_TIME => signer.signing_time = Some(time_text(b, *v)),
                        _ => {}
                    }
                }
            }
        }
        if f.tag == 0xA1 {
            for attr in children(b, *f) {
                let kv = children(b, attr);
                let [oid, set, ..] = kv.as_slice() else { continue };
                // Each value's start offset: values are laid out back to back in the SET.
                let mut value_off = set.start;
                for v in children(b, *set) {
                    match &b[oid.start..oid.end] {
                        OID_COUNTER_SIGNATURE => signer.counter_signatures.push(value_off),
                        OID_RFC3161_TOKEN => signer.timestamp_tokens.push(v),
                        OID_NESTED_SIGNATURE => signer.nested.push(v),
                        _ => {}
                    }
                    value_off = v.end;
                }
            }
        }
        field_off = f.end;
    }
    let sig = fields.iter().find(|t| t.tag == 0x04)?;
    signer.sig = (sig.start, sig.end);
    Some(signer)
}

/// Parse a ContentInfo that wraps SignedData.
fn parse_signed(b: &[u8], content_info: Tlv) -> Option<Signed> {
    let ci = children(b, content_info);
    let wrapper = ci.iter().find(|c| c.tag == 0xA0)?;
    let signed_data = children(b, *wrapper).into_iter().next()?;
    let sd = children(b, signed_data);
    let mut out = Signed { certs: Vec::new(), image_digest: None, content: None, signer: None };

    // encapContentInfo: SEQUENCE { OID, [0] { content } }. For Authenticode the
    // content is SpcIndirectDataContent, for a timestamp token an OCTET STRING.
    if let Some(encap) = sd.iter().find(|t| t.tag == 0x30)
        && let Some(explicit) = children(b, *encap).iter().find(|t| t.tag == 0xA0)
        && let Some(inner) = children(b, *explicit).first()
    {
        out.content = Some((inner.start, inner.end));
        if let [_, digest_info, ..] = children(b, *inner).as_slice()
            && let [alg, value, ..] = children(b, *digest_info).as_slice()
            && value.tag == 0x04
        {
            out.image_digest = Some((oid_of(b, *alg).and_then(|o| Hash::from_digest_oid(slice(b, o))), (value.start, value.end)));
        }
    }
    if let Some(certs) = sd.iter().find(|c| c.tag == 0xA0) {
        for c in children(b, *certs).into_iter().take(64) {
            if c.tag == 0x30
                && let Some(cert) = parse_cert(b, c)
            {
                out.certs.push(cert);
            }
        }
    }
    let infos = sd.iter().rev().find(|t| t.tag == 0x31)?;
    out.signer = parse_signer(b, infos.start);
    Some(out)
}

/// Authenticode image hash: the file without the checksum, the security
/// directory entry and the certificate table.
fn image_hash<D: Digest>(data: &[u8], pe: &Pe) -> Vec<u8> {
    let (cert_off, cert_size) = pe.dir(data, 4);
    let (cert_off, cert_size) = (cert_off as usize, cert_size as usize);
    let checksum = pe.opt + 64;
    let dir = pe.dirs_off + 32;
    let mut h = D::new();
    let cert_start = if cert_off != 0 { cert_off.min(data.len()) } else { data.len() };
    let mut feed = |from: usize, to: usize| {
        if from < to && to <= data.len() {
            h.update(&data[from..to]);
        }
    };
    feed(0, checksum);
    feed(checksum + 4, dir);
    feed(dir + 8, cert_start);
    feed((cert_start + cert_size).min(data.len()), data.len());
    h.finalize().to_vec()
}

fn now_text() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    crate::model::time_text(secs)
}

/// One line of a verification report.
struct Check {
    label: &'static str,
    /// Some(true) passed, Some(false) failed, None could not be performed.
    ok: Option<bool>,
    text: String,
}

struct Report {
    checks: Vec<Check>,
    /// Extra lines under the checks: the certificate chain.
    detail: Vec<String>,
}

impl Report {
    fn new() -> Report {
        Report { checks: Vec::new(), detail: Vec::new() }
    }

    fn add(&mut self, label: &'static str, ok: Option<bool>, text: String) {
        self.checks.push(Check { label, ok, text });
    }

    fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.ok == Some(true))
    }

    fn write(&self, out: &mut String, indent: &str) {
        for c in &self.checks {
            let mark = match c.ok {
                Some(true) => "OK     ",
                Some(false) => "FAILED ",
                None => "SKIPPED",
            };
            out.push_str(&format!("{indent}{:<18} {mark}  {}\n", c.label, c.text));
        }
        for (n, t) in self.detail.iter().enumerate() {
            out.push_str(&format!("{indent}  {}. {t}\n", n + 1));
        }
    }
}

/// The checks every CMS signer gets: the attributes cover the content, the
/// signature covers the attributes, and the certificates chain up.
/// `content` is what the signer's messageDigest attribute must match.
fn check_signer(b: &[u8], certs: &[Cert], s: &Signer, content: Option<&[u8]>, r: &mut Report, budget: &Budget) -> Option<usize> {
    let signer_cert = certs.iter().position(|c| same(b, c.issuer, s.issuer) && slice(b, c.serial) == slice(b, s.serial));
    match (s.hash, s.message_digest, content) {
        (Some(h), Some(md), Some(content)) => {
            let ok = h.digest(content) == slice(b, md);
            r.add(
                "Signed attributes",
                Some(ok),
                format!("messageDigest attribute {} the signed content ({})", if ok { "matches" } else { "does NOT match" }, h.name()),
            );
        }
        _ => r.add("Signed attributes", None, "no messageDigest attribute or unknown digest algorithm".into()),
    }
    match (s.hash, s.attrs, signer_cert.map(|i| &certs[i])) {
        (Some(h), Some(attrs), Some(cert)) => match &cert.key {
            Some(_) if !budget.take() => r.add("Signature", None, BUDGET_SPENT.into()),
            Some(key) => {
                // The attributes are signed as a SET OF, not with their [0] tag.
                let mut der = slice(b, attrs).to_vec();
                if let Some(first) = der.first_mut() {
                    *first = 0x31;
                }
                let ok = verify(key, h, &h.digest(&der), slice(b, s.sig));
                r.add("Signature", Some(ok), format!("{}, {} by {}", cert.key_note, h.name(), name_text(b, cert.subject)));
            }
            None => r.add("Signature", None, format!("the signer has a {}", cert.key_note)),
        },
        (_, _, None) => r.add("Signature", None, "the signer's certificate is not embedded".into()),
        _ => r.add("Signature", None, "no authenticated attributes or unknown digest algorithm".into()),
    }

    // The chain from the signer towards a root.
    let mut chain_ok = Some(true);
    let mut end = "the signer's certificate was not found".to_string();
    let mut not_ca = None;
    if let Some(mut i) = signer_cert {
        let mut seen = vec![i];
        loop {
            let c = &certs[i];
            let subject = name_text(b, c.subject);
            let result = |r: &Result<Hash, String>| r.as_ref().map(|h| format!("signature OK ({})", h.name())).unwrap_or_else(|e| e.clone());
            if same(b, c.subject, c.issuer) {
                let v = cert_signed_by(b, c, c, budget);
                r.detail.push(format!("{subject}\n       self-signed root: {}", result(&v)));
                if v.is_err() {
                    chain_ok = Some(false);
                }
                end = format!("ends at the self-signed root \"{subject}\"");
                break;
            }
            let Some(j) = certs.iter().position(|p| same(b, p.subject, c.issuer)) else {
                r.detail.push(format!("{subject}\n       issued by {} (not embedded)", name_text(b, c.issuer)));
                end = format!("ends at \"{}\", whose certificate is not embedded (normally the root in the OS trust store)", name_text(b, c.issuer));
                break;
            };
            let v = cert_signed_by(b, c, &certs[j], budget);
            // Any certificate can sign another one; only a CA may issue it.
            let p = &certs[j];
            let may_issue = p.ca || (p.v1 && same(b, p.subject, p.issuer));
            let remark = if may_issue { "" } else { ", but the issuer is NOT a CA certificate" };
            r.detail.push(format!("{subject}\n       issued by {}: {}{remark}", name_text(b, c.issuer), result(&v)));
            if !may_issue {
                chain_ok = Some(false);
                not_ca.get_or_insert_with(|| name_text(b, c.issuer));
            }
            match v {
                Err(e) if e == "SIGNATURE INVALID" => chain_ok = Some(false),
                Err(_) if chain_ok == Some(true) => chain_ok = None,
                _ => {}
            }
            if seen.contains(&j) || seen.len() >= 16 {
                end = "contains a loop".into();
                chain_ok = Some(false);
                break;
            }
            seen.push(j);
            i = j;
        }
    } else {
        chain_ok = None;
    }
    if let Some(name) = not_ca {
        end = format!("\"{name}\" issued a certificate but is not a CA certificate (basicConstraints)");
    }
    r.add("Certificate chain", chain_ok, end);
    signer_cert
}

/// Verify an RFC 3161 timestamp token against the bytes it should cover.
/// Returns the checks and the time the token states.
fn check_token(b: &[u8], token: Tlv, covered: &[u8], budget: &Budget) -> Option<(Report, Option<String>)> {
    let tsd = parse_signed(b, token)?;
    let mut r = Report::new();
    // TSTInfo: version, policy, messageImprint { algorithm, hash }, serial, genTime.
    let info = tsd.content.and_then(|c| tlv(b, c.0)).map(|t| children(b, t)).unwrap_or_default();
    let imprint = info.get(2).map(|t| children(b, *t)).unwrap_or_default();
    match imprint.as_slice() {
        [alg, value, ..] => match oid_of(b, *alg).and_then(|o| Hash::from_digest_oid(slice(b, o))) {
            Some(h) => {
                let ok = h.digest(covered) == b[value.start..value.end];
                r.add(
                    "Message imprint",
                    Some(ok),
                    format!("{} of the timestamped data {} the hash in the token", h.name(), if ok { "matches" } else { "does NOT match" }),
                );
            }
            None => r.add("Message imprint", None, "unknown digest algorithm".into()),
        },
        _ => r.add("Message imprint", None, "the token has no TSTInfo".into()),
    }
    match &tsd.signer {
        Some(ts) => {
            check_signer(b, &tsd.certs, ts, tsd.content.map(|c| slice(b, c)), &mut r, budget);
        }
        None => r.add("Signature", None, "the token has no signer".into()),
    }
    let time = info.iter().find(|t| t.tag == 0x18).map(|t| time_text(b, *t));
    Some((r, time))
}

/// Verify a standalone RFC 3161 timestamp token (a CMS ContentInfo) against
/// the data it was issued for.
pub fn verify_timestamp_token(token: &[u8], covered: &[u8]) -> String {
    let Some((r, time)) = tlv(token, 0).and_then(|t| check_token(token, t, covered, &Budget::new())) else { return "not a timestamp token\n".into() };
    let mut out = String::new();
    r.write(&mut out, "");
    out.push_str(&format!("Time: {}\n", time.unwrap_or_default()));
    out.push_str(if r.passed() { "Result: valid\n" } else { "Result: NOT valid\n" });
    out
}

/// Timestamps of each kind verified per signer. Every one costs a signature
/// check and a chain walk, and a signer can carry thousands of them.
const MAX_TIMESTAMPS: usize = 8;

/// Verify the timestamps attached to a signer: legacy counter signatures and
/// RFC 3161 tokens. Both must cover the signer's signature value.
fn timestamps(b: &[u8], sd: &Signed, s: &Signer, out: &mut String, budget: &Budget) {
    let signature = slice(b, s.sig);
    for off in s.counter_signatures.iter().take(MAX_TIMESTAMPS) {
        let Some(ts) = parse_signer(b, *off) else { continue };
        let mut r = Report::new();
        check_signer(b, &sd.certs, &ts, Some(signature), &mut r, budget);
        out.push_str(&format!(
            "  Timestamp (counter signature){}: {}\n",
            ts.signing_time.as_ref().map(|t| format!(", signed at {t} UTC")).unwrap_or_default(),
            if r.passed() { "valid, it covers this signature" } else { "NOT verified" }
        ));
        r.write(out, "    ");
    }
    for token in s.timestamp_tokens.iter().take(MAX_TIMESTAMPS) {
        let Some((r, time)) = check_token(b, *token, signature, budget) else { continue };
        out.push_str(&format!(
            "  Timestamp (RFC 3161 token){}: {}\n",
            time.map(|t| format!(", issued at {t} UTC")).unwrap_or_default(),
            if r.passed() { "valid, it covers this signature" } else { "NOT verified" }
        ));
        r.write(out, "    ");
    }
    let skipped = s.counter_signatures.len().saturating_sub(MAX_TIMESTAMPS) + s.timestamp_tokens.len().saturating_sub(MAX_TIMESTAMPS);
    if skipped > 0 {
        out.push_str(&format!("  {skipped} more timestamp(s) were not checked: only the first {MAX_TIMESTAMPS} of each kind are.\n"));
    }
    if s.counter_signatures.is_empty() && s.timestamp_tokens.is_empty() {
        out.push_str("  Timestamp: none, so the signature is only valid while the certificates are.\n");
    }
}

/// Full report for one Authenticode signature. Returns the checks that did
/// not pass as "label (title)": those that failed, and those that could not
/// be performed.
fn report_signature(data: &[u8], pe: &Pe, b: &[u8], sd: &Signed, title: &str, out: &mut String, budget: &Budget) -> (Vec<String>, Vec<String>) {
    let mut r = Report::new();
    // The image digest skips whatever range the security directory names, and
    // the directory entry itself is not hashed. Only a table behind all
    // section data is outside the image; anywhere else it would hide bytes
    // that sections map from the digest.
    let (cert_off, cert_size) = pe.dir(data, 4);
    let (cert_off, cert_end) = (cert_off as usize, cert_off as usize + cert_size as usize);
    if cert_off != 0 {
        let (ok, text) = if cert_off < pe.raw_end() {
            (
                false,
                "the certificate table is not at the end of the file: it lies in front of section data, which the image digest then does not cover".to_string(),
            )
        } else if cert_end > data.len() {
            (false, "the certificate table reaches past the end of the file".to_string())
        } else if cert_end < data.len() {
            (true, format!("the table follows all section data; {} byte(s) after it are covered by the image digest", data.len() - cert_end))
        } else {
            (true, "the table follows all section data and ends the file".to_string())
        };
        r.add("Certificate table", Some(ok), text);
    }
    match &sd.image_digest {
        Some((Some(h), d)) => {
            let ok = h.image(data, pe) == slice(b, *d);
            r.add(
                "Image digest",
                Some(ok),
                if ok {
                    format!("{} of the file matches the signed digest; the file was not modified after signing", h.name())
                } else {
                    format!("{} of the file differs from the signed digest; the file was modified after signing", h.name())
                },
            );
        }
        Some((None, _)) => r.add("Image digest", None, "unknown digest algorithm".into()),
        None => r.add("Image digest", None, "no SpcIndirectDataContent found".into()),
    }
    match &sd.signer {
        Some(s) => {
            check_signer(b, &sd.certs, s, sd.content.map(|c| slice(b, c)), &mut r, budget);
        }
        None => r.add("Signature", None, "no SignerInfo found".into()),
    }
    out.push_str(&format!("{title}\n"));
    r.write(out, "  ");
    if let Some(s) = &sd.signer {
        timestamps(b, sd, s, out, budget);
    }
    out.push_str(if r.passed() {
        "  Result: this signature is cryptographically valid and the file is unchanged since signing.\n\n"
    } else {
        "  Result: at least one check failed or could not be performed; see above.\n\n"
    });
    let named = |state: Option<bool>| r.checks.iter().filter(|c| c.ok == state).map(|c| format!("{} ({title})", c.label)).collect();
    (named(Some(false)), named(None))
}

fn cert_list(b: &[u8], sd: &Signed, out: &mut String) {
    let now = now_text();
    let signer = sd.signer.as_ref().and_then(|s| sd.certs.iter().position(|c| same(b, c.issuer, s.issuer) && slice(b, c.serial) == slice(b, s.serial)));
    out.push_str(&format!("Embedded certificates ({}):\n\n", sd.certs.len()));
    for (i, c) in sd.certs.iter().enumerate() {
        let state = if !c.not_after.is_empty() && c.not_after.as_str() < &now[..c.not_after.len().min(now.len())] {
            " (expired; fine if the signature is timestamped)"
        } else {
            ""
        };
        out.push_str(&format!(
            "Certificate {}{}\n  Subject: {}\n  Issuer:  {}\n  Serial:  {}\n  Valid:   {} to {}{state}\n  Key:     {}\n\n",
            i + 1,
            if signer == Some(i) { " (signer)" } else { "" },
            name_text(b, c.subject),
            name_text(b, c.issuer),
            hex_bytes(slice(b, c.serial)),
            c.not_before,
            c.not_after,
            c.key_note,
        ));
    }
}

pub fn describe(data: &[u8], pe: &Pe, blob: &[u8]) -> String {
    let mut out = String::new();
    let sha1 = image_hash::<Sha1>(data, pe);
    let sha256 = image_hash::<Sha256>(data, pe);
    out.push_str(&format!("Authenticode SHA-1:   {}\n", hex_bytes(&sha1).to_lowercase()));
    out.push_str(&format!("Authenticode SHA-256: {}\n\n", hex_bytes(&sha256).to_lowercase()));

    let Some(sd) = tlv(blob, 0).and_then(|ci| parse_signed(blob, ci)) else {
        let found = |h: &[u8]| blob.windows(h.len()).any(|w| w == h);
        out.push_str("The PKCS#7 blob could not be parsed, so the signature was not verified.\n");
        out.push_str(if found(&sha256) || found(&sha1) {
            "The image hash does appear in the blob, so the file content matches what was signed.\n"
        } else {
            "The image hash does not appear in the blob.\n"
        });
        return out;
    };

    // The verdict is what the view is opened for, so it goes above the
    // details, which are collected first.
    let mut details = String::new();
    let budget = Budget::new();
    let (mut failed, mut skipped) = report_signature(data, pe, blob, &sd, "Primary signature", &mut details, &budget);
    // Dual signed files carry further signatures as an attribute of the first.
    let nested: Vec<Signed> = sd.signer.iter().flat_map(|s| s.nested.iter()).filter_map(|n| parse_signed(blob, *n)).take(8).collect();
    for (i, n) in nested.iter().enumerate() {
        let (f, s) = report_signature(data, pe, blob, n, &format!("Nested signature {}", i + 1), &mut details, &budget);
        failed.extend(f);
        skipped.extend(s);
    }
    if failed.is_empty() && skipped.is_empty() {
        out.push_str("Result: the signature is cryptographically valid and the file is unchanged since signing.\n");
    } else {
        out.push_str(if failed.is_empty() { "Result: NOT verified." } else { "Result: NOT valid." });
        for (what, names) in [("Failed", &failed), ("Could not be checked", &skipped)] {
            if !names.is_empty() {
                out.push_str(&format!(" {what}: {}.", names.join(", ")));
            }
        }
        out.push_str(" Details below.\n");
    }
    out.push_str("Not checked here: whether the roots are trusted by the operating system, the validity periods of the certificates, and revocation.\n\n");
    out.push_str(&details);
    cert_list(blob, &sd, &mut out);
    for (i, n) in nested.iter().enumerate() {
        out.push_str(&format!("Nested signature {}\n", i + 1));
        cert_list(blob, n, &mut out);
    }
    out
}

/// Verify a plain CMS SignedData blob (not tied to a PE image): the signer's
/// attributes, signature and certificate chain. Used for testing the
/// verifier with signatures made by other tools.
pub fn verify_cms(blob: &[u8]) -> String {
    let mut out = String::new();
    let Some(sd) = tlv(blob, 0).and_then(|ci| parse_signed(blob, ci)) else { return "not a CMS SignedData structure\n".into() };
    let mut r = Report::new();
    match &sd.signer {
        Some(s) => {
            check_signer(blob, &sd.certs, s, sd.content.map(|c| slice(blob, c)), &mut r, &Budget::new());
        }
        None => r.add("Signature", None, "no SignerInfo found".into()),
    }
    r.write(&mut out, "");
    out.push_str(if r.passed() { "Result: valid\n" } else { "Result: NOT valid\n" });
    out
}
