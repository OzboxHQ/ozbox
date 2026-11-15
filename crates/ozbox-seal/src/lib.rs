//! Sealed delivery (ADR 0029, Amendment 6 section 3 and Amendment 9).
//!
//! A payload that carries a value or a signature is sealed to a **service key**: an X25519 key made and held by the
//! secrets service. The scheme is HPKE (RFC 9180) in base mode, with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
//! ChaCha20-Poly1305, from the `hpke` crate. Nothing here is home-made cryptography: this module chooses the suite, binds
//! the request's own fields as authenticated data, and holds the key bytes safely.
//!
//! * The **info** string names the purpose and the box, so a message made for one box or one use cannot be opened as another.
//! * The **aad** is the request's fields in a fixed order (the caller builds it with [`aad`]); a relay that changes the
//!   operation, the project, the environment, the box or the key's fingerprint makes the opening fail.
//! * A service key's **fingerprint** is what a laptop pins. It is a SHA-256 over a label and the public key.
//!
//! No unsafe code, and no secret is printed, serialized or put in an error: errors name only what failed.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use zeroize::{Zeroize, Zeroizing};

type Kem = X25519HkdfSha256;

/// The length of an X25519 public or private key, and of the encapsulated key a message starts with.
pub const KEY_LEN: usize = 32;

/// The cipher suite, as a sentence, for a person who asks.
pub const SUITE: &str = "HPKE base mode, X25519 + HKDF-SHA256 + ChaCha20-Poly1305 (RFC 9180)";

/// Why a seal or an open did not happen. Never carries a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// A key was not 32 bytes, or not a valid X25519 key.
    BadKey,
    /// The system's random number generator did not answer.
    NoRandom,
    /// The message was changed, made for another key, another box or another use, or is not a sealed message.
    CannotOpen,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SealError::BadKey => "that key is not valid",
            SealError::NoRandom => "the system's random numbers are not available",
            SealError::CannotOpen => {
                "that sealed message cannot be opened: it was changed, or it was made for another key, box or use"
            }
        })
    }
}

impl std::error::Error for SealError {}

/// The operating system's random numbers, as the generator HPKE asks for.
struct SystemRandom;

impl rand_core::RngCore for SystemRandom {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // a machine whose random numbers fail must not go on with a weak key: stop the process, never a guess
        if getrandom::getrandom(dest).is_err() {
            std::process::abort();
        }
    }
}

impl rand_core::CryptoRng for SystemRandom {}

/// A service key: the private half stays in this value (zeroized when dropped) and is never printed.
pub struct ServiceKey {
    secret: Zeroizing<[u8; KEY_LEN]>,
    public: [u8; KEY_LEN],
}

impl ServiceKey {
    /// A new key from the system's random numbers.
    pub fn generate() -> Result<Self, SealError> {
        let mut seed = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::getrandom(seed.as_mut()).map_err(|_| SealError::NoRandom)?;
        Self::from_secret_bytes(&seed[..])
    }

    /// A key from its private half (as stored). The public half is derived.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, SealError> {
        let secret: [u8; KEY_LEN] = bytes.try_into().map_err(|_| SealError::BadKey)?;
        let sk =
            <Kem as hpke::Kem>::PrivateKey::from_bytes(&secret).map_err(|_| SealError::BadKey)?;
        let pk = <Kem as hpke::Kem>::sk_to_pk(&sk);
        let public: [u8; KEY_LEN] = pk
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| SealError::BadKey)?;
        Ok(ServiceKey {
            secret: Zeroizing::new(secret),
            public,
        })
    }

    /// The private half, to be stored encrypted. Handle it as a secret.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        self.secret.clone()
    }

    pub fn public(&self) -> [u8; KEY_LEN] {
        self.public
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }

    /// Open one sealed message. `info` and `aad` must be exactly what the sender used.
    pub fn open(
        &self,
        info: &[u8],
        aad: &[u8],
        enc: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(&self.secret[..])
            .map_err(|_| SealError::BadKey)?;
        let encapped =
            <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| SealError::CannotOpen)?;
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &encapped,
            info,
            ciphertext,
            aad,
        )
        .map(Zeroizing::new)
        .map_err(|_| SealError::CannotOpen)
    }
}

impl std::fmt::Debug for ServiceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // the private half is never printed
        write!(f, "ServiceKey({})", self.fingerprint())
    }
}

/// What a laptop pins: a short, stable name for a public key. 128 bits of a SHA-256, in groups of eight hex digits.
pub fn fingerprint(public: &[u8; KEY_LEN]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(b"ozbox-seal-key/1");
    ctx.update(public);
    let d = ctx.finish();
    let hex: String = d.as_ref()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    hex.as_bytes()
        .chunks(8)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Seal `plaintext` to a public key. Returns the encapsulated key (32 bytes) and the ciphertext.
pub fn seal(
    recipient: &[u8; KEY_LEN],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), SealError> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(recipient).map_err(|_| SealError::BadKey)?;
    let (encapped, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        aad,
        &mut SystemRandom,
    )
    .map_err(|_| SealError::BadKey)?;
    Ok((encapped.to_bytes().to_vec(), ct))
}

/// The authenticated data for a request: fixed, length-prefixed fields, so no two different lists of fields give the same
/// bytes (`["ab","c"]` is not `["a","bc"]`). Pure.
pub fn aad(fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"ozbox-aad/1");
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f.as_bytes());
    }
    out
}

/// The `info` string: the purpose and the box, so a message cannot be moved to another box or another use.
pub fn info(purpose: &str, box_id: &str) -> Vec<u8> {
    aad(&["ozbox-seal-info/1", purpose, box_id])
}

/// Overwrite a buffer the caller no longer needs.
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

/// Parse a public key from lowercase hex (64 characters).
pub fn public_from_hex(s: &str) -> Result<[u8; KEY_LEN], SealError> {
    if s.len() != KEY_LEN * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SealError::BadKey);
    }
    let mut out = [0u8; KEY_LEN];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| SealError::BadKey)?;
    }
    // a point that is not a valid public key is refused here, not on first use
    <Kem as hpke::Kem>::PublicKey::from_bytes(&out).map_err(|_| SealError::BadKey)?;
    Ok(out)
}

pub fn public_to_hex(p: &[u8; KEY_LEN]) -> String {
    p.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SENTINEL: &[u8] = b"SENTINEL-seal-0123456789abcdef";

    #[test]
    fn a_sealed_message_opens_for_the_key_it_was_made_for_with_the_same_info_and_aad() {
        let k = ServiceKey::generate().unwrap();
        let i = info("ingress", "dev-1");
        let a = aad(&["import", "app", "staging"]);
        let (enc, ct) = seal(&k.public(), &i, &a, SENTINEL).unwrap();
        assert_eq!(enc.len(), KEY_LEN);
        assert_eq!(&k.open(&i, &a, &enc, &ct).unwrap()[..], SENTINEL);
    }

    #[test]
    fn the_ciphertext_does_not_hold_the_plaintext_and_two_seals_differ() {
        let k = ServiceKey::generate().unwrap();
        let i = info("ingress", "dev-1");
        let a = aad(&["import"]);
        let (e1, c1) = seal(&k.public(), &i, &a, SENTINEL).unwrap();
        let (e2, c2) = seal(&k.public(), &i, &a, SENTINEL).unwrap();
        assert!(!c1.windows(SENTINEL.len()).any(|w| w == SENTINEL));
        assert_ne!(e1, e2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn a_changed_field_another_box_another_key_or_a_damaged_message_does_not_open() {
        let k = ServiceKey::generate().unwrap();
        let other = ServiceKey::generate().unwrap();
        let i = info("ingress", "dev-1");
        let a = aad(&["import", "app", "staging"]);
        let (enc, ct) = seal(&k.public(), &i, &a, SENTINEL).unwrap();
        // the project changed in transit
        let moved = aad(&["import", "other", "staging"]);
        assert_eq!(k.open(&i, &moved, &enc, &ct), Err(SealError::CannotOpen));
        // the same message offered to another box's service
        assert!(k.open(&info("ingress", "dev-2"), &a, &enc, &ct).is_err());
        // another key
        assert!(other.open(&i, &a, &enc, &ct).is_err());
        // a flipped bit, a short message, an empty one
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(k.open(&i, &a, &enc, &bad).is_err());
        assert!(k.open(&i, &a, &enc, &ct[..4]).is_err());
        assert!(k.open(&i, &a, &enc[..10], &ct).is_err());
        assert!(k.open(&i, &a, &[], &[]).is_err());
    }

    #[test]
    fn the_aad_cannot_be_made_ambiguous_by_moving_a_boundary() {
        assert_ne!(aad(&["ab", "c"]), aad(&["a", "bc"]));
        assert_ne!(aad(&["a"]), aad(&["a", ""]));
        assert_ne!(info("a", "bc"), info("ab", "c"));
    }

    #[test]
    fn a_key_survives_storage_and_its_fingerprint_is_stable_and_not_the_key() {
        let k = ServiceKey::generate().unwrap();
        let again = ServiceKey::from_secret_bytes(&k.secret_bytes()[..]).unwrap();
        assert_eq!(k.public(), again.public());
        assert_eq!(k.fingerprint(), again.fingerprint());
        let f = k.fingerprint();
        assert_eq!(f.len(), 32 + 3);
        assert!(f
            .split('-')
            .all(|g| g.len() == 8 && g.bytes().all(|b| b.is_ascii_hexdigit())));
        let other = ServiceKey::generate().unwrap();
        assert_ne!(k.fingerprint(), other.fingerprint());
        // the private half is not in the debug text
        let dbg = format!("{k:?}");
        assert!(!dbg.contains(&public_to_hex(&k.secret_bytes())));
    }

    #[test]
    fn keys_of_the_wrong_length_or_shape_are_refused() {
        assert_eq!(
            ServiceKey::from_secret_bytes(&[1u8; 31]).err(),
            Some(SealError::BadKey)
        );
        assert!(public_from_hex("zz").is_err());
        assert!(public_from_hex(&"g".repeat(64)).is_err());
        let k = ServiceKey::generate().unwrap();
        assert_eq!(
            public_from_hex(&public_to_hex(&k.public())).unwrap(),
            k.public()
        );
    }

    /// RFC 9180 appendix A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode. The library is
    /// checked against the standard's own published answer, so a changed dependency that broke interoperability fails here.
    #[test]
    fn the_suite_opens_the_published_rfc_9180_message() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
                .collect()
        }
        let sk_r = unhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let enc = unhex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let aad = unhex("436f756e742d30");
        let ct = unhex(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
        );
        let k = ServiceKey::from_secret_bytes(&sk_r).unwrap();
        assert_eq!(
            &k.open(&info, &aad, &enc, &ct).unwrap()[..],
            b"Beauty is truth, truth beauty"
        );
    }
}
