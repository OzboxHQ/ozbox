//! The people who may confirm a fleet change, as the owner's own computer signed them (ADR 0040 §2, ADR 0041 §3).
//!
//! A box's dashboard keeps a list of passkeys, and a compromised dashboard could add one. So the credential holder does not
//! trust that list. It trusts a **set the laptop signed**: each credential with its person, role and public key, bound to one
//! box and one store, with a version that only goes up. A passkey assertion over a fleet plan's challenge counts only when its
//! credential is in the latest set the holder accepted, the signature verifies with the key the set names, the assertion is for
//! the relying party the set records, user verification was done, and the person is an owner.
//!
//! The signature is an Ed25519 signature by the laptop's approval key over `"ozbox-fleet-approvers-v1\n" + <the set's JSON
//! text, exactly as sent>`. Nothing is re-serialized, so there is no second encoding to disagree about. The holder pins the
//! laptop's public key once (a key a compromised `main` cannot replace).
//!
//! Pure: no clock, no files, no network.

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use crate::approval::PasskeyEvidence;
use crate::approval_subject::from_hex;
use crate::approval_verify::{verify_webauthn_assertion, ExpectedRp};
use crate::roles::Role;

/// The domain tag of the signed bytes.
pub const APPROVERS_TAG: &str = "ozbox-fleet-approvers-v1";
/// A set larger than this is refused unread.
pub const MAX_SET_BYTES: usize = 64 * 1024;
const MAX_APPROVERS: usize = 64;
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

/// One passkey the owner allowed to confirm fleet changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approver {
    /// The credential id as the assertion carries it.
    pub credential_id: String,
    /// The person, as the dashboard names them (shown in the audit chain, never trusted for authority).
    pub person: String,
    pub role: Role,
    /// The credential's public key: an uncompressed P-256 point, in hex.
    pub public_key: String,
    /// The relying party the credential's assertions must be for.
    pub rp: ExpectedRp,
}

/// The set the laptop signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverSet {
    /// Goes up with every new set; the holder refuses a lower or equal one it already passed (a rollback to an older list).
    pub version: u64,
    pub box_id: String,
    pub store_id: String,
    pub issued_at_ms: u64,
    pub approvers: Vec<Approver>,
}

/// A set and the laptop's signature over its exact text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedApproverSet {
    /// The set's JSON, exactly the text that was signed.
    pub set: String,
    /// The Ed25519 signature, in hex.
    pub signature: String,
}

/// What the laptop signs: the tag, a newline and the set's text.
pub fn signed_bytes(set_json: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(APPROVERS_TAG.len() + 1 + set_json.len());
    v.extend_from_slice(APPROVERS_TAG.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(set_json.as_bytes());
    v
}

impl ApproverSet {
    /// The text to sign. The laptop calls this once and signs the result.
    pub fn to_text(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|_| "the approver set cannot be written".to_string())
    }
}

impl SignedApproverSet {
    /// Check the signature with the laptop's pinned public key (hex) and that the set is for this box and this store; return
    /// the set. The version rule (never backwards) is the caller's, because it needs what was accepted before.
    pub fn verify(
        &self,
        laptop_public_hex: &str,
        box_id: &str,
        store_id: &str,
    ) -> Result<ApproverSet, String> {
        if self.set.len() > MAX_SET_BYTES {
            return Err("that approver list is too large".into());
        }
        let public = from_hex(laptop_public_hex).ok_or("the pinned computer key is not valid")?;
        let sig = from_hex(&self.signature)
            .filter(|s| s.len() == 64)
            .ok_or("that approver list's signature is not valid")?;
        UnparsedPublicKey::new(&ED25519, &public)
            .verify(&signed_bytes(&self.set), &sig)
            .map_err(|_| "that approver list was not signed by your computer".to_string())?;
        let set: ApproverSet = serde_json::from_str(&self.set)
            .map_err(|_| "that approver list is not readable".to_string())?;
        if set.box_id != box_id || set.store_id != store_id {
            return Err("that approver list is for another box".into());
        }
        if set.approvers.len() > MAX_APPROVERS {
            return Err("that approver list names too many people".into());
        }
        Ok(set)
    }
}

/// A passkey confirmation the set stands behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmed {
    pub person: String,
    pub credential_id: String,
    /// The authenticator's signature counter, for the holder's never-backwards rule.
    pub counter: u32,
}

impl ApproverSet {
    /// Check one assertion over `challenge`. The credential must be in this set, an owner's, and the assertion must verify with
    /// the set's key for the set's relying party, with user presence and user verification.
    pub fn check_assertion(
        &self,
        challenge: &[u8; 32],
        e: &PasskeyEvidence,
    ) -> Result<Confirmed, String> {
        let a = self
            .approvers
            .iter()
            .find(|a| a.credential_id == e.credential_id)
            .ok_or("that passkey is not one your computer approved for fleet changes")?;
        if a.role != Role::Owner {
            return Err("only an owner's passkey confirms a fleet change".into());
        }
        let public = from_hex(&a.public_key).ok_or("that passkey's record is damaged")?;
        let ad = from_hex(&e.authenticator_data).ok_or("the assertion is incomplete")?;
        let client = from_hex(&e.client_data).ok_or("the assertion is incomplete")?;
        let sig = from_hex(&e.signature)
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or("the assertion is incomplete")?;
        let (flags, counter) =
            verify_webauthn_assertion(&public, &a.rp, challenge, &ad, &client, &sig)?;
        if flags & FLAG_UP == 0 {
            return Err("that assertion was made without a touch".into());
        }
        if flags & FLAG_UV == 0 {
            return Err(
                "a fleet change needs the passkey's own check (a PIN or a fingerprint)".into(),
            );
        }
        Ok(Confirmed {
            person: a.person.clone(),
            credential_id: a.credential_id.clone(),
            counter,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::approval::KeyType;
    use crate::approval_subject::to_hex;
    use crate::approval_verify::tests::{auth_data, client_data, test_rp, Signer};
    use ring::digest::{digest, SHA256};

    fn sign_set(s: &Signer, set: &ApproverSet) -> SignedApproverSet {
        let text = set.to_text().unwrap();
        SignedApproverSet {
            signature: to_hex(&s.sign(&signed_bytes(&text))),
            set: text,
        }
    }

    fn set_with(p: &Signer, role: Role) -> ApproverSet {
        ApproverSet {
            version: 3,
            box_id: "box-1".into(),
            store_id: "store-1".into(),
            issued_at_ms: 1,
            approvers: vec![Approver {
                credential_id: "cred-1".into(),
                person: "owner".into(),
                role,
                public_key: p.public_hex(),
                rp: test_rp(),
            }],
        }
    }

    fn assertion(
        p: &Signer,
        cred: &str,
        flags: u8,
        counter: u32,
        ch: &[u8; 32],
    ) -> PasskeyEvidence {
        let ad = auth_data(flags, counter);
        let cd = client_data(ch);
        let mut payload = ad.clone();
        payload.extend_from_slice(digest(&SHA256, &cd).as_ref());
        PasskeyEvidence {
            credential_id: cred.into(),
            authenticator_data: to_hex(&ad),
            client_data: to_hex(&cd),
            signature: to_hex(&p.sign(&payload)),
        }
    }

    #[test]
    fn only_a_set_the_pinned_computer_key_signed_for_this_box_is_read() {
        let laptop = Signer::new(KeyType::Ed25519);
        let pass = Signer::new(KeyType::WebauthnP256);
        let signed = sign_set(&laptop, &set_with(&pass, Role::Owner));
        assert_eq!(
            signed
                .verify(&laptop.public_hex(), "box-1", "store-1")
                .unwrap()
                .version,
            3
        );
        // another key signed it (a compromised dashboard's own key)
        let mallory = Signer::new(KeyType::Ed25519);
        let forged = sign_set(&mallory, &set_with(&pass, Role::Owner));
        assert!(forged
            .verify(&laptop.public_hex(), "box-1", "store-1")
            .is_err());
        // another box or store
        assert!(signed
            .verify(&laptop.public_hex(), "box-2", "store-1")
            .is_err());
        assert!(signed
            .verify(&laptop.public_hex(), "box-1", "store-2")
            .is_err());
        // the text was changed after it was signed (a passkey added)
        let mut tampered = signed.clone();
        tampered.set = tampered.set.replace("\"version\":3", "\"version\":4");
        assert!(tampered
            .verify(&laptop.public_hex(), "box-1", "store-1")
            .is_err());
        // a signature over the same text without the domain tag does not count
        let text = set_with(&pass, Role::Owner).to_text().unwrap();
        let bare = SignedApproverSet {
            signature: to_hex(&laptop.sign(text.as_bytes())),
            set: text,
        };
        assert!(bare
            .verify(&laptop.public_hex(), "box-1", "store-1")
            .is_err());
        // garbage and oversize
        assert!(SignedApproverSet {
            set: "x".into(),
            signature: "zz".into()
        }
        .verify(&laptop.public_hex(), "box-1", "store-1")
        .is_err());
        let big = SignedApproverSet {
            set: "a".repeat(MAX_SET_BYTES + 1),
            signature: signed.signature.clone(),
        };
        assert!(big
            .verify(&laptop.public_hex(), "box-1", "store-1")
            .is_err());
    }

    #[test]
    fn an_owners_listed_passkey_over_the_challenge_with_a_check_is_confirmed() {
        let pass = Signer::new(KeyType::WebauthnP256);
        let set = set_with(&pass, Role::Owner);
        let ch = [7u8; 32];
        let ok = set
            .check_assertion(&ch, &assertion(&pass, "cred-1", FLAG_UP | FLAG_UV, 9, &ch))
            .unwrap();
        assert_eq!((ok.person.as_str(), ok.counter), ("owner", 9));
        // another plan's challenge
        assert!(set
            .check_assertion(
                &[8u8; 32],
                &assertion(&pass, "cred-1", FLAG_UP | FLAG_UV, 9, &ch)
            )
            .is_err());
        // a credential the set does not list, even with a valid signature of its own key
        let rogue = Signer::new(KeyType::WebauthnP256);
        assert!(set
            .check_assertion(&ch, &assertion(&rogue, "cred-2", FLAG_UP | FLAG_UV, 1, &ch))
            .is_err());
        // the listed credential id with another key's signature
        assert!(set
            .check_assertion(&ch, &assertion(&rogue, "cred-1", FLAG_UP | FLAG_UV, 1, &ch))
            .is_err());
        // no check by the authenticator, no touch
        assert!(set
            .check_assertion(&ch, &assertion(&pass, "cred-1", FLAG_UP, 9, &ch))
            .unwrap_err()
            .contains("own check"));
        assert!(set
            .check_assertion(&ch, &assertion(&pass, "cred-1", FLAG_UV, 9, &ch))
            .is_err());
    }

    #[test]
    fn a_member_in_the_set_does_not_confirm_a_fleet_change() {
        let pass = Signer::new(KeyType::WebauthnP256);
        let set = set_with(&pass, Role::Member);
        let ch = [7u8; 32];
        assert!(set
            .check_assertion(&ch, &assertion(&pass, "cred-1", FLAG_UP | FLAG_UV, 9, &ch))
            .unwrap_err()
            .contains("owner"));
    }
}
