//! RavenIntroductionV1 — recipient-specific encrypted social introductions.
//!
//! Outer fields are metadata for local routing; sensitive note stays sealed.

use crate::atsam_aead::{seal_rvna1_v2, unseal_rvna1_v2};
use crate::canon::{lp, u64_be};
use crate::identity::Identity;

pub const INTRO_DOMAIN: &[u8] = b"rvn1/intro";
/// Maximum signed lifetime (`expires_at - created_at`), matching contact
/// requests. Bounds how long a held introduction (and the inbox slot it
/// occupies) can live; without it an `expires_at` near `u64::MAX` never expires.
pub const INTRO_MAX_LIFETIME_MS: u64 = 30 * 24 * 3_600_000; // 30 days
/// Social-introduction notes require an authenticated ATSAM session root.
/// Public identity material must never be treated as an encryption secret.
pub const INTRO_SESSION_REQUIRED: &str =
    "INTRO_SESSION_REQUIRED: authenticated ATSAM root required";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RavenIntroductionV1 {
    pub intro_id: [u8; 16],
    pub introducer_raven_id: String,
    pub subject_raven_id: String,
    pub recipient_raven_id: String,
    pub subject_display_name: String,
    pub subject_aliases: Vec<String>,
    pub created_at: u64,
    pub expires_at: u64,
    /// E2EE note ciphertext (opaque to relays).
    pub note_ciphertext: Vec<u8>,
    pub signature: [u8; 64],
    pub introducer_pub: [u8; 32],
}

impl RavenIntroductionV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = INTRO_DOMAIN.to_vec();
        out.extend_from_slice(&self.intro_id);
        out.extend(lp(self.introducer_raven_id.as_bytes())?);
        out.extend(lp(self.subject_raven_id.as_bytes())?);
        out.extend(lp(self.recipient_raven_id.as_bytes())?);
        out.extend(lp(self.subject_display_name.as_bytes())?);
        let alias_count = u16::try_from(self.subject_aliases.len())
            .map_err(|_| "too many introduction aliases".to_string())?;
        out.extend_from_slice(&alias_count.to_be_bytes());
        for a in &self.subject_aliases {
            out.extend(lp(a.as_bytes())?);
        }
        out.extend_from_slice(&u64_be(self.created_at));
        out.extend_from_slice(&u64_be(self.expires_at));
        out.extend(lp(&self.note_ciphertext)?);
        Ok(out)
    }

    pub fn sign(mut self, introducer: &Identity) -> Result<Self, String> {
        self.introducer_pub = introducer.public_key_bytes();
        self.introducer_raven_id = introducer.address();
        let sb = self.signing_bytes()?;
        self.signature = introducer.sign(&sb);
        Ok(self)
    }

    pub fn verify(&self, now_ms: u64) -> Result<(), String> {
        if now_ms > self.expires_at {
            return Err("INTRO_EXPIRED".into());
        }
        if self.expires_at <= self.created_at
            || crate::address::encode_address(&self.introducer_pub) != self.introducer_raven_id
        {
            return Err("INTRO_IDENTITY_OR_TIME_MISMATCH".into());
        }
        if self.expires_at.saturating_sub(self.created_at) > INTRO_MAX_LIFETIME_MS {
            return Err("INTRO_LIFETIME_TOO_LONG".into());
        }
        let sb = self.signing_bytes()?;
        if !Identity::verify(&self.introducer_pub, &sb, &self.signature) {
            return Err("INTRO_BAD_SIG".into());
        }
        Ok(())
    }

    /// Rootless compatibility entry point. Always fails closed, including
    /// debug and lab-feature builds; use `seal_note_with_atsam_root`.
    pub fn seal_note(
        introducer: &Identity,
        recipient_pub: &[u8; 32],
        recipient_addr: &str,
        plaintext_note: &[u8],
        intro_id: &[u8; 16],
    ) -> Result<Vec<u8>, String> {
        let _ = (
            introducer,
            recipient_pub,
            recipient_addr,
            plaintext_note,
            intro_id,
        );
        Err(INTRO_SESSION_REQUIRED.into())
    }

    /// Seal a note under an authenticated ATSAM session root. The caller must
    /// allocate the chain index and nonce exactly once and persist that state.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_note_with_atsam_root(
        introducer: &Identity,
        recipient_pub: &[u8; 32],
        recipient_addr: &str,
        plaintext_note: &[u8],
        intro_id: &[u8; 16],
        root: &[u8; 32],
        chain_index: u32,
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, String> {
        if crate::address::encode_address(recipient_pub) != recipient_addr {
            return Err("INTRO_RECIPIENT_KEY_MISMATCH".into());
        }
        seal_rvna1_v2(
            root,
            &introducer.address(),
            recipient_addr,
            &hex::encode(intro_id),
            chain_index,
            plaintext_note,
            nonce,
        )
    }

    pub fn open_note(
        &self,
        recipient: &Identity,
        introducer_pub: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let _ = (recipient, introducer_pub);
        Err(INTRO_SESSION_REQUIRED.into())
    }

    pub fn open_note_with_atsam_root(
        &self,
        recipient: &Identity,
        introducer_pub: &[u8; 32],
        root: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        if self.introducer_pub != *introducer_pub
            || self.recipient_raven_id != recipient.address()
            || self.introducer_raven_id != crate::address::encode_address(introducer_pub)
        {
            return Err("INTRO_IDENTITY_MISMATCH".into());
        }
        unseal_rvna1_v2(
            root,
            &self.note_ciphertext,
            &self.introducer_raven_id,
            &self.recipient_raven_id,
            &hex::encode(self.intro_id),
        )
    }
}

/// Upper bound on held introductions; admission fails closed when full.
pub const INTRO_INBOX_MAX: usize = 256;

#[derive(Default)]
pub struct IntroductionInbox {
    /// Recipient-local encrypted intros, unique per `(introducer, intro_id)`.
    pub items: Vec<RavenIntroductionV1>,
}

impl IntroductionInbox {
    /// Admit an introduction for the local user.
    ///
    /// Beyond the introducer's own signature/address/expiry checks, the
    /// intro must be addressed to `local_raven_id` (an intro captured from
    /// someone else's inbox is not replayable here) and signed by one of
    /// `trusted_introducers` — the Raven IDs of existing, non-blocked
    /// contacts. Results from this inbox are labelled `INTRODUCED`, so a
    /// stranger's self-signed "@alias → attacker" mapping must never enter.
    pub fn add<S: AsRef<str>>(
        &mut self,
        intro: RavenIntroductionV1,
        local_raven_id: &str,
        trusted_introducers: &[S],
        now_ms: u64,
    ) -> Result<(), String> {
        intro.verify(now_ms)?;
        if intro.recipient_raven_id != local_raven_id {
            return Err("INTRO_WRONG_RECIPIENT".into());
        }
        if !trusted_introducers
            .iter()
            .any(|t| t.as_ref() == intro.introducer_raven_id)
        {
            return Err("INTRO_UNTRUSTED_INTRODUCER".into());
        }
        if self.items.iter().any(|i| {
            i.introducer_raven_id == intro.introducer_raven_id && i.intro_id == intro.intro_id
        }) {
            return Ok(()); // dedup (per introducer: another signer can't shadow it)
        }
        self.items.retain(|i| now_ms <= i.expires_at);
        if self.items.len() >= INTRO_INBOX_MAX {
            return Err("INTRO_INBOX_FULL".into());
        }
        self.items.push(intro);
        Ok(())
    }

    /// Drop every held introduction from `introducer_raven_id` (call when that
    /// contact is blocked or removed, so its intros stop occupying slots).
    /// Returns how many were removed. The comparison is case-insensitive.
    pub fn purge_introducer(&mut self, introducer_raven_id: &str) -> usize {
        let before = self.items.len();
        self.items.retain(|i| {
            !i.introducer_raven_id
                .eq_ignore_ascii_case(introducer_raven_id)
        });
        before - self.items.len()
    }

    pub fn for_subject_alias(&self, alias: &str, now_ms: u64) -> Vec<&RavenIntroductionV1> {
        let want = alias.trim().trim_start_matches('@').to_lowercase();
        self.items
            .iter()
            .filter(|i| {
                i.verify(now_ms).is_ok()
                    && i.subject_aliases
                        .iter()
                        .any(|a| a.trim().trim_start_matches('@').eq_ignore_ascii_case(&want))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000_000;

    fn intro(
        introducer: &Identity,
        recipient: &str,
        intro_id: [u8; 16],
        subject: &str,
    ) -> RavenIntroductionV1 {
        RavenIntroductionV1 {
            intro_id,
            introducer_raven_id: String::new(),
            subject_raven_id: subject.into(),
            recipient_raven_id: recipient.into(),
            subject_display_name: "Bob".into(),
            subject_aliases: vec!["bob".into()],
            created_at: T0,
            expires_at: T0 + 60_000,
            note_ciphertext: vec![1],
            signature: [0u8; 64],
            introducer_pub: [0u8; 32],
        }
        .sign(introducer)
        .unwrap()
    }

    #[test]
    fn stranger_intro_is_not_admitted() {
        let me = Identity::from_seed(&[0x01; 32]);
        let friend = Identity::from_seed(&[0x02; 32]);
        let stranger = Identity::from_seed(&[0x03; 32]);
        let attacker_subject = Identity::from_seed(&[0x04; 32]).address();
        let mut inbox = IntroductionInbox::default();
        let err = inbox
            .add(
                intro(&stranger, &me.address(), [1; 16], &attacker_subject),
                &me.address(),
                &[friend.address()],
                T0,
            )
            .unwrap_err();
        assert_eq!(err, "INTRO_UNTRUSTED_INTRODUCER");
        assert!(inbox.for_subject_alias("@bob", T0).is_empty());
    }

    #[test]
    fn intro_for_another_recipient_is_not_admitted() {
        let me = Identity::from_seed(&[0x05; 32]);
        let someone_else = Identity::from_seed(&[0x06; 32]);
        let friend = Identity::from_seed(&[0x07; 32]);
        let subject = Identity::from_seed(&[0x08; 32]).address();
        let mut inbox = IntroductionInbox::default();
        let err = inbox
            .add(
                intro(&friend, &someone_else.address(), [1; 16], &subject),
                &me.address(),
                &[friend.address()],
                T0,
            )
            .unwrap_err();
        assert_eq!(err, "INTRO_WRONG_RECIPIENT");
    }

    #[test]
    fn intro_id_collision_does_not_shadow_other_introducer() {
        let me = Identity::from_seed(&[0x09; 32]);
        let friend_a = Identity::from_seed(&[0x0A; 32]);
        let friend_b = Identity::from_seed(&[0x0B; 32]);
        let subject = Identity::from_seed(&[0x0C; 32]).address();
        let trusted = [friend_a.address(), friend_b.address()];
        let mut inbox = IntroductionInbox::default();
        inbox
            .add(
                intro(&friend_a, &me.address(), [7; 16], &subject),
                &me.address(),
                &trusted,
                T0,
            )
            .unwrap();
        inbox
            .add(
                intro(&friend_b, &me.address(), [7; 16], &subject),
                &me.address(),
                &trusted,
                T0,
            )
            .unwrap();
        // Same introducer + id is an idempotent re-delivery.
        inbox
            .add(
                intro(&friend_a, &me.address(), [7; 16], &subject),
                &me.address(),
                &trusted,
                T0,
            )
            .unwrap();
        assert_eq!(inbox.items.len(), 2);
        assert_eq!(inbox.for_subject_alias("@bob", T0).len(), 2);
    }

    #[test]
    fn far_future_expiry_is_refused_and_does_not_pin_inbox_slots() {
        let me = Identity::from_seed(&[0x0E; 32]);
        let friend = Identity::from_seed(&[0x0F; 32]);
        let subject = Identity::from_seed(&[0x10; 32]).address();
        let mut forever = intro(&friend, &me.address(), [1; 16], &subject);
        forever.expires_at = u64::MAX;
        let forever = forever.sign(&friend).unwrap();
        assert_eq!(forever.verify(T0).unwrap_err(), "INTRO_LIFETIME_TOO_LONG");
        let mut inbox = IntroductionInbox::default();
        assert_eq!(
            inbox
                .add(forever, &me.address(), &[friend.address()], T0)
                .unwrap_err(),
            "INTRO_LIFETIME_TOO_LONG"
        );
        // The cap itself is inclusive.
        let mut at_cap = intro(&friend, &me.address(), [2; 16], &subject);
        at_cap.expires_at = at_cap.created_at + INTRO_MAX_LIFETIME_MS;
        let at_cap = at_cap.sign(&friend).unwrap();
        inbox
            .add(at_cap.clone(), &me.address(), &[friend.address()], T0)
            .unwrap();
        let mut over = at_cap;
        over.expires_at += 1;
        let over = over.sign(&friend).unwrap();
        assert_eq!(over.verify(T0).unwrap_err(), "INTRO_LIFETIME_TOO_LONG");
    }

    #[test]
    fn purge_introducer_frees_that_introducers_slots_only() {
        let me = Identity::from_seed(&[0x11; 32]);
        let spammy = Identity::from_seed(&[0x12; 32]);
        let other = Identity::from_seed(&[0x13; 32]);
        let subject = Identity::from_seed(&[0x14; 32]).address();
        let trusted = [spammy.address(), other.address()];
        let mut inbox = IntroductionInbox::default();
        for n in 0..INTRO_INBOX_MAX {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(n as u64).to_be_bytes());
            inbox
                .add(
                    intro(&spammy, &me.address(), id, &subject),
                    &me.address(),
                    &trusted,
                    T0,
                )
                .unwrap();
        }
        let blocked_out = intro(&other, &me.address(), [0xEE; 16], &subject);
        assert_eq!(
            inbox
                .add(blocked_out.clone(), &me.address(), &trusted, T0)
                .unwrap_err(),
            "INTRO_INBOX_FULL"
        );
        assert_eq!(
            inbox.purge_introducer(&spammy.address().to_uppercase()),
            INTRO_INBOX_MAX
        );
        assert!(inbox.items.is_empty());
        inbox.add(blocked_out, &me.address(), &trusted, T0).unwrap();
        assert_eq!(inbox.purge_introducer(&spammy.address()), 0);
        assert_eq!(inbox.items.len(), 1);
    }

    #[test]
    fn oversized_alias_count_fails_closed() {
        let friend = Identity::from_seed(&[0x0D; 32]);
        let mut rec = intro(&friend, "rvn1me", [1; 16], "rvn1subject");
        rec.subject_aliases = vec![String::new(); usize::from(u16::MAX) + 1];
        assert!(rec.signing_bytes().is_err());
    }
}
