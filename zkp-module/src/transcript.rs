//! Fiat-Shamir transcript for the PitCrypt-F1 combined proof.
//!
//! Wraps a Merlin transcript with fixed domain separation and typed
//! helper methods, so the prover (car producer node) and the verifier
//! (relay node / FIA validator) always derive the same non-interactive
//! challenge from the same sequence of public values.

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript as MerlinTranscript;

pub struct Transcript(MerlinTranscript);

impl Transcript {
    /// Start a fresh transcript for exactly one packet's proof.
    /// `context` should uniquely identify the packet - e.g.
    /// `car_id || packet_sequence_index` - so a proof can never be
    /// replayed against a different packet or a different car.
    pub fn new(context: &[u8]) -> Self {
        let mut t = MerlinTranscript::new(b"pitcrypt-f1-zkp-v1");
        t.append_message(b"context", context);
        Transcript(t)
    }

    pub fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.0.append_message(label, point.as_bytes());
    }

    pub fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.0.append_message(label, scalar.as_bytes());
    }

    /// Squeeze a Fiat-Shamir challenge scalar out of everything appended
    /// to the transcript so far.
    pub fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.0.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }
}