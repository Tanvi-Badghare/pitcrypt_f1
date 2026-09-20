//! Combined Sigma protocol proving, in one non-interactive proof:
//!
//! 1. **Integrity** - the prover knows the opening `(value, r_v)` of the
//!    packet's value commitment `C_v`.
//! 2. **Sequence correctness** - the prover knows the opening
//!    `(sequence, r_s)` of the sequence commitment `C_s`, *and*
//!    `sequence == prev_sequence + 1`, where `prev_sequence` is only
//!    known to the verifier through its own commitment `C_prev` (no
//!    sequence number is ever revealed in the clear). This is what
//!    catches dropped, replayed, or reordered packets at the ZK layer,
//!    on top of whatever plaintext sequence checking the pipeline
//!    already does.
//!
//! This is a standard AND-composition of three Schnorr-style Sigma
//! protocols, made non-interactive with one shared Fiat-Shamir challenge
//! over Ristretto255.

use crate::commitments::{Commitment, PedersenParams};
use crate::transcript::Transcript;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkpError {
    #[error("malformed proof: a curve point failed to decompress")]
    Decompress,
    #[error("proof verification failed")]
    VerificationFailed,
}

/// Everything the prover (car producer node) knows privately about one
/// telemetry packet.
#[derive(Clone, Copy, Debug)]
pub struct PacketWitness {
    pub value: Scalar,
    pub blinding_v: Scalar,
    pub sequence: Scalar,
    pub blinding_s: Scalar,
    /// Blinding factor used in the *previous* packet's sequence
    /// commitment. Needed to prove the sequence delta without either
    /// sequence number ever appearing in the clear.
    pub prev_blinding_s: Scalar,
}

/// Everything the verifier (relay node / FIA validator) sees publicly.
#[derive(Clone, Copy, Debug)]
pub struct PacketStatement {
    pub commitment_v: Commitment,
    pub commitment_s: Commitment,
    pub prev_commitment_s: Commitment,
}

/// The combined non-interactive proof shipped alongside each packet.
#[derive(Clone, Copy, Debug)]
pub struct CombinedProof {
    t_v: CompressedRistretto,
    z_v: Scalar,
    z_rv: Scalar,
    t_s: CompressedRistretto,
    z_s: Scalar,
    z_rs: Scalar,
    t_link: CompressedRistretto,
    z_delta: Scalar,
}

/// Produce a combined proof for one packet. `context` should uniquely
/// identify the packet (e.g. `car_id || sequence_index`) so the
/// Fiat-Shamir challenge - and therefore the proof itself - is bound to
/// exactly that packet and cannot be replayed elsewhere.
pub fn prove<R: RngCore + CryptoRng>(
    params: &PedersenParams,
    witness: &PacketWitness,
    statement: &PacketStatement,
    context: &[u8],
    rng: &mut R,
) -> CombinedProof {
    let g = params.g;
    let h = params.h;

    // Fresh random nonces for every Sigma-protocol leg.
    let k_v = Scalar::random(rng);
    let k_rv = Scalar::random(rng);
    let k_s = Scalar::random(rng);
    let k_rs = Scalar::random(rng);
    let k_delta = Scalar::random(rng);

    let t_v = (k_v * g + k_rv * h).compress();
    let t_s = (k_s * g + k_rs * h).compress();
    let t_link = (k_delta * h).compress();

    let mut transcript = Transcript::new(context);
    transcript.append_point(b"C_v", &statement.commitment_v.0);
    transcript.append_point(b"C_s", &statement.commitment_s.0);
    transcript.append_point(b"C_prev", &statement.prev_commitment_s.0);
    transcript.append_point(b"t_v", &t_v);
    transcript.append_point(b"t_s", &t_s);
    transcript.append_point(b"t_link", &t_link);
    let c = transcript.challenge_scalar(b"challenge");

    let z_v = k_v + c * witness.value;
    let z_rv = k_rv + c * witness.blinding_v;
    let z_s = k_s + c * witness.sequence;
    let z_rs = k_rs + c * witness.blinding_s;
    let delta_r = witness.blinding_s - witness.prev_blinding_s;
    let z_delta = k_delta + c * delta_r;

    CombinedProof {
        t_v,
        z_v,
        z_rv,
        t_s,
        z_s,
        z_rs,
        t_link,
        z_delta,
    }
}

/// Verify a combined proof against a public statement. Returns `Ok(())`
/// only if all three legs hold: value-commitment opening, sequence-
/// commitment opening, and sequence-delta-equals-one. Never touches
/// `value` or `sequence` in the clear - the FIA validator learns nothing
/// beyond "this packet is genuine and correctly ordered".
pub fn verify(
    params: &PedersenParams,
    statement: &PacketStatement,
    proof: &CombinedProof,
    context: &[u8],
) -> Result<(), ZkpError> {
    let g = params.g;
    let h = params.h;

    let c_v = statement.commitment_v.point().ok_or(ZkpError::Decompress)?;
    let c_s = statement.commitment_s.point().ok_or(ZkpError::Decompress)?;
    let c_prev = statement
        .prev_commitment_s
        .point()
        .ok_or(ZkpError::Decompress)?;
    let t_v = proof.t_v.decompress().ok_or(ZkpError::Decompress)?;
    let t_s = proof.t_s.decompress().ok_or(ZkpError::Decompress)?;
    let t_link = proof.t_link.decompress().ok_or(ZkpError::Decompress)?;

    let mut transcript = Transcript::new(context);
    transcript.append_point(b"C_v", &statement.commitment_v.0);
    transcript.append_point(b"C_s", &statement.commitment_s.0);
    transcript.append_point(b"C_prev", &statement.prev_commitment_s.0);
    transcript.append_point(b"t_v", &proof.t_v);
    transcript.append_point(b"t_s", &proof.t_s);
    transcript.append_point(b"t_link", &proof.t_link);
    let c = transcript.challenge_scalar(b"challenge");

    // Leg 1: knowledge of the opening of C_v (packet integrity).
    let lhs_v = t_v + c * c_v;
    let rhs_v = proof.z_v * g + proof.z_rv * h;
    if lhs_v != rhs_v {
        return Err(ZkpError::VerificationFailed);
    }

    // Leg 2: knowledge of the opening of C_s.
    let lhs_s = t_s + c * c_s;
    let rhs_s = proof.z_s * g + proof.z_rs * h;
    if lhs_s != rhs_s {
        return Err(ZkpError::VerificationFailed);
    }

    // Leg 3: C_s - C_prev - G = delta_r * H, i.e. sequence == prev + 1,
    // proved purely as a discrete-log-of-H statement so no sequence
    // number is ever revealed - this is what catches drops/replays/
    // reordering at the ZK layer.
    let target = c_s - c_prev - g;
    let lhs_link = t_link + c * target;
    let rhs_link = proof.z_delta * h;
    if lhs_link != rhs_link {
        return Err(ZkpError::VerificationFailed);
    }

    Ok(())
}