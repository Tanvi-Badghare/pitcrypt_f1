//! PitCrypt-F1 zero-knowledge proof module.
//!
//! Provides Pedersen commitments and a combined Sigma-protocol proof that
//! a telemetry packet's commitment opens correctly *and* that its
//! sequence number correctly follows the previous packet's sequence
//! number - both proved in a single non-interactive proof, without ever
//! revealing the underlying telemetry value or sequence number.
//!
//! This module sits inside the FIA-validator-facing leg of the pipeline:
//! car producer -> relay node -> FIA validator. The validator calls
//! `proof_system::verify` as one of its checks (alongside signature
//! verification and sequence checking done elsewhere in the pipeline) and
//! never needs to see raw telemetry values to do it.

pub mod commitments;
pub mod proof_system;
pub mod transcript;

pub use commitments::{commit, verify_open, Commitment, PedersenParams};
pub use proof_system::{prove, verify, CombinedProof, PacketStatement, PacketWitness, ZkpError};

/// Hash arbitrary telemetry payload bytes down to a curve scalar so it
/// can be committed to with a Pedersen commitment. Domain-separated so
/// this can never collide with scalars used elsewhere in the protocol.
pub fn hash_to_scalar(bytes: &[u8]) -> curve25519_dalek::scalar::Scalar {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(b"pitcrypt-f1-zkp-v1-scalar");
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&wide)
}