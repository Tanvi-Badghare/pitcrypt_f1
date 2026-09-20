//! Pedersen commitments over Ristretto255.
//!
//! `C = v*G + r*H`, where `G` is the standard Ristretto basepoint and `H`
//! is a second, independent generator derived by hashing a fixed label
//! to the curve (a "nothing-up-my-sleeve" construction). Because nobody
//! - including the car producer, the relay node, or the FIA validator -
//! knows `log_G(H)`, the commitment is both binding (can't be opened to
//! two different values) and hiding (reveals nothing about the value).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::Sha512;

/// Public parameters shared by every party in the pipeline (car producer,
/// relay node, FIA validator). Fixed and identical everywhere - there is
/// no trusted setup and no trapdoor.
#[derive(Clone, Copy, Debug)]
pub struct PedersenParams {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

impl PedersenParams {
    /// Deterministically derive the standard PitCrypt-F1 parameter set.
    pub fn new() -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = RistrettoPoint::hash_from_bytes::<Sha512>(b"pitcrypt-f1-zkp-v1-generator-H");
        PedersenParams { g, h }
    }
}

impl Default for PedersenParams {
    fn default() -> Self {
        Self::new()
    }
}

/// A Pedersen commitment `C = v*G + r*H`, stored in compressed
/// (32-byte) form so it is cheap to serialize onto the wire alongside
/// the rest of a telemetry packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(pub CompressedRistretto);

impl Commitment {
    pub fn point(&self) -> Option<RistrettoPoint> {
        self.0.decompress()
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Commitment(CompressedRistretto(*bytes))
    }
}

/// Commit to `value` with blinding factor `blinding`.
pub fn commit(params: &PedersenParams, value: Scalar, blinding: Scalar) -> Commitment {
    let point = value * params.g + blinding * params.h;
    Commitment(point.compress())
}

/// Check that `commitment` opens to `(value, blinding)`. This is only
/// used in tests/debugging - the whole point of `proof_system` is that
/// the FIA validator checks correctness *without* ever learning the
/// opening.
pub fn verify_open(
    params: &PedersenParams,
    commitment: &Commitment,
    value: Scalar,
    blinding: Scalar,
) -> bool {
    commit(params, value, blinding) == *commitment
}