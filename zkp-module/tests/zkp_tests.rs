//! Integration tests for the combined integrity + sequence proof.
//!
//! These mirror the adversarial scenarios PitCrypt-F1's dashboard injects
//! for demonstration: a tampered value, a dropped/replayed packet
//! (sequence gap), and a proof replayed against the wrong context.

use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use zkp_module::commitments::{commit, verify_open, PedersenParams};
use zkp_module::hash_to_scalar;
use zkp_module::proof_system::{prove, verify, PacketStatement, PacketWitness};

/// Build a witness + statement pair for a packet at `sequence`, chained
/// to a previous packet at `prev_sequence`.
fn setup_packet(
    params: &PedersenParams,
    value_bytes: &[u8],
    sequence: u64,
    prev_sequence: u64,
    rng: &mut OsRng,
) -> (PacketWitness, PacketStatement) {
    let value = hash_to_scalar(value_bytes);
    let blinding_v = Scalar::random(rng);
    let sequence_scalar = Scalar::from(sequence);
    let blinding_s = Scalar::random(rng);
    let prev_blinding_s = Scalar::random(rng);
    let prev_sequence_scalar = Scalar::from(prev_sequence);

    let commitment_v = commit(params, value, blinding_v);
    let commitment_s = commit(params, sequence_scalar, blinding_s);
    let prev_commitment_s = commit(params, prev_sequence_scalar, prev_blinding_s);

    let witness = PacketWitness {
        value,
        blinding_v,
        sequence: sequence_scalar,
        blinding_s,
        prev_blinding_s,
    };
    let statement = PacketStatement {
        commitment_v,
        commitment_s,
        prev_commitment_s,
    };
    (witness, statement)
}

#[test]
fn commitment_opens_correctly() {
    let params = PedersenParams::new();
    let mut rng = OsRng;
    let value = hash_to_scalar(b"speed=312.4kph");
    let blinding = Scalar::random(&mut rng);
    let c = commit(&params, value, blinding);

    assert!(verify_open(&params, &c, value, blinding));
    assert!(!verify_open(&params, &c, value, Scalar::random(&mut rng)));
}

#[test]
fn valid_packet_proof_verifies() {
    let params = PedersenParams::new();
    let mut rng = OsRng;
    let (witness, statement) = setup_packet(&params, b"packet-42-telemetry", 42, 41, &mut rng);

    let context = b"car:VER|seq:42";
    let proof = prove(&params, &witness, &statement, context, &mut rng);

    assert!(verify(&params, &statement, &proof, context).is_ok());
}

#[test]
fn tampered_value_commitment_is_rejected() {
    let params = PedersenParams::new();
    let mut rng = OsRng;
    let (witness, mut statement) =
        setup_packet(&params, b"packet-42-telemetry", 42, 41, &mut rng);

    let context = b"car:VER|seq:42";
    let proof = prove(&params, &witness, &statement, context, &mut rng);

    // Attacker swaps in a different value commitment after the proof was
    // generated (e.g. a relay node tampering with the telemetry value).
    let forged_value = hash_to_scalar(b"packet-42-telemetry-TAMPERED");
    statement.commitment_v = commit(&params, forged_value, witness.blinding_v);

    assert!(verify(&params, &statement, &proof, context).is_err());
}

#[test]
fn dropped_or_replayed_sequence_is_rejected() {
    let params = PedersenParams::new();
    let mut rng = OsRng;
    // Sequence jumps from 41 straight to 43 - a dropped or replayed packet
    // in between - so the delta-equals-one leg must fail.
    let (witness, statement) = setup_packet(&params, b"packet-43-telemetry", 43, 41, &mut rng);

    let context = b"car:VER|seq:43";
    let proof = prove(&params, &witness, &statement, context, &mut rng);

    assert!(verify(&params, &statement, &proof, context).is_err());
}

#[test]
fn proof_bound_to_wrong_context_is_rejected() {
    let params = PedersenParams::new();
    let mut rng = OsRng;
    let (witness, statement) = setup_packet(&params, b"packet-42-telemetry", 42, 41, &mut rng);

    let proof = prove(&params, &witness, &statement, b"car:VER|seq:42", &mut rng);

    // A different car/sequence context should never validate a proof
    // generated for another packet, even if the statement is otherwise
    // structurally identical.
    assert!(verify(&params, &statement, &proof, b"car:HAM|seq:42").is_err());
}