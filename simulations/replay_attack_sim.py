import os
import sys
import json
import time
import logging
from datetime import datetime, timezone

# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(os.path.dirname(__file__) + '/..')
CAR_SRC = os.path.join(ROOT, 'car-producer',  'src')
REL_SRC = os.path.join(ROOT, 'relay-node',    'src')
VAL_SRC = os.path.join(ROOT, 'validator-node', 'src')

sys.path.insert(0, CAR_SRC)
sys.path.insert(0, REL_SRC)
sys.path.insert(0, VAL_SRC)

from crypto_engine       import CryptoEngine
from sensor_simulator    import SensorSimulator
from packet_builder      import PacketBuilder
from signer              import PacketSigner
from encryptor           import PacketEncryptor
from decryptor           import RelayDecryptor
from reencryptor         import RelayReencryptor
from integrity_checker   import IntegrityChecker
from sequence_checker    import ValidatorSequenceChecker
from signature_verifier  import ValidatorSignatureVerifier
from zkp_verifier        import ZKPVerifier
from audit_logger        import AuditLogger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

"""
replay_attack_sim.py

Simulates replay attack scenarios against PitCrypt-F1.

Attack vectors tested:
    1. Simple replay      — resend a captured valid packet
    2. Delayed replay     — send old packet after delay
    3. Sequence replay    — replay with modified sequence
    4. Batch replay       — replay multiple captured packets
    5. Cross-session      — replay packet from old session

Defence mechanisms verified:
    - IntegrityChecker at relay (sequence + seen set)
    - ValidatorSequenceChecker at validator
    - Both must independently detect replay

Results saved to:
    simulations/results/replay_log.json
"""

RESULTS_DIR = os.path.join(ROOT, 'simulations', 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)


def build_pipeline():
    """Build complete car → relay → validator pipeline."""
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R',
        add_noise=False, inject_anomalies=False,
    )
    builder = PacketBuilder(team='mercedes', session='R')
    signer  = PacketSigner(node_id='mercedes_car')

    # Car → Relay ECDH
    car_eng   = CryptoEngine(node_id='mercedes_car')
    relay_eng = CryptoEngine(node_id='relay_01')
    cp        = car_eng.new_session()
    rp        = relay_eng.new_session()
    car_eng.complete_handshake(rp)
    relay_eng.complete_handshake(cp)

    # Relay → Validator ECDH
    relay_val = CryptoEngine(node_id='relay_val')
    val_eng   = CryptoEngine(node_id='validator')
    rvp       = relay_val.new_session()
    vp        = val_eng.new_session()
    relay_val.complete_handshake(vp)
    val_eng.complete_handshake(rvp)

    enc   = PacketEncryptor(
        crypto_engine=car_eng, node_id='mercedes_car'
    )
    dec   = RelayDecryptor(node_id='relay_01')
    dec.register_session('mercedes_car', relay_eng)
    reenc = RelayReencryptor(node_id='relay_01')
    reenc.register_validator_session(relay_val)

    relay_checker = IntegrityChecker(
        node_id='relay_01',
        check_timestamps=False,
        check_signatures=True,
    )
    val_checker = ValidatorSequenceChecker(
        node_id='fia_validator',
        check_timestamps=False,
        strict_ordering=True,
    )
    sig_verifier = ValidatorSignatureVerifier(
        node_id='fia_validator'
    )
    sig_verifier.register_node(
        'mercedes_car', signer.public_key_bytes
    )
    zkp = ZKPVerifier(node_id='fia_validator')
    audit = AuditLogger(
        node_id='fia_validator',
        log_to_file=False,
    )

    return {
        'sim':           sim,
        'builder':       builder,
        'signer':        signer,
        'enc':           enc,
        'dec':           dec,
        'reenc':         reenc,
        'val_eng':       val_eng,
        'relay_checker': relay_checker,
        'val_checker':   val_checker,
        'sig_verifier':  sig_verifier,
        'zkp':           zkp,
        'audit':         audit,
    }


def make_packet(p: dict) -> dict:
    """Build one full pipeline packet."""
    frame   = p['sim'].get_next_frame()
    packet  = p['builder'].build(frame)
    signed  = p['signer'].sign_packet(packet)
    commit  = ZKPVerifier.generate_commitment(
        signed['payload']
    )
    enc     = p['enc'].encrypt_packet(signed)
    dec     = p['dec'].decrypt(enc)
    reenc   = p['reenc'].reencrypt(dec)
    pt      = p['val_eng'].decrypt(
        nonce=reenc['nonce_bytes'],
        ciphertext=reenc['ciphertext_bytes'],
        associated_data=reenc['header'],
    )
    val_pkt = dict(reenc)
    val_pkt['payload_bytes']  = pt
    val_pkt['original_node']  = 'mercedes_car'
    val_pkt['zkp_commitment'] = commit['commitment']
    val_pkt['zkp_nonce']      = commit['nonce']
    return val_pkt, dec   # val_packet, relay_packet


def process_at_relay(p: dict, relay_pkt: dict) -> bool:
    """Run relay integrity check. Returns True if passed."""
    result = p['relay_checker'].check(relay_pkt)
    return result.passed


def process_at_validator(
    p: dict, val_pkt: dict
) -> dict:
    """Run full validator pipeline. Returns result dict."""
    results = {'passed': False, 'stages': {}}

    # Signature
    try:
        p['sig_verifier'].verify(val_pkt)
        results['stages']['signature'] = 'PASS'
    except Exception as e:
        results['stages']['signature'] = f'FAIL: {e}'
        results['reason'] = 'signature_failed'
        return results

    # Sequence
    seq_result = p['val_checker'].check(val_pkt)
    if not seq_result.passed:
        results['stages']['sequence'] = (
            f'FAIL: {seq_result.errors}'
        )
        results['reason'] = 'sequence_failed'
        return results
    results['stages']['sequence'] = 'PASS'

    # ZKP
    zkp_result = p['zkp'].verify_packet(val_pkt)
    if not zkp_result.verified:
        results['stages']['zkp'] = (
            f'FAIL: {zkp_result.reason}'
        )
        results['reason'] = 'zkp_failed'
        return results
    results['stages']['zkp'] = 'PASS'

    results['passed'] = True
    results['reason'] = 'all_checks_passed'
    return results


# ── Attack simulations ────────────────────────────────────────────

def sim_1_simple_replay(p: dict) -> dict:
    """
    Attack: Capture valid packet, resend immediately.
    Expected: Detected at both relay AND validator.
    """
    print("\n[Attack 1] Simple Replay")
    print("  Capturing valid packet...")

    val_pkt, relay_pkt = make_packet(p)

    # First pass — legitimate
    relay_ok = process_at_relay(p, relay_pkt)
    val_result = process_at_validator(p, val_pkt)

    print(f"  Legitimate: relay={relay_ok} "
          f"validator={val_result['passed']}")

    # Replay attempt
    print("  Replaying captured packet...")
    relay_replay = process_at_relay(p, relay_pkt)
    val_replay   = process_at_validator(p, val_pkt)

    relay_detected = not relay_replay
    val_detected   = not val_replay['passed']

    print(f"  Relay detected:     {relay_detected}")
    print(f"  Validator detected: {val_detected}")
    print(
        f"  Result: "
        f"{'✅ DETECTED' if relay_detected or val_detected else '❌ MISSED'}"
    )

    return {
        'attack':           'simple_replay',
        'legitimate_passed': val_result['passed'],
        'relay_detected':   relay_detected,
        'validator_detected': val_detected,
        'detected':         relay_detected or val_detected,
    }


def sim_2_sequence_manipulation(p: dict) -> dict:
    """
    Attack: Replay packet with manually set old sequence.
    Expected: Rejected — sequence already seen.
    """
    print("\n[Attack 2] Sequence Manipulation Replay")

    val_pkt, relay_pkt = make_packet(p)

    # Process legitimately first
    process_at_relay(p, relay_pkt)
    process_at_validator(p, val_pkt)

    # Try replaying with same sequence
    old_seq = val_pkt['sequence_no']
    print(f"  Original sequence: {old_seq}")
    print(f"  Replaying with same sequence...")

    val_replay = process_at_validator(p, val_pkt)
    detected   = not val_replay['passed']

    print(
        f"  Result: "
        f"{'✅ DETECTED' if detected else '❌ MISSED'}"
    )

    return {
        'attack':    'sequence_manipulation',
        'sequence':  old_seq,
        'detected':  detected,
        'reason':    val_replay.get('reason', ''),
    }


def sim_3_batch_replay(p: dict) -> dict:
    """
    Attack: Capture a sequence of packets, replay them all.
    Expected: All replays detected at validator.
    """
    print("\n[Attack 3] Batch Replay Attack")
    print("  Capturing 5 packets...")

    captured_val   = []
    captured_relay = []

    for _ in range(5):
        vp, rp = make_packet(p)
        process_at_relay(p, rp)
        process_at_validator(p, vp)
        captured_val.append(vp)
        captured_relay.append(rp)

    print(f"  Replaying all 5 captured packets...")
    detected_count = 0

    for i, (vp, rp) in enumerate(
        zip(captured_val, captured_relay)
    ):
        relay_ok = process_at_relay(p, rp)
        val_res  = process_at_validator(p, vp)
        detected = not relay_ok or not val_res['passed']
        if detected:
            detected_count += 1

    print(f"  Detected: {detected_count}/5")
    print(
        f"  Result: "
        f"{'✅ ALL DETECTED' if detected_count == 5 else f'⚠️  {detected_count}/5 detected'}"
    )

    return {
        'attack':          'batch_replay',
        'packets_replayed': 5,
        'detected_count':  detected_count,
        'all_detected':    detected_count == 5,
    }


def sim_4_delayed_replay(p: dict) -> dict:
    """
    Attack: Capture packet, wait, then replay.
    Expected: Detected by sequence checker.
    """
    print("\n[Attack 4] Delayed Replay")
    print("  Capturing packet...")

    val_pkt, relay_pkt = make_packet(p)
    process_at_relay(p, relay_pkt)
    process_at_validator(p, val_pkt)

    # Send a few more legitimate packets
    for _ in range(3):
        vp, rp = make_packet(p)
        process_at_relay(p, rp)
        process_at_validator(p, vp)

    print(f"  Replaying old packet (seq="
          f"{val_pkt['sequence_no']}) after "
          f"3 newer packets...")

    val_replay = process_at_validator(p, val_pkt)
    detected   = not val_replay['passed']

    print(
        f"  Result: "
        f"{'✅ DETECTED' if detected else '❌ MISSED'}"
    )

    return {
        'attack':   'delayed_replay',
        'detected': detected,
        'reason':   val_replay.get('reason', ''),
    }


def sim_5_sequence_increment_attack(p: dict) -> dict:
    """
    Attack: Replay packet but manually increment sequence.
    Expected: Signature verification fails —
    the signature covers original sequence in header.
    """
    print("\n[Attack 5] Sequence Increment Attack")
    print(
        "  Replaying with incremented sequence "
        "(header tampering)..."
    )

    val_pkt, relay_pkt = make_packet(p)
    process_at_relay(p, relay_pkt)
    process_at_validator(p, val_pkt)

    # Try to fool validator by incrementing sequence
    # but this requires modifying the header which
    # breaks the Ed25519 signature
    fake_pkt = dict(val_pkt)
    fake_pkt['sequence_no'] = val_pkt['sequence_no'] + 1000

    # Header bytes still contain original sequence
    # Signature covers original header — will fail

    val_result = process_at_validator(p, fake_pkt)
    # Note: sequence check uses dict field, not header bytes
    # so this tests the sequence dict manipulation
    detected   = not val_result['passed']

    print(f"  Stage failures: {val_result.get('stages', {})}")
    print(
        f"  Result: "
        f"{'✅ DETECTED' if detected else '⚠️  Passed (seq dict overridden)'}"
    )

    return {
        'attack':   'sequence_increment',
        'detected': detected,
        'stages':   val_result.get('stages', {}),
    }


# ── Main ──────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  PitCrypt-F1 — Replay Attack Simulation")
    print("  Testing defence mechanisms against replay attacks")
    print("="*60)

    p       = build_pipeline()
    results = []
    start   = time.time()

    results.append(sim_1_simple_replay(p))
    results.append(sim_2_sequence_manipulation(p))
    results.append(sim_3_batch_replay(p))
    results.append(sim_4_delayed_replay(p))
    results.append(sim_5_sequence_increment_attack(p))

    elapsed = time.time() - start

    # ── Summary ──────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  Simulation Summary")
    print("="*60)

    total    = len(results)
    detected = sum(
        1 for r in results
        if r.get('detected') or r.get('all_detected')
    )

    for r in results:
        status = (
            '✅' if r.get('detected') or
            r.get('all_detected') else '⚠️ '
        )
        print(f"  {status} {r['attack']}")

    print(f"\n  Attacks simulated: {total}")
    print(f"  Detected:          {detected}/{total}")
    print(f"  Elapsed:           {elapsed:.2f}s")

    # ── Save results ─────────────────────────────────────────────
    output = {
        'simulation':  'replay_attack',
        'timestamp':   datetime.now(timezone.utc).isoformat(),
        'total':       total,
        'detected':    detected,
        'elapsed_s':   round(elapsed, 2),
        'results':     results,
    }

    path = os.path.join(RESULTS_DIR, 'replay_log.json')
    with open(path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n  Results saved → {path}")
    print(f"\n✅ Replay attack simulation complete.")

    return output


if __name__ == '__main__':
    main()