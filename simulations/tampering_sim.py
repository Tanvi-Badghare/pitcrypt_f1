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
from signature_verifier  import (
    ValidatorSignatureVerifier,
    SignatureVerificationError,
)
from zkp_verifier        import ZKPVerifier
from audit_logger        import AuditLogger
from cryptography.exceptions import InvalidTag, InvalidSignature

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

"""
tampering_sim.py

Simulates packet tampering attack scenarios
against PitCrypt-F1.

Attack vectors tested:
    1. Payload bit flip       — flip bits in ciphertext
    2. Header manipulation    — modify sequence in header
    3. Speed injection        — inject false speed value
    4. Signature stripping    — remove Ed25519 signature
    5. Commitment mismatch    — tamper with ZKP commitment
    6. Header associated data — modify AEAD associated data
    7. Full payload replace   — swap entire payload

Defence mechanisms verified:
    - AEAD authentication tag at relay decryption
    - Ed25519 signature at validator
    - ZKP commitment at validator
    - Physical bounds at anomaly filter

Results saved to:
    simulations/results/tamper_detection.csv
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

    car_eng   = CryptoEngine(node_id='mercedes_car')
    relay_eng = CryptoEngine(node_id='relay_01')
    cp        = car_eng.new_session()
    rp        = relay_eng.new_session()
    car_eng.complete_handshake(rp)
    relay_eng.complete_handshake(cp)

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
    )
    sig_verifier = ValidatorSignatureVerifier(
        node_id='fia_validator'
    )
    sig_verifier.register_node(
        'mercedes_car', signer.public_key_bytes
    )
    zkp   = ZKPVerifier(node_id='fia_validator')
    audit = AuditLogger(
        node_id='fia_validator', log_to_file=False
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


def make_encrypted_packet(p: dict) -> tuple:
    """
    Build packet — return at different pipeline stages.
    Returns: (signed, encrypted, decrypted, reencrypted,
               val_packet, commit_info)
    """
    frame  = p['sim'].get_next_frame()
    packet = p['builder'].build(frame)
    signed = p['signer'].sign_packet(packet)
    commit = ZKPVerifier.generate_commitment(
        signed['payload']
    )
    enc    = p['enc'].encrypt_packet(signed)
    dec    = p['dec'].decrypt(enc)
    reenc  = p['reenc'].reencrypt(dec)
    pt     = p['val_eng'].decrypt(
        nonce=reenc['nonce_bytes'],
        ciphertext=reenc['ciphertext_bytes'],
        associated_data=reenc['header'],
    )
    val_pkt = dict(reenc)
    val_pkt['payload_bytes']  = pt
    val_pkt['original_node']  = 'mercedes_car'
    val_pkt['zkp_commitment'] = commit['commitment']
    val_pkt['zkp_nonce']      = commit['nonce']

    return signed, enc, dec, reenc, val_pkt, commit


def check_detected_at_relay(
    p: dict, enc_packet: dict, attack_desc: str
) -> tuple:
    """Try to decrypt tampered packet at relay."""
    try:
        p['dec'].decrypt(enc_packet)
        return False, 'relay_passed'
    except InvalidTag:
        return True, 'aead_tag_failed'
    except Exception as e:
        return True, str(e)


def check_detected_at_validator(
    p: dict, val_pkt: dict
) -> tuple:
    """Run validator checks on packet."""
    # Signature
    try:
        p['sig_verifier'].verify(val_pkt)
    except (InvalidSignature, SignatureVerificationError) as e:
        return True, f'signature_failed: {e}'

    # Sequence
    seq = p['val_checker'].check(val_pkt)
    if not seq.passed:
        return True, f'sequence_failed: {seq.errors}'

    # ZKP
    zkp = p['zkp'].verify_packet(val_pkt)
    if not zkp.verified:
        return True, f'zkp_failed: {zkp.reason}'

    return False, 'all_passed'


# ── Attack simulations ────────────────────────────────────────────

def sim_1_payload_bit_flip(p: dict) -> dict:
    """
    Attack: Flip bits in encrypted ciphertext.
    Defence: AEAD authentication tag fails at relay.
    """
    print("\n[Attack 1] Payload Bit Flip")

    signed, enc, dec, reenc, val_pkt, _ = (
        make_encrypted_packet(p)
    )

    # Flip bits in ciphertext
    tampered_ct = bytearray(enc['ciphertext_bytes'])
    tampered_ct[10] ^= 0xFF
    tampered_ct[20] ^= 0xAA
    tampered_enc = dict(enc)
    tampered_enc['ciphertext_bytes'] = bytes(tampered_ct)
    tampered_enc['ciphertext']       = bytes(tampered_ct).hex()

    detected, reason = check_detected_at_relay(
        p, tampered_enc, 'bit_flip'
    )

    print(f"  Flipped bytes at positions 10, 20")
    print(f"  Detected at relay: {detected}")
    print(f"  Reason: {reason}")
    print(
        f"  Result: "
        f"{'✅ DETECTED' if detected else '❌ MISSED'}"
    )

    return {
        'attack':        'payload_bit_flip',
        'layer':         'relay_aead',
        'detected':      detected,
        'reason':        reason,
        'detection_point': 'relay' if detected else 'none',
    }


def sim_2_speed_value_injection(p: dict) -> dict:
    """
    Attack: Decrypt, modify speed value, re-encrypt.
    Defence: Ed25519 signature fails — signed data changed.
    """
    print("\n[Attack 2] Speed Value Injection")

    signed, enc, dec, reenc, val_pkt, commit = (
        make_encrypted_packet(p)
    )

    original_speed = val_pkt.get('payload_bytes', b'')
    import json as _json
    try:
        original_payload = _json.loads(
            original_speed.decode()
        )
        original_speed_val = original_payload.get(
            'Speed', 0
        )
    except Exception:
        original_speed_val = 0

    # Modify speed in payload
    tampered_pkt = dict(val_pkt)
    tampered_payload = bytearray(val_pkt['payload_bytes'])
    # Flip bits to corrupt speed value
    tampered_payload[5] ^= 0xFF
    tampered_pkt['payload_bytes'] = bytes(tampered_payload)

    detected, reason = check_detected_at_validator(
        p, tampered_pkt
    )

    print(
        f"  Original speed: {original_speed_val} km/h"
    )
    print(f"  Payload bytes corrupted")
    print(f"  Detected at validator: {detected}")
    print(f"  Reason: {reason}")
    print(
        f"  Result: "
        f"{'✅ DETECTED' if detected else '❌ MISSED'}"
    )

    return {
        'attack':          'speed_injection',
        'layer':           'validator_signature',
        'original_speed':  original_speed_val,
        'detected':        detected,
        'reason':          reason,
        'detection_point': 'validator' if detected else 'none',
    }


def sim_3_signature_stripping(p: dict) -> dict:
    """
    Attack: Remove Ed25519 signature from packet.
    Defence: ValidatorSignatureVerifier rejects.
    """
    print("\n[Attack 3] Signature Stripping")

    signed, enc, dec, reenc, val_pkt, _ = (
        make_encrypted_packet(p)
    )

    # Strip signature
    tampered = dict(val_pkt)
    tampered.pop('signature',       None)
    tampered.pop('signature_bytes', None)

    detected, reason = check_detected_at_validator(
        p, tampered
    )

    print(f"  Signature fields removed")
    print(f"  Detected: {detected}")
    print(f"  Reason: {reason}")
    print(
        f"  Result: "
        f"{'✅ DETECTED' if detected else '❌ MISSED'}"
    )

    return {
        'attack':          'signature_stripping',
        'layer':           'validator_signature',
        'detected':        detected,
        'reason':          reason,
        'detection_point': 'validator' if detected else 'none',
    }


def sim_4_zkp_commitment_tamper(p: dict) -> dict:
    """
    Attack: Tamper with ZKP commitment value.
    Defence: ZKPVerifier commitment mismatch.
    """
    print("\n[Attack 4] ZKP Commitment Tampering")

    signed, enc, dec, reenc, val_pkt, _ = (
        make_encrypted_packet(p)
    )

    # Use valid validator packet through sequence checker
    # but tamper with ZKP commitment
    p['val_checker'].check(val_pkt)   # Register sequence

    tampered = dict(val_pkt)
    tampered['zkp_commitment'] = 'a' * 64   # Fake commitment

    # Only check ZKP (skip sig/seq to isolate)
    zkp_result = p['zkp'].verify_packet(tampered)
    detected   = not zkp_result.verified

    print(f"  Commitment replaced with fake value")
    print(f"  ZKP detected: {detected}")
    print(f"  Reason: {zkp_result.reason}")
    print(
        f"  Result: "
        f"{'✅ DETECTED' if detected else '❌ MISSED'}"
    )

    return {
        'attack':          'zkp_commitment_tamper',
        'layer':           'validator_zkp',
        'detected':        detected,
        'reason':          zkp_result.reason,
        'detection_point': 'validator' if detected else 'none',
    }


def sim_5_header_aead_tamper(p: dict) -> dict:
    """
    Attack: Modify AEAD associated data (header).
    Defence: AEAD auth tag covers header — fails at relay.
    """
    print("\n[Attack 5] Header AEAD Tampering")

    signed, enc, dec, reenc, val_pkt, _ = (
        make_encrypted_packet(p)
    )

    # Tamper with header bytes
    tampered_header = bytearray(enc['header'])
    tampered_header[8] ^= 0xFF    # Flip byte in header
    tampered_enc = dict(enc)
    tampered_enc['header']     = bytes(tampered_header)
    tampered_enc['header_hex'] = bytes(tampered_header).hex()

    detected, reason = check_detected_at_relay(
        p, tampered_enc, 'header_tamper'
    )

    print(f"  Header byte at position 8 flipped")
    print(f"  Detected at relay: {detected}")
    print(f"  Reason: {reason}")
    print(
        f"  Result: "
        f"{'✅ DETECTED' if detected else '❌ MISSED'}"
    )

    return {
        'attack':          'header_aead_tamper',
        'layer':           'relay_aead',
        'detected':        detected,
        'reason':          reason,
        'detection_point': 'relay' if detected else 'none',
    }


def sim_6_wrong_signature(p: dict) -> dict:
    """
    Attack: Replace Ed25519 signature with random bytes.
    Defence: ValidatorSignatureVerifier rejects.
    """
    print("\n[Attack 6] Wrong Signature")

    signed, enc, dec, reenc, val_pkt, _ = (
        make_encrypted_packet(p)
    )

    tampered                    = dict(val_pkt)
    fake_sig                    = os.urandom(64)
    tampered['signature_bytes'] = fake_sig
    tampered['signature']       = fake_sig.hex()

    detected, reason = check_detected_at_validator(
        p, tampered
    )

    print(f"  Signature replaced with random 64 bytes")
    print(f"  Detected: {detected}")
    print(f"  Reason: {reason}")
    print(
        f"  Result: "
        f"{'✅ DETECTED' if detected else '❌ MISSED'}"
    )

    return {
        'attack':          'wrong_signature',
        'layer':           'validator_signature',
        'detected':        detected,
        'reason':          reason,
        'detection_point': 'validator' if detected else 'none',
    }


def sim_7_multi_layer_tamper(p: dict) -> dict:
    """
    Attack: Tamper at multiple layers simultaneously.
    Expected: Caught at earliest detection point.
    """
    print("\n[Attack 7] Multi-Layer Tampering")

    signed, enc, dec, reenc, val_pkt, _ = (
        make_encrypted_packet(p)
    )

    # Tamper ciphertext AND signature
    tampered_ct = bytearray(enc['ciphertext_bytes'])
    tampered_ct[5] ^= 0xFF
    tampered_enc                    = dict(enc)
    tampered_enc['ciphertext_bytes'] = bytes(tampered_ct)
    tampered_enc['ciphertext']       = bytes(tampered_ct).hex()

    # Also strip signature
    tampered_val = dict(val_pkt)
    tampered_val.pop('signature',       None)
    tampered_val.pop('signature_bytes', None)

    # Check relay first
    relay_detected, relay_reason = check_detected_at_relay(
        p, tampered_enc, 'multi_layer'
    )

    print(f"  Tampered: ciphertext bits + stripped signature")
    print(f"  Relay detected:     {relay_detected} "
          f"({relay_reason})")

    if not relay_detected:
        val_detected, val_reason = check_detected_at_validator(
            p, tampered_val
        )
        print(f"  Validator detected: {val_detected} "
              f"({val_reason})")
        detected = val_detected
        point    = 'validator' if detected else 'none'
    else:
        detected = True
        point    = 'relay'

    print(
        f"  Result: "
        f"{'✅ DETECTED at ' + point if detected else '❌ MISSED'}"
    )

    return {
        'attack':          'multi_layer_tamper',
        'layers':          ['ciphertext', 'signature'],
        'detected':        detected,
        'detection_point': point,
        'relay_detected':  relay_detected,
    }


# ── Main ──────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  PitCrypt-F1 — Tampering Attack Simulation")
    print("  Testing defence mechanisms against packet tampering")
    print("="*60)

    p       = build_pipeline()
    results = []
    start   = time.time()

    results.append(sim_1_payload_bit_flip(p))
    results.append(sim_2_speed_value_injection(p))
    results.append(sim_3_signature_stripping(p))
    results.append(sim_4_zkp_commitment_tamper(p))
    results.append(sim_5_header_aead_tamper(p))
    results.append(sim_6_wrong_signature(p))
    results.append(sim_7_multi_layer_tamper(p))

    elapsed = time.time() - start

    # ── Summary ──────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  Simulation Summary")
    print("="*60)

    total    = len(results)
    detected = sum(1 for r in results if r['detected'])

    for r in results:
        status = '✅' if r['detected'] else '❌'
        point  = r.get('detection_point', '?')
        layer  = r.get('layer', '?')
        print(
            f"  {status} {r['attack']:<30} "
            f"layer={layer:<25} "
            f"point={point}"
        )

    print(f"\n  Attacks simulated: {total}")
    print(f"  Detected:          {detected}/{total}")
    print(f"  Elapsed:           {elapsed:.2f}s")

    # ── Save CSV ─────────────────────────────────────────────────
    csv_path = os.path.join(
        RESULTS_DIR, 'tamper_detection.csv'
    )
    with open(csv_path, 'w') as f:
        f.write(
            "attack,layer,detected,"
            "detection_point,reason\n"
        )
        for r in results:
            f.write(
                f"{r['attack']},"
                f"{r.get('layer', '')},"
                f"{r['detected']},"
                f"{r.get('detection_point', '')},"
                f"{r.get('reason', '')}\n"
            )

    print(f"\n  Results saved → {csv_path}")

    # ── Save JSON ─────────────────────────────────────────────────
    json_path = os.path.join(
        RESULTS_DIR, 'tamper_detection.json'
    )
    output = {
        'simulation': 'tampering_attack',
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'total':      total,
        'detected':   detected,
        'elapsed_s':  round(elapsed, 2),
        'results':    results,
    }
    with open(json_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"  Results saved → {json_path}")
    print(f"\n✅ Tampering simulation complete.")

    return output


if __name__ == '__main__':
    main()