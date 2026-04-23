import os
import sys
import json
import time
import random
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

from crypto_engine      import CryptoEngine
from sensor_simulator   import SensorSimulator
from packet_builder     import PacketBuilder
from signer             import PacketSigner
from encryptor          import PacketEncryptor
from decryptor          import RelayDecryptor
from reencryptor        import RelayReencryptor
from sequence_checker   import ValidatorSequenceChecker
from signature_verifier import ValidatorSignatureVerifier
from zkp_verifier       import ZKPVerifier
from audit_logger       import AuditLogger

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

"""
packet_loss_sim.py

Simulates packet loss scenarios and measures pipeline
resilience under real F1 telemetry conditions.

Scenarios tested:
    1. Random loss     — packets dropped randomly at 5%, 10%, 20%
    2. Burst loss      — consecutive packets dropped (network blip)
    3. Selective loss  — specific sequence numbers dropped
    4. Recovery        — pipeline continues after loss episode
    5. High load loss  — loss under sustained 100Hz simulation

Metrics captured:
    - Loss rate actual vs configured
    - Sequence gap detection count
    - Pipeline recovery time
    - Accepted vs dropped at validator

Results saved to:
    simulations/results/packet_loss_results.json
"""

RESULTS_DIR = os.path.join(ROOT, 'simulations', 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)


def build_pipeline():
    """Build complete pipeline."""
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

    val_checker = ValidatorSequenceChecker(
        node_id='fia_validator',
        check_timestamps=False,
        strict_ordering=True,
        max_sequence_gap=50,
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
        'sim':          sim,
        'builder':      builder,
        'signer':       signer,
        'enc':          enc,
        'dec':          dec,
        'reenc':        reenc,
        'val_eng':      val_eng,
        'val_checker':  val_checker,
        'sig_verifier': sig_verifier,
        'zkp':          zkp,
        'audit':        audit,
    }


def make_val_packet(p: dict) -> dict:
    """Build one full pipeline validator packet."""
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
    return val_pkt


def process_at_validator(p: dict, pkt: dict) -> bool:
    """Run validator checks. Returns True if accepted."""
    from cryptography.exceptions import InvalidSignature
    from signature_verifier import SignatureVerificationError

    try:
        p['sig_verifier'].verify(pkt)
    except (InvalidSignature, SignatureVerificationError):
        return False

    seq = p['val_checker'].check(pkt)
    if not seq.passed:
        return False

    zkp = p['zkp'].verify_packet(pkt)
    return zkp.verified


# ── Scenario simulations ─────────────────────────────────────────

def sim_1_random_loss(p: dict) -> dict:
    """
    Scenario: Packets dropped randomly at various rates.
    Measures: Gap detection, recovery, acceptance rate.
    """
    print("\n[Scenario 1] Random Packet Loss")

    loss_rates = [0.05, 0.10, 0.20]
    scenario_results = []

    for rate in loss_rates:
        n_packets  = 50
        sent       = 0
        dropped    = 0
        accepted   = 0
        gaps_seen  = 0

        # Fresh checker for each rate
        checker = ValidatorSequenceChecker(
            node_id=f'val_{int(rate*100)}pct',
            check_timestamps=False,
            strict_ordering=True,
            max_sequence_gap=10,
        )

        for _ in range(n_packets):
            pkt = make_val_packet(p)
            sent += 1

            # Simulate random loss
            if random.random() < rate:
                dropped += 1
                continue

            # Process surviving packet
            from cryptography.exceptions import InvalidSignature
            from signature_verifier import (
                SignatureVerificationError
            )
            try:
                p['sig_verifier'].verify(pkt)
            except (
                InvalidSignature, SignatureVerificationError
            ):
                continue

            seq_result = checker.check(pkt)
            if seq_result.warnings:
                gaps_seen += len(seq_result.warnings)
            if seq_result.passed:
                zkp = p['zkp'].verify_packet(pkt)
                if zkp.verified:
                    accepted += 1

        actual_rate = round(dropped / sent, 3)
        print(
            f"  Loss {int(rate*100):3d}%: "
            f"sent={sent} "
            f"dropped={dropped} "
            f"accepted={accepted} "
            f"gaps={gaps_seen} "
            f"actual_rate={actual_rate}"
        )

        scenario_results.append({
            'configured_loss_pct': int(rate * 100),
            'sent':          sent,
            'dropped':       dropped,
            'accepted':      accepted,
            'gaps_detected': gaps_seen,
            'actual_rate':   actual_rate,
        })

    return {
        'scenario':  'random_loss',
        'results':   scenario_results,
    }


def sim_2_burst_loss(p: dict) -> dict:
    """
    Scenario: Consecutive packets dropped (network blip).
    Measures: Gap detection during burst, recovery after.
    """
    print("\n[Scenario 2] Burst Packet Loss")

    burst_sizes = [3, 5, 10]
    scenario_results = []

    for burst in burst_sizes:
        n_packets   = 30
        burst_start = 10
        accepted    = 0
        dropped     = 0
        gaps_seen   = 0

        checker = ValidatorSequenceChecker(
            node_id=f'val_burst_{burst}',
            check_timestamps=False,
            strict_ordering=True,
            max_sequence_gap=2,
        )

        for i in range(n_packets):
            pkt = make_val_packet(p)

            # Drop burst window
            if burst_start <= i < burst_start + burst:
                dropped += 1
                continue

            from cryptography.exceptions import InvalidSignature
            from signature_verifier import (
                SignatureVerificationError
            )
            try:
                p['sig_verifier'].verify(pkt)
            except (
                InvalidSignature, SignatureVerificationError
            ):
                continue

            seq_result = checker.check(pkt)
            if seq_result.warnings:
                gaps_seen += 1
            if seq_result.passed:
                zkp = p['zkp'].verify_packet(pkt)
                if zkp.verified:
                    accepted += 1

        print(
            f"  Burst {burst:2d} pkts: "
            f"dropped={dropped} "
            f"accepted={accepted} "
            f"gaps_detected={gaps_seen}"
        )

        scenario_results.append({
            'burst_size':    burst,
            'dropped':       dropped,
            'accepted':      accepted,
            'gaps_detected': gaps_seen,
            'recovered':     accepted > 0,
        })

    return {
        'scenario': 'burst_loss',
        'results':  scenario_results,
    }


def sim_3_selective_loss(p: dict) -> dict:
    """
    Scenario: Specific sequence numbers dropped.
    Measures: Gap detection for known missing sequences.
    """
    print("\n[Scenario 3] Selective Packet Loss")

    n_packets    = 20
    drop_indices = {3, 7, 12, 15}
    accepted     = 0
    dropped      = 0
    gaps_seen    = 0

    checker = ValidatorSequenceChecker(
        node_id='val_selective',
        check_timestamps=False,
        strict_ordering=True,
        max_sequence_gap=2,
    )

    from cryptography.exceptions import InvalidSignature
    from signature_verifier import SignatureVerificationError

    for i in range(n_packets):
        pkt = make_val_packet(p)

        if i in drop_indices:
            dropped += 1
            print(
                f"  Dropped seq={pkt['sequence_no']} "
                f"(index={i})"
            )
            continue

        try:
            p['sig_verifier'].verify(pkt)
        except (InvalidSignature, SignatureVerificationError):
            continue

        seq_result = checker.check(pkt)
        if seq_result.warnings:
            gaps_seen += 1
        if seq_result.passed:
            zkp = p['zkp'].verify_packet(pkt)
            if zkp.verified:
                accepted += 1

    print(
        f"  Selective drop: "
        f"dropped={dropped} "
        f"accepted={accepted} "
        f"gaps_detected={gaps_seen}"
    )

    return {
        'scenario':      'selective_loss',
        'drop_indices':  list(drop_indices),
        'dropped':       dropped,
        'accepted':      accepted,
        'gaps_detected': gaps_seen,
        'recovered':     accepted > 0,
    }


def sim_4_recovery(p: dict) -> dict:
    """
    Scenario: Normal → loss episode → recovery.
    Measures: Pipeline continues accepting after loss stops.
    """
    print("\n[Scenario 4] Pipeline Recovery After Loss")

    checker = ValidatorSequenceChecker(
        node_id='val_recovery',
        check_timestamps=False,
        strict_ordering=True,
        max_sequence_gap=20,
    )

    from cryptography.exceptions import InvalidSignature
    from signature_verifier import SignatureVerificationError

    phases = [
        ('normal',   10, 0.00),
        ('loss',     10, 1.00),
        ('recovery', 10, 0.00),
    ]

    phase_results = []
    for phase_name, n, loss_rate in phases:
        accepted = 0
        dropped  = 0

        for _ in range(n):
            pkt = make_val_packet(p)

            if random.random() < loss_rate:
                dropped += 1
                continue

            try:
                p['sig_verifier'].verify(pkt)
            except (
                InvalidSignature, SignatureVerificationError
            ):
                continue

            seq = checker.check(pkt)
            if seq.passed:
                zkp = p['zkp'].verify_packet(pkt)
                if zkp.verified:
                    accepted += 1

        print(
            f"  Phase [{phase_name:8s}]: "
            f"sent={n} "
            f"dropped={dropped} "
            f"accepted={accepted}"
        )

        phase_results.append({
            'phase':    phase_name,
            'sent':     n,
            'dropped':  dropped,
            'accepted': accepted,
        })

    recovery_phase = phase_results[2]
    recovered = recovery_phase['accepted'] > 0
    print(
        f"  Pipeline recovered: "
        f"{'✅ YES' if recovered else '❌ NO'}"
    )

    return {
        'scenario': 'recovery',
        'phases':   phase_results,
        'recovered': recovered,
    }


def sim_5_high_load_loss(p: dict) -> dict:
    """
    Scenario: 100 packets at 5% loss rate — high load.
    Measures: Overall acceptance rate under sustained load.
    """
    print("\n[Scenario 5] High Load with Packet Loss")

    n_packets  = 100
    loss_rate  = 0.05
    accepted   = 0
    dropped    = 0
    start      = time.time()

    checker = ValidatorSequenceChecker(
        node_id='val_highload',
        check_timestamps=False,
        strict_ordering=True,
        max_sequence_gap=10,
    )

    from cryptography.exceptions import InvalidSignature
    from signature_verifier import SignatureVerificationError

    for _ in range(n_packets):
        pkt = make_val_packet(p)

        if random.random() < loss_rate:
            dropped += 1
            continue

        try:
            p['sig_verifier'].verify(pkt)
        except (InvalidSignature, SignatureVerificationError):
            continue

        seq = checker.check(pkt)
        if seq.passed:
            zkp = p['zkp'].verify_packet(pkt)
            if zkp.verified:
                accepted += 1

    elapsed      = time.time() - start
    accept_rate  = round(accepted / n_packets, 3)
    pkt_per_sec  = round(n_packets / elapsed, 1)

    print(
        f"  Packets: {n_packets} | "
        f"Dropped: {dropped} | "
        f"Accepted: {accepted}"
    )
    print(
        f"  Accept rate: {accept_rate:.1%} | "
        f"Throughput: {pkt_per_sec:.0f} pkt/s"
    )

    return {
        'scenario':    'high_load_loss',
        'n_packets':   n_packets,
        'loss_rate':   loss_rate,
        'dropped':     dropped,
        'accepted':    accepted,
        'accept_rate': accept_rate,
        'pkt_per_sec': pkt_per_sec,
        'elapsed_s':   round(elapsed, 3),
    }


# ── Main ──────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  PitCrypt-F1 — Packet Loss Simulation")
    print("  Measuring pipeline resilience under packet loss")
    print("="*60)

    random.seed(42)
    p       = build_pipeline()
    results = []
    start   = time.time()

    results.append(sim_1_random_loss(p))
    results.append(sim_2_burst_loss(p))
    results.append(sim_3_selective_loss(p))
    results.append(sim_4_recovery(p))
    results.append(sim_5_high_load_loss(p))

    elapsed = time.time() - start

    print("\n" + "="*60)
    print("  Summary")
    print("="*60)
    for r in results:
        print(f"  ✅ {r['scenario']}")
    print(f"\n  Elapsed: {elapsed:.2f}s")

    output = {
        'simulation': 'packet_loss',
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'elapsed_s':  round(elapsed, 2),
        'results':    results,
    }

    path = os.path.join(
        RESULTS_DIR, 'packet_loss_results.json'
    )
    with open(path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n  Results saved → {path}")
    print(f"\n✅ Packet loss simulation complete.")
    return output


if __name__ == '__main__':
    main()