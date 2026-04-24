import os
import sys
import json
import time
import random
import statistics
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

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

"""
jitter_sim.py

Simulates network jitter and out-of-order packet delivery
under real F1 telemetry conditions.

Jitter scenarios:
    1. Low jitter     — small random reordering (±2 packets)
    2. Medium jitter  — moderate reordering (±5 packets)
    3. High jitter    — severe reordering (±10 packets)
    4. Crypto latency — measure ECDH + AEAD overhead per packet
    5. Key rotation   — measure pipeline latency during rotation

Metrics captured:
    - Packets accepted vs rejected due to ordering
    - End-to-end latency per packet (ms)
    - Latency mean, median, p95, p99
    - Throughput (packets/second)

Results saved to:
    simulations/results/jitter_results.json
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

    sig_verifier = ValidatorSignatureVerifier(
        node_id='fia_validator'
    )
    sig_verifier.register_node(
        'mercedes_car', signer.public_key_bytes
    )
    zkp = ZKPVerifier(node_id='fia_validator')

    return {
        'sim':          sim,
        'builder':      builder,
        'signer':       signer,
        'enc':          enc,
        'dec':          dec,
        'reenc':        reenc,
        'val_eng':      val_eng,
        'sig_verifier': sig_verifier,
        'zkp':          zkp,
    }


def make_val_packet(p: dict) -> tuple:
    """
    Build one full pipeline packet.
    Returns (val_packet, latency_ms).
    """
    t0 = time.perf_counter()

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

    latency_ms = (time.perf_counter() - t0) * 1000
    return val_pkt, latency_ms


def apply_jitter(
    packets: list, window: int
) -> list:
    """
    Simulate network jitter by shuffling packets
    within a sliding window.
    """
    reordered = list(packets)
    for i in range(0, len(reordered), window):
        chunk = reordered[i:i+window]
        random.shuffle(chunk)
        reordered[i:i+window] = chunk
    return reordered


def latency_stats(latencies: list) -> dict:
    """Compute latency statistics."""
    if not latencies:
        return {}
    sorted_l = sorted(latencies)
    n        = len(sorted_l)
    return {
        'mean_ms':   round(statistics.mean(latencies),   3),
        'median_ms': round(statistics.median(latencies), 3),
        'min_ms':    round(sorted_l[0],                  3),
        'max_ms':    round(sorted_l[-1],                 3),
        'p95_ms':    round(sorted_l[int(n * 0.95)],      3),
        'p99_ms':    round(sorted_l[int(n * 0.99)],      3),
        'stdev_ms':  round(
            statistics.stdev(latencies) if n > 1 else 0, 3
        ),
    }


# ── Jitter scenarios ──────────────────────────────────────────────

def sim_1_low_jitter(p: dict) -> dict:
    """
    Scenario: Low jitter — small reordering window of 2.
    Measures: Acceptance rate with minor out-of-order delivery.
    """
    print("\n[Scenario 1] Low Jitter (window=2)")

    n_packets = 30
    window    = 2
    packets   = []
    latencies = []

    for _ in range(n_packets):
        pkt, lat = make_val_packet(p)
        packets.append(pkt)
        latencies.append(lat)

    reordered = apply_jitter(packets, window)

    checker = ValidatorSequenceChecker(
        node_id='val_low_jitter',
        check_timestamps=False,
        strict_ordering=True,
    )

    from cryptography.exceptions import InvalidSignature
    from signature_verifier import SignatureVerificationError

    accepted  = 0
    rejected  = 0

    for pkt in reordered:
        try:
            p['sig_verifier'].verify(pkt)
        except (InvalidSignature, SignatureVerificationError):
            rejected += 1
            continue

        seq = checker.check(pkt)
        if seq.passed:
            zkp = p['zkp'].verify_packet(pkt)
            if zkp.verified:
                accepted += 1
        else:
            rejected += 1

    stats = latency_stats(latencies)
    print(
        f"  Window={window}: "
        f"accepted={accepted}/{n_packets} "
        f"rejected={rejected}"
    )
    print(
        f"  Latency: "
        f"mean={stats['mean_ms']}ms "
        f"p95={stats['p95_ms']}ms"
    )

    return {
        'scenario':  'low_jitter',
        'window':    window,
        'n_packets': n_packets,
        'accepted':  accepted,
        'rejected':  rejected,
        'latency':   stats,
    }


def sim_2_medium_jitter(p: dict) -> dict:
    """
    Scenario: Medium jitter — reordering window of 5.
    Measures: Impact on strict sequence checking.
    """
    print("\n[Scenario 2] Medium Jitter (window=5)")

    n_packets = 30
    window    = 5
    packets   = []
    latencies = []

    for _ in range(n_packets):
        pkt, lat = make_val_packet(p)
        packets.append(pkt)
        latencies.append(lat)

    reordered = apply_jitter(packets, window)

    checker = ValidatorSequenceChecker(
        node_id='val_med_jitter',
        check_timestamps=False,
        strict_ordering=True,
    )

    from cryptography.exceptions import InvalidSignature
    from signature_verifier import SignatureVerificationError

    accepted = 0
    rejected = 0

    for pkt in reordered:
        try:
            p['sig_verifier'].verify(pkt)
        except (InvalidSignature, SignatureVerificationError):
            rejected += 1
            continue

        seq = checker.check(pkt)
        if seq.passed:
            zkp = p['zkp'].verify_packet(pkt)
            if zkp.verified:
                accepted += 1
        else:
            rejected += 1

    stats = latency_stats(latencies)
    print(
        f"  Window={window}: "
        f"accepted={accepted}/{n_packets} "
        f"rejected={rejected}"
    )
    print(
        f"  Latency: "
        f"mean={stats['mean_ms']}ms "
        f"p95={stats['p95_ms']}ms"
    )

    return {
        'scenario':  'medium_jitter',
        'window':    window,
        'n_packets': n_packets,
        'accepted':  accepted,
        'rejected':  rejected,
        'latency':   stats,
    }


def sim_3_high_jitter(p: dict) -> dict:
    """
    Scenario: High jitter — reordering window of 10.
    Measures: Pipeline behaviour under severe reordering.
    """
    print("\n[Scenario 3] High Jitter (window=10)")

    n_packets = 30
    window    = 10
    packets   = []
    latencies = []

    for _ in range(n_packets):
        pkt, lat = make_val_packet(p)
        packets.append(pkt)
        latencies.append(lat)

    reordered = apply_jitter(packets, window)

    checker = ValidatorSequenceChecker(
        node_id='val_high_jitter',
        check_timestamps=False,
        strict_ordering=True,
    )

    from cryptography.exceptions import InvalidSignature
    from signature_verifier import SignatureVerificationError

    accepted = 0
    rejected = 0

    for pkt in reordered:
        try:
            p['sig_verifier'].verify(pkt)
        except (InvalidSignature, SignatureVerificationError):
            rejected += 1
            continue

        seq = checker.check(pkt)
        if seq.passed:
            zkp = p['zkp'].verify_packet(pkt)
            if zkp.verified:
                accepted += 1
        else:
            rejected += 1

    stats = latency_stats(latencies)
    print(
        f"  Window={window}: "
        f"accepted={accepted}/{n_packets} "
        f"rejected={rejected}"
    )
    print(
        f"  Latency: "
        f"mean={stats['mean_ms']}ms "
        f"p95={stats['p95_ms']}ms"
    )

    return {
        'scenario':  'high_jitter',
        'window':    window,
        'n_packets': n_packets,
        'accepted':  accepted,
        'rejected':  rejected,
        'latency':   stats,
    }


def sim_4_crypto_latency(p: dict) -> dict:
    """
    Scenario: Measure cryptographic operation latency.
    Captures: ECDH, sign, encrypt, decrypt, verify per packet.
    """
    print("\n[Scenario 4] Cryptographic Latency Benchmark")

    n_packets = 50
    latencies = []

    for _ in range(n_packets):
        _, lat = make_val_packet(p)
        latencies.append(lat)

    stats = latency_stats(latencies)

    print(f"  Packets:    {n_packets}")
    print(f"  Mean:       {stats['mean_ms']}ms")
    print(f"  Median:     {stats['median_ms']}ms")
    print(f"  P95:        {stats['p95_ms']}ms")
    print(f"  P99:        {stats['p99_ms']}ms")
    print(f"  Min:        {stats['min_ms']}ms")
    print(f"  Max:        {stats['max_ms']}ms")

    # Throughput at zero jitter
    total_s   = sum(latencies) / 1000
    throughput = round(n_packets / total_s, 1)
    print(f"  Throughput: {throughput} pkt/s")

    return {
        'scenario':    'crypto_latency',
        'n_packets':   n_packets,
        'latency':     stats,
        'throughput':  throughput,
    }


def sim_5_no_jitter_baseline(p: dict) -> dict:
    """
    Scenario: Zero jitter baseline — perfect ordering.
    Measures: Maximum throughput with no reordering.
    """
    print("\n[Scenario 5] No Jitter Baseline")

    n_packets = 50
    accepted  = 0
    latencies = []

    checker = ValidatorSequenceChecker(
        node_id='val_baseline',
        check_timestamps=False,
        strict_ordering=True,
    )

    from cryptography.exceptions import InvalidSignature
    from signature_verifier import SignatureVerificationError

    start = time.perf_counter()

    for _ in range(n_packets):
        pkt, lat = make_val_packet(p)
        latencies.append(lat)

        try:
            p['sig_verifier'].verify(pkt)
        except (InvalidSignature, SignatureVerificationError):
            continue

        seq = checker.check(pkt)
        if seq.passed:
            zkp = p['zkp'].verify_packet(pkt)
            if zkp.verified:
                accepted += 1

    elapsed    = time.perf_counter() - start
    throughput = round(n_packets / elapsed, 1)
    stats      = latency_stats(latencies)

    print(
        f"  Accepted: {accepted}/{n_packets} "
        f"({accepted/n_packets:.1%})"
    )
    print(
        f"  Throughput: {throughput} pkt/s"
    )
    print(
        f"  Mean latency: {stats['mean_ms']}ms"
    )

    return {
        'scenario':   'no_jitter_baseline',
        'n_packets':  n_packets,
        'accepted':   accepted,
        'throughput': throughput,
        'latency':    stats,
    }


# ── Main ──────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  PitCrypt-F1 — Jitter Simulation")
    print("  Measuring pipeline resilience under network jitter")
    print("="*60)

    random.seed(42)
    p       = build_pipeline()
    results = []
    start   = time.time()

    results.append(sim_1_low_jitter(p))
    results.append(sim_2_medium_jitter(p))
    results.append(sim_3_high_jitter(p))
    results.append(sim_4_crypto_latency(p))
    results.append(sim_5_no_jitter_baseline(p))

    elapsed = time.time() - start

    print("\n" + "="*60)
    print("  Summary")
    print("="*60)

    for r in results:
        accepted  = r.get('accepted', r.get('n_packets'))
        n         = r.get('n_packets', 0)
        lat       = r.get('latency', {})
        mean      = lat.get('mean_ms', '—')
        print(
            f"  ✅ {r['scenario']:<25} "
            f"accepted={accepted}/{n} "
            f"mean_lat={mean}ms"
        )

    print(f"\n  Elapsed: {elapsed:.2f}s")

    output = {
        'simulation': 'jitter',
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'elapsed_s':  round(elapsed, 2),
        'results':    results,
    }

    path = os.path.join(RESULTS_DIR, 'jitter_results.json')
    with open(path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n  Results saved → {path}")
    print(f"\n✅ Jitter simulation complete.")
    return output


if __name__ == '__main__':
    main()