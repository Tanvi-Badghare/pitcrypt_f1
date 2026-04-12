import os
import sys
import time
import logging
from typing import Dict, Set, Optional
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Path setup ───────────────────────────────────────────────────
ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
sys.path.insert(0, os.path.join(ROOT, 'car-producer', 'src'))
sys.path.insert(0, os.path.join(ROOT, 'relay-node',   'src'))

"""
sequence_checker.py

Final sequence ordering and replay defence
at the FIA validator node.

This is the second line of replay defence after the relay.
Even if an attacker compromises the relay node and injects
replayed packets, the validator's sequence checker
independently detects them.

Checks:
    1. Strict monotonic sequence — must be greater than last
    2. Replay detection          — seen sequences rejected
    3. Timestamp freshness       — configurable age window
    4. Per-node independent state — Mercedes and Red Bull
                                   tracked separately
    5. Gap analysis              — large gaps logged for audit

Why validator needs its own sequence checker:
    - Relay checks sequence but could be compromised
    - Validator is the final authority — FIA endpoint
    - Independent check ensures defence in depth
    - Validator logs are the authoritative audit record
"""

MAX_TIMESTAMP_AGE_MS = 60_000     # 60 seconds at validator
MAX_SEQUENCE_GAP     = 1000       # Larger gap allowed — relay
                                   # may buffer packets
REPLAY_WINDOW        = 50_000     # Remember last 50k sequences


class SequenceCheckResult:
    """Result of sequence check on a single packet."""

    def __init__(self):
        self.passed   = True
        self.warnings = []
        self.errors   = []

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)
        logging.warning(f"[SequenceChecker] ⚠️  {msg}")

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.passed = False
        logging.error(f"[SequenceChecker] 🚨 {msg}")

    def to_dict(self) -> dict:
        return {
            'passed':   self.passed,
            'warnings': self.warnings,
            'errors':   self.errors,
        }


class ValidatorSequenceChecker:
    """
    Sequence ordering and replay defence at validator node.
    Maintains strict per-node sequence state.
    """

    def __init__(
        self,
        node_id:              str  = 'validator',
        max_timestamp_age_ms: int  = MAX_TIMESTAMP_AGE_MS,
        max_sequence_gap:     int  = MAX_SEQUENCE_GAP,
        check_timestamps:     bool = True,
        strict_ordering:      bool = True,
    ):
        self.node_id             = node_id
        self._max_ts_age         = max_timestamp_age_ms
        self._max_gap            = max_sequence_gap
        self._check_ts           = check_timestamps
        self._strict             = strict_ordering

        # Per car-node state
        self._last_seq:   Dict[str, int]      = {}
        self._seen_seqs:  Dict[str, Set[int]] = {}
        self._first_seen: Dict[str, float]    = {}

        # Stats
        self._checked_count  = 0
        self._passed_count   = 0
        self._failed_count   = 0
        self._replay_count   = 0
        self._gap_count      = 0

        print(f"  [ValidatorSequenceChecker] "
              f"Initialised: {node_id}")
        print(f"  [ValidatorSequenceChecker] "
              f"Strict ordering: {strict_ordering}")
        print(f"  [ValidatorSequenceChecker] "
              f"Timestamp check: {check_timestamps}")

    def check(self, packet: dict) -> SequenceCheckResult:
        """
        Check sequence integrity of a validator-bound packet.

        Args:
            packet: Packet dict containing sequence_no,
                    timestamp, original_node or node_id

        Returns:
            SequenceCheckResult
        """
        result  = SequenceCheckResult()
        node_id = (
            packet.get('original_node') or
            packet.get('node_id', 'unknown')
        )
        seq    = packet.get('sequence_no', 0)
        ts_ms  = packet.get('timestamp',   0)

        # ── Init node state ──────────────────────────────────────
        if node_id not in self._last_seq:
            self._last_seq[node_id]   = 0
            self._seen_seqs[node_id]  = set()
            self._first_seen[node_id] = time.time()
            logging.info(
                f"  [ValidatorSequenceChecker] "
                f"New node: {node_id}"
            )

        # ── 1. Sequence validity ─────────────────────────────────
        if seq <= 0:
            result.add_error(
                f"Invalid sequence: {seq}. Must be > 0."
            )

        # ── 2. Replay detection ──────────────────────────────────
        if seq in self._seen_seqs[node_id]:
            self._replay_count += 1
            result.add_error(
                f"REPLAY DETECTED — "
                f"node={node_id} seq={seq} "
                f"already processed by validator."
            )

        # ── 3. Strict ordering ───────────────────────────────────
        last = self._last_seq[node_id]
        if self._strict and last > 0 and seq <= last:
            result.add_error(
                f"OUT OF ORDER — "
                f"node={node_id} "
                f"seq={seq} <= last={last}."
            )

        # ── 4. Gap analysis ──────────────────────────────────────
        if last > 0:
            gap = seq - last
            if gap > self._max_gap:
                self._gap_count += 1
                result.add_warning(
                    f"LARGE GAP — "
                    f"node={node_id} "
                    f"gap={gap} packets. "
                    f"Possible packet loss or injection."
                )

        # ── 5. Timestamp freshness ───────────────────────────────
        if self._check_ts and ts_ms > 0:
            now_ms = int(time.time() * 1000)
            age_ms = now_ms - ts_ms

            if age_ms > self._max_ts_age:
                result.add_error(
                    f"STALE PACKET — "
                    f"node={node_id} "
                    f"age={age_ms}ms > "
                    f"max={self._max_ts_age}ms."
                )
            elif age_ms < -5000:
                result.add_warning(
                    f"FUTURE TIMESTAMP — "
                    f"node={node_id} "
                    f"delta={age_ms}ms."
                )

        # ── Update state if passed ───────────────────────────────
        if result.passed:
            self._last_seq[node_id] = seq
            self._seen_seqs[node_id].add(seq)

            # Rolling window — prevent unbounded memory
            if len(self._seen_seqs[node_id]) > REPLAY_WINDOW:
                oldest = min(self._seen_seqs[node_id])
                self._seen_seqs[node_id].discard(oldest)

        # ── Stats ────────────────────────────────────────────────
        self._checked_count += 1
        if result.passed:
            self._passed_count += 1
        else:
            self._failed_count += 1

        return result

    def check_and_annotate(self, packet: dict) -> dict:
        """Annotate packet with sequence check result."""
        result = self.check(packet)
        pkt    = dict(packet)
        pkt['sequence_result']   = result.to_dict()
        pkt['sequence_passed']   = result.passed
        pkt['sequence_warnings'] = result.warnings
        pkt['sequence_errors']   = result.errors
        return pkt

    def reset_node(self, node_id: str) -> None:
        """Reset state for a node — call on reconnection."""
        self._last_seq.pop(node_id,   None)
        self._seen_seqs.pop(node_id,  None)
        self._first_seen.pop(node_id, None)
        logging.info(
            f"  [ValidatorSequenceChecker] "
            f"Reset: {node_id}"
        )

    def get_node_stats(self, node_id: str) -> dict:
        """Per-node statistics."""
        return {
            'node_id':      node_id,
            'last_seq':     self._last_seq.get(node_id, 0),
            'seen_count':   len(
                self._seen_seqs.get(node_id, set())
            ),
            'first_seen':   self._first_seen.get(node_id),
        }

    # ── Properties ───────────────────────────────────────────────

    @property
    def checked_count(self) -> int:
        return self._checked_count

    @property
    def passed_count(self) -> int:
        return self._passed_count

    @property
    def failed_count(self) -> int:
        return self._failed_count

    @property
    def replay_count(self) -> int:
        return self._replay_count

    @property
    def gap_count(self) -> int:
        return self._gap_count


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    from sensor_simulator import SensorSimulator
    from packet_builder   import PacketBuilder
    from signer           import PacketSigner
    from encryptor        import PacketEncryptor
    from crypto_engine    import CryptoEngine
    from decryptor        import RelayDecryptor
    from reencryptor      import RelayReencryptor

    print("\n" + "="*55)
    print("  ValidatorSequenceChecker — Self Test")
    print("="*55)

    # ── Pipeline setup ───────────────────────────────────────────
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R',
        add_noise=False,
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

    checker = ValidatorSequenceChecker(
        node_id='fia_validator',
        check_timestamps=False,
        strict_ordering=True,
    )

    def make_val_packet():
        frame   = sim.get_next_frame()
        pkt     = builder.build(frame)
        signed  = signer.sign_packet(pkt)
        enc_pkt = enc.encrypt_packet(signed)
        dec_pkt = dec.decrypt(enc_pkt)
        reenc_p = reenc.reencrypt(dec_pkt)
        pt      = val_eng.decrypt(
            nonce=reenc_p['nonce_bytes'],
            ciphertext=reenc_p['ciphertext_bytes'],
            associated_data=reenc_p['header'],
        )
        val_pkt = dict(reenc_p)
        val_pkt['payload_bytes'] = pt
        val_pkt['original_node'] = 'mercedes_car'
        return val_pkt

    # ── Test 1: Sequential packets pass ─────────────────────────
    print("\n[Test 1] Sequential packets all pass")
    results = [checker.check(make_val_packet())
               for _ in range(10)]
    passed = sum(1 for r in results if r.passed)
    print(f"  Passed: {passed}/10")
    assert passed == 10
    print(f"  Sequential check: ✅")

    # ── Test 2: Replay detected ──────────────────────────────────
    print("\n[Test 2] Replay attack detected")
    pkt2    = make_val_packet()
    checker.check(pkt2)        # First — OK
    result2 = checker.check(pkt2)   # Replay
    print(f"  Passed:  {result2.passed}")
    print(f"  Errors:  {result2.errors}")
    assert not result2.passed
    assert checker.replay_count >= 1
    print(f"  Replay detected: ✅")

    # ── Test 3: Out of order detected ───────────────────────────
    print("\n[Test 3] Out of order detected")
    c2   = ValidatorSequenceChecker(
        node_id='val_ooo', check_timestamps=False
    )
    high      = make_val_packet()
    low       = make_val_packet()
    high['sequence_no'] = 500
    low['sequence_no']  = 200
    c2.check(high)
    r3 = c2.check(low)
    assert not r3.passed
    print(f"  Out of order detected: ✅")

    # ── Test 4: Annotate packet ──────────────────────────────────
    print("\n[Test 4] Annotate packet")
    c3  = ValidatorSequenceChecker(
        node_id='val_ann', check_timestamps=False
    )
    p4  = make_val_packet()
    ann = c3.check_and_annotate(p4)
    assert 'sequence_result'  in ann
    assert 'sequence_passed'  in ann
    assert ann['sequence_passed'] is True
    print(f"  Annotation: ✅")

    # ── Test 5: Node stats ───────────────────────────────────────
    print("\n[Test 5] Node statistics")
    stats = checker.get_node_stats('mercedes_car')
    print(f"  Last seq:   {stats['last_seq']}")
    print(f"  Seen count: {stats['seen_count']}")
    assert stats['last_seq'] > 0
    print(f"  Node stats: ✅")

    print(f"\n  Checked: {checker.checked_count}")
    print(f"  Passed:  {checker.passed_count}")
    print(f"  Failed:  {checker.failed_count}")
    print(f"  Replays: {checker.replay_count}")
    print(f"\n✅ ValidatorSequenceChecker self-test complete.")