import os
import sys
import time
import logging
from typing import Dict, Optional, Set
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

"""
integrity_checker.py

Sequence ordering and replay attack detection
at the relay node.

Checks:
    1. Sequence ordering  — packets must arrive in order
    2. Replay detection   — duplicate sequence numbers rejected
    3. Timestamp window   — packets too old are rejected
    4. Sequence gap       — large gaps flagged as suspicious
    5. Signature presence — packet must have Ed25519 signature

This runs BEFORE anomaly filtering — a packet with
invalid sequence or replay characteristics is dropped
immediately without further processing.

Why check at relay not just validator:
    - Defence in depth — catch attacks as early as possible
    - Reduces validator load
    - Relay is the first point that sees decrypted metadata
"""

# ── Constants ─────────────────────────────────────────────────────
MAX_TIMESTAMP_AGE_MS  = 30_000   # 30 seconds — reject older
MAX_SEQUENCE_GAP      = 100      # Flag gaps larger than this
REPLAY_WINDOW_SIZE    = 10_000   # Remember last N sequence nums


class IntegrityError(Exception):
    """Raised when integrity check fails critically."""
    pass


class IntegrityCheckResult:
    """Result of integrity check on a single packet."""

    def __init__(self):
        self.passed   = True
        self.warnings = []
        self.errors   = []

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)
        logging.warning(f"[IntegrityChecker] ⚠️  {msg}")

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.passed = False
        logging.error(f"[IntegrityChecker] 🚨 {msg}")

    def to_dict(self) -> dict:
        return {
            'passed':   self.passed,
            'warnings': self.warnings,
            'errors':   self.errors,
        }


class IntegrityChecker:
    """
    Sequence and replay integrity checker at relay node.
    Maintains per-node sequence state.
    """

    def __init__(
        self,
        node_id:              str   = 'relay',
        max_timestamp_age_ms: int   = MAX_TIMESTAMP_AGE_MS,
        max_sequence_gap:     int   = MAX_SEQUENCE_GAP,
        check_timestamps:     bool  = True,
        check_signatures:     bool  = True,
    ):
        self.node_id              = node_id
        self._max_ts_age          = max_timestamp_age_ms
        self._max_gap             = max_sequence_gap
        self._check_timestamps    = check_timestamps
        self._check_signatures    = check_signatures

        # Per-node state — keyed by car node_id
        self._last_sequence:  Dict[str, int]      = {}
        self._seen_sequences: Dict[str, Set[int]] = {}

        # Stats
        self._checked_count    = 0
        self._passed_count     = 0
        self._failed_count     = 0
        self._replay_count     = 0
        self._out_of_order     = 0

        print(f"  [IntegrityChecker] Initialised: {node_id}")
        print(
            f"  [IntegrityChecker] Max timestamp age: "
            f"{max_timestamp_age_ms}ms"
        )
        print(
            f"  [IntegrityChecker] Max sequence gap: "
            f"{max_sequence_gap}"
        )

    def check(self, packet: dict) -> IntegrityCheckResult:
        """
        Run all integrity checks on a packet.

        Args:
            packet: Decrypted packet dict containing:
                    sequence_no, timestamp, node_id,
                    signature or signature_bytes

        Returns:
            IntegrityCheckResult
        """
        result  = IntegrityCheckResult()
        node_id = packet.get('node_id', 'unknown')
        seq     = packet.get('sequence_no', 0)
        ts_ms   = packet.get('timestamp',   0)

        # ── Init node state ──────────────────────────────────────
        if node_id not in self._last_sequence:
            self._last_sequence[node_id]  = 0
            self._seen_sequences[node_id] = set()

        # ── 1. Sequence number validation ────────────────────────
        if seq <= 0:
            result.add_error(
                f"Invalid sequence number: {seq}. "
                f"Must be > 0."
            )

        # ── 2. Replay detection ──────────────────────────────────
        if seq in self._seen_sequences[node_id]:
            self._replay_count += 1
            result.add_error(
                f"REPLAY ATTACK DETECTED — "
                f"node={node_id} seq={seq} "
                f"already seen."
            )

        # ── 3. Sequence ordering ─────────────────────────────────
        last_seq = self._last_sequence[node_id]
        if last_seq > 0 and seq <= last_seq:
            self._out_of_order += 1
            result.add_error(
                f"OUT OF ORDER — "
                f"node={node_id} "
                f"got seq={seq}, "
                f"last={last_seq}. "
                f"Possible replay."
            )

        # ── 4. Sequence gap detection ────────────────────────────
        if last_seq > 0:
            gap = seq - last_seq
            if gap > self._max_gap:
                result.add_warning(
                    f"LARGE SEQUENCE GAP — "
                    f"node={node_id} "
                    f"gap={gap} (max={self._max_gap}). "
                    f"Possible packet loss or injection."
                )

        # ── 5. Timestamp validation ──────────────────────────────
        if self._check_timestamps and ts_ms > 0:
            now_ms  = int(time.time() * 1000)
            age_ms  = now_ms - ts_ms

            if age_ms > self._max_ts_age:
                result.add_error(
                    f"TIMESTAMP TOO OLD — "
                    f"node={node_id} "
                    f"age={age_ms}ms > "
                    f"max={self._max_ts_age}ms. "
                    f"Possible replay."
                )
            elif age_ms < -5000:
                # More than 5s in the future — suspicious
                result.add_warning(
                    f"FUTURE TIMESTAMP — "
                    f"node={node_id} "
                    f"age={age_ms}ms. "
                    f"Clock skew or tampering."
                )

        # ── 6. Signature presence ────────────────────────────────
        if self._check_signatures:
            has_sig = (
                packet.get('signature') or
                packet.get('signature_bytes')
            )
            if not has_sig:
                result.add_error(
                    f"MISSING SIGNATURE — "
                    f"node={node_id} seq={seq}. "
                    f"Packet rejected."
                )

        # ── Update state if passed ───────────────────────────────
        if result.passed:
            self._last_sequence[node_id] = seq
            # Maintain rolling window
            self._seen_sequences[node_id].add(seq)
            if len(self._seen_sequences[node_id]) > (
                REPLAY_WINDOW_SIZE
            ):
                # Remove oldest — approximated by min
                oldest = min(self._seen_sequences[node_id])
                self._seen_sequences[node_id].discard(oldest)

        # ── Update stats ─────────────────────────────────────────
        self._checked_count += 1
        if result.passed:
            self._passed_count += 1
        else:
            self._failed_count += 1

        return result

    def check_and_annotate(self, packet: dict) -> dict:
        """
        Run integrity check and annotate packet.

        Returns packet with added fields:
            integrity_result  — IntegrityCheckResult.to_dict()
            integrity_passed  — bool
            integrity_warnings — list
            integrity_errors   — list
        """
        result = self.check(packet)
        pkt    = dict(packet)

        pkt['integrity_result']   = result.to_dict()
        pkt['integrity_passed']   = result.passed
        pkt['integrity_warnings'] = result.warnings
        pkt['integrity_errors']   = result.errors

        return pkt

    def reset_node(self, node_id: str) -> None:
        """
        Reset sequence state for a node.
        Call on key rotation or reconnection.
        """
        self._last_sequence.pop(node_id,  None)
        self._seen_sequences.pop(node_id, None)
        logging.info(
            f"[IntegrityChecker] Reset state: {node_id}"
        )

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
    def out_of_order_count(self) -> int:
        return self._out_of_order


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    sys.path.insert(
        0, os.path.join(ROOT, 'car-producer', 'src')
    )
    from sensor_simulator import SensorSimulator
    from packet_builder   import PacketBuilder
    from signer           import PacketSigner
    from encryptor        import PacketEncryptor
    from crypto_engine    import CryptoEngine
    from decryptor        import RelayDecryptor

    print("\n" + "="*55)
    print("  IntegrityChecker — Self Test")
    print("="*55)

    # ── Setup pipeline ───────────────────────────────────────────
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R'
    )
    builder = PacketBuilder(team='mercedes', session='R')
    signer  = PacketSigner(node_id='mercedes_car')

    car_eng   = CryptoEngine(node_id='mercedes_car')
    relay_eng = CryptoEngine(node_id='relay_01')
    cp        = car_eng.new_session()
    rp        = relay_eng.new_session()
    car_eng.complete_handshake(rp)
    relay_eng.complete_handshake(cp)

    enc = PacketEncryptor(
        crypto_engine=car_eng, node_id='mercedes_car'
    )
    dec = RelayDecryptor(node_id='relay_01')
    dec.register_session('mercedes_car', relay_eng)
    checker = IntegrityChecker(
        node_id='relay_01',
        check_timestamps=True,
        check_signatures=True,
    )

    def make_decrypted():
        frame = sim.get_next_frame()
        pkt   = builder.build(frame)
        sig   = signer.sign_packet(pkt)
        enc_p = enc.encrypt_packet(sig)
        return dec.decrypt(enc_p)

    # ── Test 1: Valid packet passes ──────────────────────────────
    print("\n[Test 1] Valid packet passes")
    d      = make_decrypted()
    result = checker.check(d)
    print(f"  Passed:   {result.passed}")
    print(f"  Warnings: {result.warnings}")
    print(f"  Errors:   {result.errors}")
    assert result.passed
    print(f"  Valid packet: ✅")

    # ── Test 2: Replay attack detected ───────────────────────────
    print("\n[Test 2] Replay attack detected")
    d2      = make_decrypted()
    checker.check(d2)   # First pass — OK
    result2 = checker.check(d2)   # Replay — should fail
    print(f"  Passed:  {result2.passed}")
    print(f"  Errors:  {result2.errors}")
    assert not result2.passed
    assert checker.replay_count >= 1
    print(f"  Replay detected: ✅")

    # ── Test 3: Out of order detected ────────────────────────────
    print("\n[Test 3] Out of order packet")
    checker2 = IntegrityChecker(
        node_id='relay_02',
        check_timestamps=False,
    )
    # Send seq 5 then seq 3
    fake_high = make_decrypted()
    fake_high['sequence_no'] = 5
    fake_low  = make_decrypted()
    fake_low['sequence_no']  = 3

    checker2.check(fake_high)
    result3 = checker2.check(fake_low)
    print(f"  Passed: {result3.passed}")
    print(f"  Errors: {result3.errors}")
    assert not result3.passed
    print(f"  Out of order detected: ✅")

    # ── Test 4: Missing signature rejected ───────────────────────
    print("\n[Test 4] Missing signature rejected")
    d4 = make_decrypted()
    d4.pop('signature',       None)
    d4.pop('signature_bytes', None)

    checker3 = IntegrityChecker(
        node_id='relay_03',
        check_timestamps=False,
    )
    result4 = checker3.check(d4)
    print(f"  Passed: {result4.passed}")
    print(f"  Errors: {result4.errors}")
    assert not result4.passed
    print(f"  Missing signature rejected: ✅")

    # ── Test 5: Sequential packets all pass ──────────────────────
    print("\n[Test 5] Sequential packets all pass")
    checker4 = IntegrityChecker(
        node_id='relay_04',
        check_timestamps=False,
    )
    results = []
    for _ in range(10):
        d = make_decrypted()
        results.append(checker4.check(d))

    passed = sum(1 for r in results if r.passed)
    print(f"  Passed: {passed}/10")
    assert passed == 10
    print(f"  Sequential packets: ✅")

    print(f"\n  Checked:      {checker.checked_count}")
    print(f"  Passed:       {checker.passed_count}")
    print(f"  Failed:       {checker.failed_count}")
    print(f"  Replays:      {checker.replay_count}")
    print(f"\n✅ IntegrityChecker self-test complete.")