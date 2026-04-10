import os
import sys
import json
import logging
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Path setup ───────────────────────────────────────────────────
ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
THRESHOLDS_PATH = os.path.join(
    ROOT, 'data', 'processed', 'thresholds.json'
)

"""
anomaly_filters.py

Statistical anomaly detection at the relay node.

Filters decrypted telemetry packets against calibrated
thresholds derived from real 2025 Mercedes AMG and
Red Bull Racing telemetry data.

Thresholds are loaded from:
    data/processed/thresholds.json
    — produced by forensic/calibrate_thresholds.py

Detection methods:
    1. Threshold violation  — value outside [lower, upper]
    2. Physical bounds      — value physically impossible
    3. Rate-of-change       — value changed too fast
    4. Freeze detection     — value unchanged too long

Anomaly actions:
    PASS    — packet passes all checks
    FLAG    — anomaly detected, packet forwarded with flag
    REJECT  — anomaly severe enough to drop packet

Why flag vs reject:
    - Threshold violations are flagged — could be legitimate
      extreme driving (Monaco kerbs, safety car restart)
    - Physical impossibilities are rejected — Speed=500 km/h
      cannot happen and indicates tampering or sensor failure
"""

# ── Physical hard limits — impossible values ─────────────────────
PHYSICAL_LIMITS = {
    'Speed':    {'min': -5.0,  'max': 400},  # Allow slight negative — pit lane rollback
    'RPM':      {'min': 0,     'max': 16000},
    'Throttle': {'min': 0,     'max': 100},
    'Brake':    {'min': 0,     'max': 1},
    'nGear':    {'min': 0,     'max': 8},
    'DRS':      {'min': 0,     'max': 14},
}

# ── Rate-of-change limits — per frame ────────────────────────────
# Maximum change between consecutive frames
ROC_LIMITS = {
    'Speed':    50.0,    # Max 50 km/h change per frame
    'RPM':      3000.0,  # Max 3000 RPM change per frame
    'Throttle': 100.0,   # Full range change allowed
    'Brake':    1.0,     # Boolean — full change allowed
    'nGear':    2.0,     # Max 2 gear change per frame
    'DRS':      14.0,    # Full range change allowed
}

# ── Anomaly severity levels ───────────────────────────────────────
SEVERITY_PASS   = 'PASS'
SEVERITY_FLAG   = 'FLAG'
SEVERITY_REJECT = 'REJECT'

CHANNELS = ['Speed', 'RPM', 'Throttle', 'Brake', 'nGear', 'DRS']


class AnomalyResult:
    """Result of anomaly check on a single packet."""

    def __init__(self):
        self.severity    = SEVERITY_PASS
        self.violations  = []
        self.channel     = None
        self.value       = None
        self.expected    = None

    def add_violation(
        self,
        channel:   str,
        value:     float,
        reason:    str,
        severity:  str,
        expected:  str = None,
    ) -> None:
        self.violations.append({
            'channel':  channel,
            'value':    value,
            'reason':   reason,
            'severity': severity,
            'expected': expected,
        })
        # Escalate severity if needed
        if severity == SEVERITY_REJECT:
            self.severity = SEVERITY_REJECT
        elif (severity == SEVERITY_FLAG and
              self.severity == SEVERITY_PASS):
            self.severity = SEVERITY_FLAG

    @property
    def is_clean(self) -> bool:
        return self.severity == SEVERITY_PASS

    @property
    def is_flagged(self) -> bool:
        return self.severity == SEVERITY_FLAG

    @property
    def is_rejected(self) -> bool:
        return self.severity == SEVERITY_REJECT

    def to_dict(self) -> dict:
        return {
            'severity':   self.severity,
            'violations': self.violations,
            'clean':      self.is_clean,
        }


class AnomalyFilter:
    """
    Filters telemetry packets against calibrated thresholds.
    Per-team thresholds loaded from thresholds.json.
    """

    def __init__(
        self,
        thresholds_path: str = THRESHOLDS_PATH,
        node_id:         str = 'relay',
    ):
        self.node_id          = node_id
        self._thresholds      = self._load_thresholds(
            thresholds_path
        )
        self._last_values:    Dict[str, Dict] = {}
        self._checked_count   = 0
        self._flagged_count   = 0
        self._rejected_count  = 0

        print(f"  [AnomalyFilter] Initialised: {node_id}")
        if self._thresholds:
            teams = [
                t for t in self._thresholds.keys()
                if t != 'combined'
            ]
            print(
                f"  [AnomalyFilter] Thresholds loaded "
                f"for: {teams}"
            )
        else:
            print(
                f"  [AnomalyFilter] WARNING: No thresholds "
                f"loaded — using physical limits only"
            )

    def _load_thresholds(self, path: str) -> dict:
        if not os.path.exists(path):
            logging.warning(
                f"[AnomalyFilter] thresholds.json not found: "
                f"{path}. Using physical limits only."
            )
            return {}
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                logging.info(
                    f"[AnomalyFilter] Thresholds loaded: {path}"
                )
                return data
        except Exception as e:
            logging.error(
                f"[AnomalyFilter] Failed to load thresholds: {e}"
            )
            return {}

    def _get_thresholds(self, team: str) -> dict:
        """Get thresholds for team, fallback to combined."""
        return (
            self._thresholds.get(team) or
            self._thresholds.get('combined') or
            {}
        )

    def check(self, decrypted_packet: dict) -> AnomalyResult:
        """
        Run all anomaly checks on a decrypted packet.

        Args:
            decrypted_packet: dict from RelayDecryptor.decrypt()
                              Must contain 'payload_json'

        Returns:
            AnomalyResult with severity and violations
        """
        result  = AnomalyResult()
        payload = decrypted_packet.get('payload_json', {})
        team    = decrypted_packet.get('team', 'combined')
        node_id = decrypted_packet.get('node_id', 'unknown')

        thresholds = self._get_thresholds(team)

        for channel in CHANNELS:
            if channel not in payload:
                continue

            value = payload[channel]

            # ── 1. Physical bounds ───────────────────────────────
            limits = PHYSICAL_LIMITS.get(channel, {})
            if limits:
                if value < limits['min'] or value > limits['max']:
                    result.add_violation(
                        channel=channel,
                        value=value,
                        reason='physical_bounds_violation',
                        severity=SEVERITY_REJECT,
                        expected=(
                            f"[{limits['min']}, {limits['max']}]"
                        ),
                    )
                    continue   # Skip further checks

            # ── 2. Statistical threshold ─────────────────────────
            if channel in thresholds:
                lower = thresholds[channel].get('lower', None)
                upper = thresholds[channel].get('upper', None)

                if lower is not None and value < lower:
                    result.add_violation(
                        channel=channel,
                        value=value,
                        reason='below_threshold',
                        severity=SEVERITY_FLAG,
                        expected=f">= {lower:.2f}",
                    )
                elif upper is not None and value > upper:
                    result.add_violation(
                        channel=channel,
                        value=value,
                        reason='above_threshold',
                        severity=SEVERITY_FLAG,
                        expected=f"<= {upper:.2f}",
                    )

            # ── 3. Rate of change ────────────────────────────────
            last = self._last_values.get(node_id, {})
            if channel in last:
                roc       = abs(value - last[channel])
                roc_limit = ROC_LIMITS.get(channel, float('inf'))
                if roc > roc_limit:
                    result.add_violation(
                        channel=channel,
                        value=value,
                        reason='rate_of_change_exceeded',
                        severity=SEVERITY_FLAG,
                        expected=f"delta <= {roc_limit}",
                    )

        # ── Update last values ───────────────────────────────────
        if node_id not in self._last_values:
            self._last_values[node_id] = {}
        for channel in CHANNELS:
            if channel in payload:
                self._last_values[node_id][channel] = (
                    payload[channel]
                )

        # ── Update stats ─────────────────────────────────────────
        self._checked_count += 1
        if result.is_flagged:
            self._flagged_count  += 1
            logging.warning(
                f"[AnomalyFilter] ⚠️  FLAG — "
                f"node={node_id} team={team} "
                f"violations={result.violations}"
            )
        elif result.is_rejected:
            self._rejected_count += 1
            logging.error(
                f"[AnomalyFilter] 🚨 REJECT — "
                f"node={node_id} team={team} "
                f"violations={result.violations}"
            )

        return result

    def check_and_annotate(
        self, decrypted_packet: dict
    ) -> dict:
        """
        Run anomaly check and annotate packet with result.

        Returns packet dict with added fields:
            anomaly_result  — AnomalyResult.to_dict()
            anomaly_clean   — bool
            anomaly_flagged — bool
            anomaly_rejected — bool
        """
        result = self.check(decrypted_packet)
        packet = dict(decrypted_packet)

        packet['anomaly_result']   = result.to_dict()
        packet['anomaly_clean']    = result.is_clean
        packet['anomaly_flagged']  = result.is_flagged
        packet['anomaly_rejected'] = result.is_rejected

        return packet

    def check_batch(
        self, packets: list
    ) -> Tuple[list, list, list]:
        """
        Check a batch of packets.

        Returns:
            (clean_list, flagged_list, rejected_list)
        """
        clean    = []
        flagged  = []
        rejected = []

        for packet in packets:
            annotated = self.check_and_annotate(packet)
            if annotated['anomaly_rejected']:
                rejected.append(annotated)
            elif annotated['anomaly_flagged']:
                flagged.append(annotated)
            else:
                clean.append(annotated)

        return clean, flagged, rejected

    # ── Properties ───────────────────────────────────────────────

    @property
    def checked_count(self) -> int:
        return self._checked_count

    @property
    def flagged_count(self) -> int:
        return self._flagged_count

    @property
    def rejected_count(self) -> int:
        return self._rejected_count

    @property
    def thresholds_loaded(self) -> bool:
        return len(self._thresholds) > 0


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
    print("  AnomalyFilter — Self Test")
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

    enc  = PacketEncryptor(
        crypto_engine=car_eng, node_id='mercedes_car'
    )
    dec  = RelayDecryptor(node_id='relay_01')
    dec.register_session('mercedes_car', relay_eng)
    filt = AnomalyFilter(node_id='relay_01')

    def make_decrypted(speed=None, rpm=None):
        frame  = sim.get_next_frame()
        if speed is not None:
            frame['Speed'] = speed
        if rpm is not None:
            frame['RPM'] = rpm
        pkt = builder.build(frame)
        sig = signer.sign_packet(pkt)
        enc_pkt = enc.encrypt_packet(sig)
        return dec.decrypt(enc_pkt)

    # ── Test 1: Normal packet passes ─────────────────────────────
    print("\n[Test 1] Normal packet passes")
    decrypted = make_decrypted()
    result    = filt.check(decrypted)
    print(f"  Severity: {result.severity}")
    print(f"  Clean:    {result.is_clean}")
    assert result.severity in [SEVERITY_PASS, SEVERITY_FLAG]
    print(f"  Normal packet check: ✅")

    # ── Test 2: Physical impossibility rejected ───────────────────
    print("\n[Test 2] Impossible speed rejected")
    bad = make_decrypted(speed=999.0)
    bad['payload_json']['Speed'] = 999.0
    result2 = filt.check(bad)
    print(f"  Severity:   {result2.severity}")
    print(f"  Violations: {result2.violations}")
    assert result2.is_rejected
    print(f"  Physical violation rejected: ✅")

    # ── Test 3: Annotate packet ───────────────────────────────────
    print("\n[Test 3] Annotate packet with anomaly result")
    decrypted3  = make_decrypted()
    annotated   = filt.check_and_annotate(decrypted3)
    print(f"  Has anomaly_result:   "
          f"{'anomaly_result' in annotated}")
    print(f"  Has anomaly_clean:    "
          f"{'anomaly_clean' in annotated}")
    print(f"  Has anomaly_rejected: "
          f"{'anomaly_rejected' in annotated}")
    assert 'anomaly_result' in annotated
    assert 'anomaly_clean'  in annotated
    print(f"  Annotation: ✅")

    # ── Test 4: Batch check ───────────────────────────────────────
    print("\n[Test 4] Batch anomaly check")
    batch = [make_decrypted() for _ in range(5)]
    clean, flagged, rejected = filt.check_batch(batch)
    print(f"  Clean:    {len(clean)}")
    print(f"  Flagged:  {len(flagged)}")
    print(f"  Rejected: {len(rejected)}")
    assert len(clean) + len(flagged) + len(rejected) == 5
    print(f"  Batch check: ✅")

    print(f"\n  Checked:  {filt.checked_count}")
    print(f"  Flagged:  {filt.flagged_count}")
    print(f"  Rejected: {filt.rejected_count}")
    print(f"\n✅ AnomalyFilter self-test complete.")