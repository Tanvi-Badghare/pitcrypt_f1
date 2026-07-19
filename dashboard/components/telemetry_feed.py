import os
import sys
import time
import logging
from typing import Optional
from datetime import datetime, timezone

# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
CAR_SRC = os.path.join(ROOT, 'car-producer',  'src')
REL_SRC = os.path.join(ROOT, 'relay-node',    'src')
VAL_SRC = os.path.join(ROOT, 'validator-node', 'src')

for path in [CAR_SRC, REL_SRC, VAL_SRC]:
    if path not in sys.path:
        sys.path.insert(0, path)

from crypto_engine      import CryptoEngine
from sensor_simulator   import SensorSimulator
from packet_builder     import PacketBuilder
from signer             import PacketSigner
from encryptor          import PacketEncryptor
from decryptor          import RelayDecryptor
from reencryptor        import RelayReencryptor
from anomaly_filters    import AnomalyFilter
from integrity_checker  import IntegrityChecker
from sequence_checker   import ValidatorSequenceChecker
from signature_verifier import (
    ValidatorSignatureVerifier,
    SignatureVerificationError,
)
from zkp_verifier       import ZKPVerifier
from audit_logger       import AuditLogger
from cryptography.exceptions import InvalidSignature, InvalidTag

logging.basicConfig(level=logging.WARNING)

"""
telemetry_feed.py

Live telemetry feed component for the PitCrypt-F1 dashboard.
Manages the complete Car → Relay → Validator pipeline.
"""


class TelemetryFeed:

    def __init__(self):
        self._initialised = False
        self._reset_state()

    def _reset_state(self):
        self._sim           = None
        self._builder       = None
        self._signer        = None
        self._enc           = None
        self._dec           = None
        self._reenc         = None
        self._val_eng       = None
        self._anomaly       = None
        self._relay_checker = None
        self._val_checker   = None
        self._sig_verifier  = None
        self._zkp           = None
        self._audit         = None
        self._car_engine    = None
        self._relay_engine  = None
        self._relay_val_eng = None
        self._session_start = time.time()
        self._packet_count  = 0

        # ── Buffers ───────────────────────────────────────────────
        # Increased to 500 — needed for full lap track map coverage
        self._recent_packets = []
        self._audit_events   = []
        self._last_encrypted = None

        # ── Chart history — increased to 1000 for full lap trace ──
        self._chart_history = {
            'seq':      [],
            'speed':    [],
            'rpm':      [],
            'throttle': [],
        }

        # ── Stats ─────────────────────────────────────────────────
        self._stats = {
            'total':         0,
            'accepted':      0,
            'rejected':      0,
            'flagged':       0,
            'key_rotations': 0,
            'start_time':    None,
        }
        self._anomaly_stats = {
            'checked':  0,
            'flagged':  0,
            'rejected': 0,
        }
        self._crypto_stats = {
            'car_key':      '0' * 32,
            'val_key':      '0' * 32,
            'encrypted':    0,
            'reencrypted':  0,
            'signatures':   0,
            'zkp_verified': 0,
            'key_age_s':    0,
        }

        self._data_rows   = 0
        self._initialised = False

    def initialise(
        self,
        team:    str = 'mercedes',
        race:    str = 'Bahrain',
        session: str = 'R',
        driver:  str = None,
        lap:     int = None,
    ) -> None:
        self._reset_state()

        self._sim = SensorSimulator(
            team=team, race=race, session=session,
            driver=driver, lap=lap,
            add_noise=False, inject_anomalies=False,
        )
        self._data_rows = (
            self._sim.total_frames
            if hasattr(self._sim, 'total_frames')
            else len(self._sim.data)
            if hasattr(self._sim, 'data')
            else 0
        )
        self._builder = PacketBuilder(
            team=team, session=session
        )
        self._signer = PacketSigner(
            node_id=f'{team}_car'
        )

        # ── Car → Relay ECDH ──────────────────────────────────────
        self._car_engine   = CryptoEngine(node_id=f'{team}_car')
        self._relay_engine = CryptoEngine(node_id='relay_01')
        cp = self._car_engine.new_session()
        rp = self._relay_engine.new_session()
        self._car_engine.complete_handshake(rp)
        self._relay_engine.complete_handshake(cp)

        # ── Relay → Validator ECDH ────────────────────────────────
        self._relay_val_eng = CryptoEngine(node_id='relay_val')
        self._val_eng       = CryptoEngine(node_id='fia_validator')
        rvp = self._relay_val_eng.new_session()
        vp  = self._val_eng.new_session()
        self._relay_val_eng.complete_handshake(vp)
        self._val_eng.complete_handshake(rvp)

        # ── Pipeline components ───────────────────────────────────
        self._enc = PacketEncryptor(
            crypto_engine=self._car_engine,
            node_id=f'{team}_car',
        )
        self._dec = RelayDecryptor(node_id='relay_01')
        self._dec.register_session(
            f'{team}_car', self._relay_engine
        )
        self._reenc = RelayReencryptor(node_id='relay_01')
        self._reenc.register_validator_session(self._relay_val_eng)

        self._anomaly = AnomalyFilter(node_id='relay_01')
        self._relay_checker = IntegrityChecker(
            node_id='relay_01',
            check_timestamps=False,
            check_signatures=True,
        )
        self._val_checker = ValidatorSequenceChecker(
            node_id='fia_validator',
            check_timestamps=False,
            strict_ordering=True,
        )
        self._sig_verifier = ValidatorSignatureVerifier(
            node_id='fia_validator'
        )
        self._sig_verifier.register_node(
            f'{team}_car',
            self._signer.public_key_bytes,
        )
        self._zkp   = ZKPVerifier(node_id='fia_validator')
        self._audit = AuditLogger(
            node_id='fia_validator',
            log_to_file=False,
        )

        car_key = self._car_engine._session.session_key
        val_key = self._val_eng._session.session_key
        self._crypto_stats['car_key'] = car_key.hex()
        self._crypto_stats['val_key'] = val_key.hex()
        self._session_start           = time.time()
        self._stats['start_time']     = time.time()
        self._initialised             = True

    def process_one_packet(self) -> Optional[dict]:
        if not self._initialised:
            return None

        try:
            # ── Car side ─────────────────────────────────────────
            frame     = self._sim.get_next_frame()
            packet    = self._builder.build(frame)
            signed    = self._signer.sign_packet(packet)
            commit    = ZKPVerifier.generate_commitment(
                signed['payload']
            )
            encrypted = self._enc.encrypt_packet(signed)
            self._crypto_stats['encrypted'] += 1

            # ── Relay side ────────────────────────────────────────
            try:
                decrypted = self._dec.decrypt(encrypted)
            except InvalidTag:
                self._record_reject(encrypted, 'aead_failed')
                return self._make_result(
                    encrypted, 'REJECT', 'aead_failed'
                )

            integrity = self._relay_checker.check(decrypted)
            if not integrity.passed:
                self._record_reject(decrypted, 'integrity_failed')
                return self._make_result(
                    decrypted, 'REJECT', 'integrity_failed'
                )

            annotated = self._anomaly.check_and_annotate(decrypted)
            self._anomaly_stats['checked'] += 1

            if annotated['anomaly_rejected']:
                self._anomaly_stats['rejected'] += 1
                self._record_reject(decrypted, 'anomaly_rejected')
                return self._make_result(
                    decrypted, 'REJECT', 'anomaly_rejected'
                )
            if annotated['anomaly_flagged']:
                self._anomaly_stats['flagged'] += 1

            reencrypted = self._reenc.reencrypt(annotated)
            self._crypto_stats['reencrypted'] += 1

            # ── Validator side ────────────────────────────────────
            plaintext = self._val_eng.decrypt(
                nonce=reencrypted['nonce_bytes'],
                ciphertext=reencrypted['ciphertext_bytes'],
                associated_data=reencrypted['header'],
            )

            val_pkt = dict(reencrypted)
            val_pkt['payload_bytes']  = plaintext
            val_pkt['original_node']  = (
                encrypted.get('node_id', 'unknown')
            )
            val_pkt['zkp_commitment'] = commit['commitment']
            val_pkt['zkp_nonce']      = commit['nonce']

            try:
                self._sig_verifier.verify(val_pkt)
                self._crypto_stats['signatures'] += 1
            except (InvalidSignature, SignatureVerificationError):
                self._record_reject(val_pkt, 'sig_failed')
                return self._make_result(
                    val_pkt, 'REJECT', 'sig_failed'
                )

            seq_result = self._val_checker.check(val_pkt)
            if not seq_result.passed:
                self._record_reject(val_pkt, 'sequence_failed')
                return self._make_result(
                    val_pkt, 'REJECT', 'sequence_failed'
                )

            zkp_result = self._zkp.verify_packet(val_pkt)
            if not zkp_result.verified:
                self._record_reject(val_pkt, 'zkp_failed')
                return self._make_result(
                    val_pkt, 'REJECT', 'zkp_failed'
                )
            self._crypto_stats['zkp_verified'] += 1

            # ── Accept ────────────────────────────────────────────
            decision = (
                'FLAG' if annotated['anomaly_flagged']
                else 'ACCEPT'
            )

            if decision == 'FLAG':
                self._audit.log_flag(
                    val_pkt, reason='anomaly_flagged'
                )
                self._stats['flagged'] += 1
            else:
                self._audit.log_accept(
                    val_pkt, reason='all_checks_passed'
                )
                self._stats['accepted'] += 1

            self._stats['total']    += 1
            self._packet_count      += 1
            self._crypto_stats['key_age_s'] = (
                time.time() - self._session_start
            )

            val_pkt['anomaly_result'] = annotated.get(
                'anomaly_result', {}
            )

            result = self._make_result(
                val_pkt, decision, 'all_checks_passed'
            )
            result['payload_json']    = frame
            result['anomaly_flagged'] = annotated['anomaly_flagged']
            result['anomaly_result']  = annotated.get(
                'anomaly_result', {}
            )

            # ── Packet buffer (500 for full lap track map) ────────
            self._recent_packets.append(result)
            if len(self._recent_packets) > 500:
                self._recent_packets.pop(0)

            # Save for replay attack injection
            self._last_encrypted = dict(encrypted)

            # ── Chart history (1000 for full lap trace) ───────────
            self._chart_history['seq'].append(
                val_pkt.get('sequence_no', 0)
            )
            self._chart_history['speed'].append(
                frame.get('Speed', 0)
            )
            self._chart_history['rpm'].append(
                frame.get('RPM', 0)
            )
            self._chart_history['throttle'].append(
                frame.get('Throttle', 0)
            )
            if len(self._chart_history['seq']) > 1000:
                for key in self._chart_history:
                    self._chart_history[key].pop(0)

            # ── Audit event ───────────────────────────────────────
            audit_evt = {
                'timestamp':   datetime.now(timezone.utc).isoformat(),
                'decision':    decision,
                'sequence_no': val_pkt.get('sequence_no', 0),
                'reason':      'all_checks_passed',
            }
            self._audit_events.append(audit_evt)
            if len(self._audit_events) > 50:
                self._audit_events.pop(0)

            return result

        except Exception as e:
            logging.error(f"Pipeline error: {e}")
            self._stats['rejected'] += 1
            self._stats['total']    += 1
            return None

    def inject_attack(self, attack_type: str) -> Optional[dict]:
        if not self._initialised:
            return None

        if attack_type == 'replay':
            if self._last_encrypted is None:
                return None
            encrypted = dict(self._last_encrypted)
        else:
            frame     = self._sim.get_next_frame()
            packet    = self._builder.build(frame)
            signed    = self._signer.sign_packet(packet)
            commit    = ZKPVerifier.generate_commitment(
                signed['payload']
            )
            encrypted = self._enc.encrypt_packet(signed)

            if attack_type == 'tamper':
                tampered_ct = bytearray(
                    encrypted['ciphertext_bytes']
                )
                tampered_ct[5] ^= 0xFF
                encrypted['ciphertext_bytes'] = bytes(tampered_ct)
                encrypted['ciphertext']        = bytes(tampered_ct).hex()

        self._stats['total'] += 1

        try:
            decrypted = self._dec.decrypt(encrypted)
        except InvalidTag:
            self._record_reject(encrypted, 'aead_failed')
            result = self._make_result(
                encrypted, 'REJECT', 'aead_failed'
            )
            result['attack_injected'] = attack_type
            self._recent_packets.append(result)
            return result

        integrity = self._relay_checker.check(decrypted)
        if not integrity.passed:
            self._record_reject(decrypted, 'integrity_failed')
            result = self._make_result(
                decrypted, 'REJECT', 'integrity_failed'
            )
            result['attack_injected'] = attack_type
            self._recent_packets.append(result)
            return result

        if attack_type == 'forge':
            decrypted = dict(decrypted)
            decrypted['signature_bytes'] = os.urandom(64)
            decrypted['signature']       = (
                decrypted['signature_bytes'].hex()
            )

        try:
            reencrypted = self._reenc.reencrypt(decrypted)
        except Exception:
            result = self._make_result(
                decrypted, 'REJECT', 'reencrypt_failed'
            )
            result['attack_injected'] = attack_type
            self._recent_packets.append(result)
            return result

        try:
            plaintext = self._val_eng.decrypt(
                nonce=reencrypted['nonce_bytes'],
                ciphertext=reencrypted['ciphertext_bytes'],
                associated_data=reencrypted['header'],
            )
        except InvalidTag:
            self._record_reject(reencrypted, 'aead_failed')
            result = self._make_result(
                reencrypted, 'REJECT', 'aead_failed'
            )
            result['attack_injected'] = attack_type
            self._recent_packets.append(result)
            return result

        val_pkt = dict(reencrypted)
        val_pkt['payload_bytes'] = plaintext
        val_pkt['original_node'] = encrypted.get('node_id', 'unknown')

        seq_result = self._val_checker.check(val_pkt)
        if not seq_result.passed:
            self._record_reject(val_pkt, 'sequence_failed')
            result = self._make_result(
                val_pkt, 'REJECT', 'sequence_failed'
            )
            result['attack_injected'] = attack_type
            self._recent_packets.append(result)
            return result

        try:
            self._sig_verifier.verify(val_pkt)
        except (InvalidSignature, SignatureVerificationError):
            self._record_reject(val_pkt, 'sig_failed')
            result = self._make_result(
                val_pkt, 'REJECT', 'sig_failed'
            )
            result['attack_injected'] = attack_type
            self._recent_packets.append(result)
            return result

        result = self._make_result(
            val_pkt, 'ACCEPT', 'all_checks_passed'
        )
        result['attack_injected'] = attack_type
        self._recent_packets.append(result)
        self._stats['accepted'] += 1
        return result

    def _make_result(
        self,
        pkt:      dict,
        decision: str,
        reason:   str,
    ) -> dict:
        return {
            'sequence_no':    pkt.get('sequence_no', 0),
            'team':           pkt.get('team', ''),
            'session':        pkt.get('session', ''),
            'driver':         pkt.get('driver', 'UNK'),
            'node_id':        pkt.get(
                'node_id', pkt.get('original_node', '')
            ),
            'decision':       decision,
            'reason':         reason,
            'timestamp':      datetime.now(timezone.utc).isoformat(),
            'payload_json':   pkt.get('payload_json', {}),
            'anomaly_result': pkt.get('anomaly_result', {}),
        }

    def _record_reject(self, pkt: dict, reason: str) -> None:
        self._stats['rejected'] += 1
        evt = {
            'timestamp':   datetime.now(timezone.utc).isoformat(),
            'decision':    'REJECT',
            'sequence_no': pkt.get('sequence_no', 0),
            'reason':      reason,
        }
        self._audit_events.append(evt)

    # ── Getters ───────────────────────────────────────────────────

    def get_recent_packets(self, limit: int = 20) -> list:
        return self._recent_packets[-limit:]

    def get_stats(self) -> dict:
        total = self._stats['total']
        return {
            **self._stats,
            'accept_rate': (
                self._stats['accepted'] / total
                if total > 0 else 0
            ),
        }

    def get_crypto_stats(self) -> dict:
        self._crypto_stats['key_age_s'] = (
            time.time() - self._session_start
        )
        return dict(self._crypto_stats)

    def get_anomaly_stats(self) -> dict:
        return dict(self._anomaly_stats)

    def get_audit_events(self, limit: int = 20) -> list:
        return self._audit_events[-limit:]

    def get_pipeline_status(self) -> str:
        return "ACTIVE" if self._initialised else "IDLE"

    def get_data_rows(self) -> int:
        return self._data_rows

    def get_chart_history(self) -> dict:
        return dict(self._chart_history)

    def get_available_drivers(self) -> list:
        if self._sim is not None:
            return self._sim.available_drivers
        return []

    def get_available_laps(self) -> list:
        if self._sim is not None:
            return self._sim.available_laps
        return []

    def reset(self) -> None:
        self._reset_state()