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
from audit_logger       import AuditLogger, AuditDecision
from cryptography.exceptions import InvalidSignature, InvalidTag

logging.basicConfig(level=logging.WARNING)

"""
telemetry_feed.py

Live telemetry feed component for the PitCrypt-F1 dashboard.

Manages the complete pipeline:
    Car → Relay → Validator

Provides methods for the dashboard to:
    - Initialise pipeline for a team/race/session
    - Process one packet through the full pipeline
    - Get recent packets, stats, crypto health
    - Get audit events and anomaly statistics
"""


class TelemetryFeed:
    """
    Manages live telemetry pipeline for dashboard.
    Wraps car → relay → validator pipeline components.
    """

    def __init__(self):
        self._initialised = False
        self._reset_state()

    def _reset_state(self):
        """Reset all pipeline state."""
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

        # Crypto metadata
        self._car_engine    = None
        self._relay_engine  = None
        self._relay_val_eng = None
        self._session_start = time.time()
        self._packet_count  = 0

        # Packet buffer
        self._recent_packets = []
        self._audit_events   = []

        # Stats
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
            'car_key':     '0' * 32,
            'val_key':     '0' * 32,
            'encrypted':   0,
            'reencrypted': 0,
            'signatures':  0,
            'zkp_verified': 0,
            'key_age_s':   0,
        }

        self._data_rows   = 0
        self._initialised = False

    def initialise(
        self,
        team:    str = 'mercedes',
        race:    str = 'Bahrain',
        session: str = 'R',
    ) -> None:
        """
        Initialise full pipeline for given team/race/session.
        Performs ECDH handshakes on both legs.
        """
        self._reset_state()

        # ── Sensor + builder + signer ─────────────────────────────
        self._sim = SensorSimulator(
            team=team, race=race, session=session,
            add_noise=False, inject_anomalies=False,
        )
        self._data_rows = len(self._sim._df)
        self._builder   = PacketBuilder(
            team=team, session=session
        )
        self._signer    = PacketSigner(
            node_id=f'{team}_car'
        )

        # ── Car → Relay ECDH ──────────────────────────────────────
        self._car_engine   = CryptoEngine(
            node_id=f'{team}_car'
        )
        self._relay_engine = CryptoEngine(
            node_id='relay_01'
        )
        cp = self._car_engine.new_session()
        rp = self._relay_engine.new_session()
        self._car_engine.complete_handshake(rp)
        self._relay_engine.complete_handshake(cp)

        # ── Relay → Validator ECDH ────────────────────────────────
        self._relay_val_eng = CryptoEngine(
            node_id='relay_val'
        )
        self._val_eng = CryptoEngine(
            node_id='fia_validator'
        )
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
        self._reenc.register_validator_session(
            self._relay_val_eng
        )
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

        # ── Crypto stats seed ─────────────────────────────────────
        car_key = self._car_engine._session.session_key
        val_key = self._val_eng._session.session_key
        self._crypto_stats['car_key'] = car_key.hex()
        self._crypto_stats['val_key'] = val_key.hex()
        self._session_start           = time.time()
        self._stats['start_time']     = time.time()
        self._initialised             = True

    def process_one_packet(self) -> Optional[dict]:
        """
        Process one telemetry packet through full pipeline.
        Returns result dict or None if not initialised.
        """
        if not self._initialised:
            return None

        team_id = (
            self._builder._team_id_str.lower()
            if hasattr(self._builder, '_team_id_str')
            else 'mercedes'
        )

        try:
            # ── Car side ─────────────────────────────────────────
            frame  = self._sim.get_next_frame()
            packet = self._builder.build(frame)
            signed = self._signer.sign_packet(packet)
            commit = ZKPVerifier.generate_commitment(
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
                self._record_reject(
                    decrypted, 'integrity_failed'
                )
                return self._make_result(
                    decrypted, 'REJECT', 'integrity_failed'
                )

            annotated = self._anomaly.check_and_annotate(
                decrypted
            )
            self._anomaly_stats['checked'] += 1

            if annotated['anomaly_rejected']:
                self._anomaly_stats['rejected'] += 1
                self._record_reject(
                    decrypted, 'anomaly_rejected'
                )
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

            # Signature verify
            try:
                self._sig_verifier.verify(val_pkt)
                self._crypto_stats['signatures'] += 1
            except (
                InvalidSignature,
                SignatureVerificationError,
            ) as e:
                self._record_reject(val_pkt, 'sig_failed')
                return self._make_result(
                    val_pkt, 'REJECT', 'sig_failed'
                )

            # Sequence check
            seq_result = self._val_checker.check(val_pkt)
            if not seq_result.passed:
                self._record_reject(
                    val_pkt, 'sequence_failed'
                )
                return self._make_result(
                    val_pkt, 'REJECT', 'sequence_failed'
                )

            # ZKP
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

            self._stats['total'] += 1
            self._packet_count   += 1

            # Update key age
            self._crypto_stats['key_age_s'] = (
                time.time() - self._session_start
            )

            result = self._make_result(
                val_pkt, decision, 'all_checks_passed'
            )
            result['payload_json'] = frame
            result['anomaly_flagged'] = (
                annotated['anomaly_flagged']
            )

            # Store in buffer
            self._recent_packets.append(result)
            if len(self._recent_packets) > 100:
                self._recent_packets.pop(0)

            # Store audit event
            audit_evt = {
                'timestamp':   datetime.now(
                    timezone.utc
                ).isoformat(),
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

    def _make_result(
        self,
        pkt:      dict,
        decision: str,
        reason:   str,
    ) -> dict:
        """Build result dict for dashboard."""
        return {
            'sequence_no': pkt.get('sequence_no', 0),
            'team':        pkt.get('team', ''),
            'session':     pkt.get('session', ''),
            'node_id':     pkt.get(
                'node_id',
                pkt.get('original_node', '')
            ),
            'decision':    decision,
            'reason':      reason,
            'timestamp':   datetime.now(
                timezone.utc
            ).isoformat(),
            'payload_json': pkt.get('payload_json', {}),
        }

    def _record_reject(
        self, pkt: dict, reason: str
    ) -> None:
        """Record a rejection."""
        self._stats['rejected'] += 1
        self._stats['total']    += 1

        evt = {
            'timestamp':   datetime.now(
                timezone.utc
            ).isoformat(),
            'decision':    'REJECT',
            'sequence_no': pkt.get('sequence_no', 0),
            'reason':      reason,
        }
        self._audit_events.append(evt)

    # ── Getters ───────────────────────────────────────────────────

    def get_recent_packets(
        self, limit: int = 20
    ) -> list:
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

    def get_audit_events(
        self, limit: int = 20
    ) -> list:
        return self._audit_events[-limit:]

    def get_pipeline_status(self) -> str:
        return "ACTIVE" if self._initialised else "IDLE"

    def get_data_rows(self) -> int:
        return self._data_rows

    def reset(self) -> None:
        self._reset_state()