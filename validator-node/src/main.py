import os
import sys
import json
import socket
import logging
import threading
import queue
import yaml
from typing import Optional
from datetime import datetime, timezone

# ── Path setup ───────────────────────────────────────────────────
SRC_DIR  = os.path.dirname(os.path.abspath(__file__))
ROOT     = os.path.abspath(os.path.join(SRC_DIR, '..', '..'))
LOGS_DIR = os.path.join(ROOT, 'logs')
CFG_PATH = os.path.join(
    ROOT, 'validator-node', 'config', 'validator.yaml'
)

sys.path.insert(0, SRC_DIR)
sys.path.insert(0, os.path.join(ROOT, 'car-producer', 'src'))
sys.path.insert(0, os.path.join(ROOT, 'relay-node',   'src'))
os.makedirs(LOGS_DIR, exist_ok=True)

from crypto_engine        import CryptoEngine
from signature_verifier   import (
    ValidatorSignatureVerifier,
    SignatureVerificationError,
)
from sequence_checker     import ValidatorSequenceChecker
from zkp_verifier         import ZKPVerifier
from audit_logger         import AuditLogger, AuditDecision

from cryptography.exceptions import InvalidSignature

"""
main.py — FIA Validator Node

Final verification pipeline:
    Receive → Decrypt → Signature Verify
    → Sequence Check → ZKP Verify → Audit Log → Accept/Reject

This is the authoritative FIA endpoint.
Every packet decision is logged to the audit trail.
No packet is accepted without passing ALL checks.

Pipeline stages:
    1. Decrypt          — relay → validator ECDH leg
    2. SignatureVerifier — Ed25519 car signature check
    3. SequenceChecker  — replay and ordering defence
    4. ZKPVerifier      — commitment integrity check
    5. AuditLogger      — immutable decision record
"""


def setup_logging(cfg: dict) -> logging.Logger:
    level = getattr(
        logging,
        cfg.get('logging', {}).get('level', 'INFO')
    )
    handlers = [logging.StreamHandler()]

    if cfg.get('logging', {}).get('log_to_file', False):
        log_file = os.path.join(
            ROOT,
            cfg['logging'].get(
                'log_file', 'logs/validator.log'
            )
        )
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format=(
            "%(asctime)s — %(name)s — "
            "%(levelname)s — %(message)s"
        ),
        handlers=handlers,
    )
    return logging.getLogger('ValidatorNode')


def load_config() -> dict:
    if not os.path.exists(CFG_PATH):
        raise FileNotFoundError(
            f"Config not found: {CFG_PATH}"
        )
    with open(CFG_PATH, 'r') as f:
        return yaml.safe_load(f)


class ValidatorNode:
    """
    FIA Validator Node — final pipeline authority.

    Receives re-encrypted packets from relay node,
    decrypts, verifies, and logs every decision.
    """

    def __init__(self, config: dict):
        self.cfg    = config
        self.logger = logging.getLogger('ValidatorNode')

        node_cfg = config.get('node',      {})
        sig_cfg  = config.get('signature', {})
        seq_cfg  = config.get('sequence',  {})
        zkp_cfg  = config.get('zkp',       {})
        aud_cfg  = config.get('audit',     {})
        pip_cfg  = config.get('pipeline',  {})
        net_cfg  = config.get('network',   {})

        self.node_id = node_cfg.get('id', 'fia_validator')

        # ── Pipeline components ──────────────────────────────────
        self.logger.info(
            "Initialising validator pipeline..."
        )

        # Signature verifier
        self.sig_verifier = ValidatorSignatureVerifier(
            node_id=self.node_id
        )

        # Sequence checker
        self.seq_checker = ValidatorSequenceChecker(
            node_id=self.node_id,
            max_timestamp_age_ms=seq_cfg.get(
                'max_timestamp_age_ms', 60000
            ),
            max_sequence_gap=seq_cfg.get(
                'max_sequence_gap', 1000
            ),
            check_timestamps=seq_cfg.get(
                'check_timestamps', False
            ),
            strict_ordering=seq_cfg.get(
                'strict_ordering', True
            ),
        )

        # ZKP verifier
        self.zkp_verifier = ZKPVerifier(
            node_id=self.node_id
        )

        # Audit logger
        self.audit = AuditLogger(
            node_id=self.node_id,
            log_to_file=aud_cfg.get('log_to_file', True),
            log_file=os.path.join(
                ROOT,
                aud_cfg.get(
                    'log_file',
                    'logs/validator_audit.jsonl'
                )
            ),
            alert_on_reject=aud_cfg.get(
                'alert_on_reject', True
            ),
        )

        # Validator ECDH engine
        self._val_engine: Optional[CryptoEngine] = None

        # Network
        self._listen_host = net_cfg.get(
            'listen_host', '0.0.0.0'
        )
        self._listen_port = net_cfg.get('listen_port', 9002)

        # State
        self._running      = False
        self._packet_queue = queue.Queue(
            maxsize=pip_cfg.get('max_queue_size', 500)
        )

        # Stats
        self._stats = {
            'received':   0,
            'accepted':   0,
            'rejected':   0,
            'flagged':    0,
            'sig_failed': 0,
            'seq_failed': 0,
            'zkp_failed': 0,
            'start_time': None,
        }

        self.logger.info(
            f"ValidatorNode ready — {self.node_id}"
        )

    # ── Session setup ────────────────────────────────────────────

    def register_car_node(
        self,
        node_id:          str,
        public_key_bytes: bytes,
    ) -> None:
        """Register a car node's Ed25519 public key."""
        self.sig_verifier.register_node(
            node_id, public_key_bytes
        )
        self.logger.info(
            f"Car node registered: {node_id}"
        )

    def setup_relay_session(
        self,
        relay_pub_key: bytes,
    ) -> bytes:
        """
        ECDH handshake with relay node.
        Returns validator's public key.
        """
        self._val_engine = CryptoEngine(
            node_id=self.node_id
        )
        val_pub = self._val_engine.new_session()
        self._val_engine.complete_handshake(relay_pub_key)
        self.logger.info("Relay session established ✅")
        return val_pub

    def _simulate_sessions(
        self,
        relay_val_engine: CryptoEngine,
        car_signers: dict,
    ) -> None:
        """
        Setup validator for simulation mode.

        Args:
            relay_val_engine: Relay's validator-leg engine
            car_signers:      {node_id: public_key_bytes}
        """
        # Setup ECDH with relay
        self._val_engine = CryptoEngine(
            node_id=self.node_id
        )
        val_pub  = self._val_engine.new_session()
        relay_pub = relay_val_engine.get_public_key_bytes()

        # Cross-handshake
        self._val_engine.complete_handshake(
            relay_val_engine.public_key_bytes
            if hasattr(relay_val_engine, 'public_key_bytes')
            else relay_pub
        )

        # Register car nodes
        for node_id, pub_key in car_signers.items():
            self.sig_verifier.register_node(
                node_id, pub_key
            )

        self.logger.info(
            "Validator simulation sessions ready ✅"
        )

    # ── Core pipeline ────────────────────────────────────────────

    def process_packet(
        self, reencrypted_packet: dict
    ) -> Optional[dict]:
        """
        Run one packet through the full validator pipeline.

        Args:
            reencrypted_packet: dict from relay reencryptor
                                containing nonce_bytes,
                                ciphertext_bytes, header,
                                signature, original_node

        Returns:
            Accepted packet dict or None if rejected
        """
        self._stats['received'] += 1

        # ── 1. Decrypt relay → validator leg ─────────────────────
        if self._val_engine is None:
            self.logger.error("No validator session")
            self._reject(
                reencrypted_packet,
                'no_session',
            )
            return None

        try:
            plaintext = self._val_engine.decrypt(
                nonce=reencrypted_packet['nonce_bytes'],
                ciphertext=reencrypted_packet[
                    'ciphertext_bytes'
                ],
                associated_data=reencrypted_packet.get(
                    'header'
                ),
            )
        except Exception as e:
            self.logger.error(f"Decrypt failed: {e}")
            self._reject(
                reencrypted_packet,
                'decryption_failed',
                {'error': str(e)},
            )
            return None

        # Build validator packet
        packet = dict(reencrypted_packet)
        packet['payload_bytes'] = plaintext

        try:
            import json as _json
            packet['payload_json'] = _json.loads(
                plaintext.decode('utf-8')
            )
        except Exception:
            packet['payload_json'] = {}

        # ── 2. Signature verification ─────────────────────────────
        try:
            sig_result = self.sig_verifier.verify(packet)
            packet['signature_result'] = sig_result

        except (SignatureVerificationError, InvalidSignature) as e:
            self._stats['sig_failed'] += 1
            self._reject(
                packet,
                'signature_invalid',
                {'error': str(e)},
            )
            return None

        # ── 3. Sequence check ────────────────────────────────────
        seq_result = self.seq_checker.check(packet)
        packet['sequence_result'] = seq_result.to_dict()

        if not seq_result.passed:
            self._stats['seq_failed'] += 1
            self._reject(
                packet,
                'sequence_invalid',
                {'errors': seq_result.errors},
            )
            return None

        # ── 4. ZKP verification ──────────────────────────────────
        zkp_result = self.zkp_verifier.verify_packet(packet)
        packet['zkp_result'] = zkp_result.to_dict()

        if not zkp_result.verified:
            self._stats['zkp_failed'] += 1
            self._reject(
                packet,
                'zkp_invalid',
                {'reason': zkp_result.reason},
            )
            return None

        # ── 5. Accept ────────────────────────────────────────────
        has_warnings = bool(seq_result.warnings)

        if has_warnings:
            self._stats['flagged'] += 1
            self.audit.log_flag(
                packet,
                reason='sequence_warnings',
                details={'warnings': seq_result.warnings},
            )
        else:
            self._stats['accepted'] += 1
            self.audit.log_accept(
                packet,
                reason='all_checks_passed',
                details={
                    'sig':      'valid',
                    'sequence': 'valid',
                    'zkp':      zkp_result.reason,
                },
            )

        self.logger.info(
            f"✅ ACCEPTED — "
            f"seq={packet.get('sequence_no')} "
            f"node={packet.get('original_node')} "
            f"team={packet.get('team')}"
        )
        return packet

    def _reject(
        self,
        packet:  dict,
        reason:  str,
        details: Optional[dict] = None,
    ) -> None:
        """Log rejection and update stats."""
        self._stats['rejected'] += 1
        self.audit.log_reject(
            packet, reason=reason, details=details
        )

    # ── Simulation mode ──────────────────────────────────────────

    def run_simulation(
        self,
        n_packets: int  = 10,
        verbose:   bool = True,
    ) -> dict:
        """Run validator in simulation mode."""
        from sensor_simulator import SensorSimulator
        from packet_builder   import PacketBuilder
        from signer           import PacketSigner
        from encryptor        import PacketEncryptor
        from decryptor        import RelayDecryptor
        from reencryptor      import RelayReencryptor

        self.logger.info(
            f"Starting simulation — {n_packets} packets"
        )

        # ── Full pipeline setup ──────────────────────────────────
        sim     = SensorSimulator(
            team='mercedes', race='Bahrain', session='R',
            add_noise=False,
        )
        builder = PacketBuilder(
            team='mercedes', session='R'
        )
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
        self._val_engine = CryptoEngine(
            node_id=self.node_id
        )
        rvp = relay_val.new_session()
        vp  = self._val_engine.new_session()
        relay_val.complete_handshake(vp)
        self._val_engine.complete_handshake(rvp)

        # Register car node
        self.sig_verifier.register_node(
            'mercedes_car', signer.public_key_bytes
        )

        # Components
        enc   = PacketEncryptor(
            crypto_engine=car_eng,
            node_id='mercedes_car',
        )
        dec   = RelayDecryptor(node_id='relay_01')
        dec.register_session('mercedes_car', relay_eng)
        reenc = RelayReencryptor(node_id='relay_01')
        reenc.register_validator_session(relay_val)

        self._stats['start_time'] = datetime.now(
            timezone.utc
        ).isoformat()

        # ── Run pipeline ─────────────────────────────────────────
        for i in range(n_packets):
            frame   = sim.get_next_frame()
            packet  = builder.build(frame)
            signed  = signer.sign_packet(packet)

            # ZKP commitment on car side
            commit  = ZKPVerifier.generate_commitment(
                signed['payload']
            )

            encrypted   = enc.encrypt_packet(signed)
            decrypted   = dec.decrypt(encrypted)
            reencrypted = reenc.reencrypt(decrypted)

            # Add ZKP fields for validator
            reencrypted['zkp_commitment'] = (
                commit['commitment']
            )
            reencrypted['zkp_nonce']      = commit['nonce']

            result = self.process_packet(reencrypted)

            if result and verbose:
                print(
                    f"  Packet {i+1:3d}: "
                    f"seq={result.get('sequence_no'):4d} | "
                    f"team={result.get('team')} | "
                    f"sig=✅ seq=✅ zkp=✅"
                )

        return self._stats

    def _print_stats(self) -> None:
        self.logger.info(
            f"\n{'='*45}\n"
            f"  Validator Pipeline Statistics\n"
            f"{'='*45}\n"
            f"  Received:    {self._stats['received']:,}\n"
            f"  Accepted:    {self._stats['accepted']:,}\n"
            f"  Flagged:     {self._stats['flagged']:,}\n"
            f"  Rejected:    {self._stats['rejected']:,}\n"
            f"  Sig failed:  {self._stats['sig_failed']:,}\n"
            f"  Seq failed:  {self._stats['seq_failed']:,}\n"
            f"  ZKP failed:  {self._stats['zkp_failed']:,}\n"
            f"{'='*45}"
        )


# ── Entry point ──────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "="*55)
    print("  ValidatorNode — Self Test")
    print("="*55)

    try:
        cfg = load_config()
        print(f"\n  Config loaded: {CFG_PATH}")
    except FileNotFoundError:
        print(f"\n  Config not found — using defaults")
        cfg = {
            'node':      {'id': 'fia_validator'},
            'network':   {
                'listen_host': '0.0.0.0',
                'listen_port': 9002,
                'timeout_seconds': 10,
                'max_connections': 5,
            },
            'signature': {
                'enabled': True,
                'reject_unknown_nodes': True,
            },
            'sequence':  {
                'check_timestamps': False,
                'strict_ordering':  True,
                'max_sequence_gap': 1000,
            },
            'zkp':       {
                'enabled':        True,
                'skip_if_missing': True,
            },
            'audit':     {
                'log_to_file':    True,
                'alert_on_reject': True,
            },
            'logging':   {
                'level':       'INFO',
                'log_to_file': False,
            },
            'pipeline':  {'max_queue_size': 500},
        }

    logger    = setup_logging(cfg)
    validator = ValidatorNode(cfg)

    # ── Test 1: 10-packet simulation ─────────────────────────────
    print("\n[Test 1] 10-packet validator simulation")
    stats = validator.run_simulation(
        n_packets=10, verbose=True
    )

    print(f"\n  Received: {stats['received']}")
    print(f"  Accepted: {stats['accepted']}")
    print(f"  Rejected: {stats['rejected']}")

    assert stats['received'] == 10
    assert stats['accepted'] + stats['flagged'] == 10
    assert stats['rejected'] == 0
    print(f"  All 10 packets accepted: ✅")

    # ── Test 2: Audit summary ────────────────────────────────────
    print("\n[Test 2] Audit summary")
    summary = validator.audit.summary()
    print(f"  {summary}")
    assert summary['total'] == 10
    print(f"  Audit summary: ✅")

    # ── Test 3: Pipeline stats ───────────────────────────────────
    print("\n[Test 3] Pipeline statistics")
    validator._print_stats()
    print(f"  Stats: ✅")

    print("\n✅ ValidatorNode self-test complete.")
    print("\nTo run the live validator:")
    print("  validator.start()   # starts TCP server")
    print("  validator.stop()    # stops gracefully")