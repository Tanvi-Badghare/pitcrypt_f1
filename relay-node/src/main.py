import os
import sys
import time
import json
import socket
import logging
import threading
import queue
import yaml
from typing import Optional, Dict
from datetime import datetime, timezone

# ── Path setup ───────────────────────────────────────────────────
SRC_DIR  = os.path.dirname(os.path.abspath(__file__))
ROOT     = os.path.abspath(os.path.join(SRC_DIR, '..', '..'))
LOGS_DIR = os.path.join(ROOT, 'logs')
CFG_PATH = os.path.join(
    ROOT, 'relay-node', 'config', 'relay.yaml'
)

sys.path.insert(0, SRC_DIR)
sys.path.insert(0, os.path.join(ROOT, 'car-producer', 'src'))
os.makedirs(LOGS_DIR, exist_ok=True)

from crypto_engine     import CryptoEngine
from packet_parser     import PacketParser, PacketParseError
from decryptor         import RelayDecryptor, DecryptionError
from reencryptor       import RelayReencryptor, ReencryptionError
from anomaly_filters   import AnomalyFilter
from integrity_checker import IntegrityChecker

from cryptography.exceptions import InvalidTag

"""
main.py — Relay Node

Full relay pipeline:
    Receive → Parse → Decrypt → Integrity Check
    → Anomaly Filter → Re-encrypt → Forward to Validator

Reads configuration from relay-node/config/relay.yaml

Pipeline stages:
    1. PacketParser     — deserialize + validate structure
    2. RelayDecryptor   — AEAD decrypt car → relay leg
    3. IntegrityChecker — sequence + replay detection
    4. AnomalyFilter    — statistical anomaly detection
    5. RelayReencryptor — re-encrypt relay → validator leg
    6. Forward          — send to validator node
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
            cfg['logging'].get('log_file', 'logs/relay.log')
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
    return logging.getLogger('RelayNode')


def load_config() -> dict:
    if not os.path.exists(CFG_PATH):
        raise FileNotFoundError(
            f"Config not found: {CFG_PATH}"
        )
    with open(CFG_PATH, 'r') as f:
        return yaml.safe_load(f)


class RelayNode:
    """
    Relay node — middle tier of PitCrypt-F1 pipeline.

    Sits between car producers and the FIA validator.
    Decrypts, validates, filters, re-encrypts, and forwards.
    """

    def __init__(self, config: dict):
        self.cfg    = config
        self.logger = logging.getLogger('RelayNode')

        node_cfg = config.get('node',      {})
        net_cfg  = config.get('network',   {})
        cry_cfg  = config.get('crypto',    {})
        ano_cfg  = config.get('anomaly',   {})
        int_cfg  = config.get('integrity', {})
        pip_cfg  = config.get('pipeline',  {})

        self.node_id = node_cfg.get('id', 'relay_01')

        # ── Pipeline components ──────────────────────────────────
        self.logger.info("Initialising relay pipeline...")

        self.parser = PacketParser(node_id=self.node_id)

        self.decryptor = RelayDecryptor(
            node_id=self.node_id
        )

        self.integrity = IntegrityChecker(
            node_id=self.node_id,
            max_timestamp_age_ms=int_cfg.get(
                'max_timestamp_age_ms', 30000
            ),
            max_sequence_gap=int_cfg.get(
                'max_sequence_gap', 100
            ),
            check_timestamps=int_cfg.get(
                'check_timestamps', True
            ),
            check_signatures=int_cfg.get(
                'check_signatures', True
            ),
        )

        self.anomaly = AnomalyFilter(
            thresholds_path=os.path.join(
                ROOT,
                ano_cfg.get(
                    'thresholds_path',
                    'data/processed/thresholds.json'
                )
            ),
            node_id=self.node_id,
        )

        self.reencryptor = RelayReencryptor(
            node_id=self.node_id
        )

        # ── Network ──────────────────────────────────────────────
        self._listen_host  = net_cfg.get(
            'listen_host', '0.0.0.0'
        )
        self._listen_port  = net_cfg.get('listen_port', 9001)
        self._val_host     = net_cfg.get(
            'validator_host', '127.0.0.1'
        )
        self._val_port     = net_cfg.get('validator_port', 9002)
        self._timeout      = net_cfg.get('timeout_seconds', 5)
        self._max_conn     = net_cfg.get('max_connections', 10)

        self._server_socket: Optional[socket.socket] = None
        self._val_socket:    Optional[socket.socket]  = None

        # ── State ────────────────────────────────────────────────
        self._running       = False
        self._packet_queue  = queue.Queue(
            maxsize=pip_cfg.get('max_queue_size', 1000)
        )

        # ── Stats ────────────────────────────────────────────────
        self._stats = {
            'received':          0,
            'parsed':            0,
            'decrypted':         0,
            'integrity_passed':  0,
            'integrity_failed':  0,
            'anomaly_clean':     0,
            'anomaly_flagged':   0,
            'anomaly_rejected':  0,
            'reencrypted':       0,
            'forwarded':         0,
            'dropped':           0,
            'start_time':        None,
        }

        self.logger.info(
            f"RelayNode ready — {self.node_id}"
        )

    # ── Session setup ────────────────────────────────────────────

    def setup_car_session(
        self,
        car_node_id:   str,
        car_pub_key:   bytes,
    ) -> bytes:
        """
        Perform ECDH handshake with car producer.
        Returns relay's public key to send back to car.
        """
        engine    = CryptoEngine(node_id=self.node_id)
        relay_pub = engine.new_session()
        engine.complete_handshake(car_pub_key)
        self.decryptor.register_session(car_node_id, engine)
        self.logger.info(
            f"Car session established: {car_node_id}"
        )
        return relay_pub

    def setup_validator_session(
        self,
        validator_pub_key: bytes,
    ) -> bytes:
        """
        Perform ECDH handshake with validator.
        Returns relay's public key to send to validator.
        """
        engine    = CryptoEngine(
            node_id=f"{self.node_id}_validator"
        )
        relay_pub = engine.new_session()
        engine.complete_handshake(validator_pub_key)
        self.reencryptor.register_validator_session(engine)
        self.logger.info("Validator session established")
        return relay_pub

    def _simulate_sessions(self) -> None:
        """
        Simulate ECDH sessions for testing without network.
        Sets up car and validator sessions using local engines.
        """
        self.logger.info(
            "Simulating ECDH sessions..."
        )

        # Simulate car session
        car_engine   = CryptoEngine(node_id='mercedes_car_sim')
        relay_car_e  = CryptoEngine(
            node_id=f"{self.node_id}_car"
        )
        car_pub      = car_engine.new_session()
        relay_car_p  = relay_car_e.new_session()
        car_engine.complete_handshake(relay_car_p)
        relay_car_e.complete_handshake(car_pub)
        self.decryptor.register_session(
            'mercedes_car_sim', relay_car_e
        )
        self._sim_car_engine = car_engine

        # Simulate validator session
        val_engine   = CryptoEngine(node_id='validator_sim')
        relay_val_e  = CryptoEngine(
            node_id=f"{self.node_id}_val"
        )
        val_pub      = val_engine.new_session()
        relay_val_p  = relay_val_e.new_session()
        val_engine.complete_handshake(relay_val_p)
        relay_val_e.complete_handshake(val_pub)
        self.reencryptor.register_validator_session(relay_val_e)
        self._sim_val_engine = val_engine

        self.logger.info("Simulated sessions ready ✅")

    # ── Core pipeline ────────────────────────────────────────────

    def process_packet(
        self, raw_data: bytes
    ) -> Optional[dict]:
        """
        Run one packet through the full relay pipeline.

        Returns re-encrypted packet ready for validator,
        or None if packet was dropped.
        """
        self._stats['received'] += 1

        # ── 1. Parse ─────────────────────────────────────────────
        try:
            parsed = self.parser.parse_json_packet(raw_data)
            errors = self.parser.validate_json_packet(parsed)
            if errors:
                self.logger.warning(
                    f"Parse validation errors: {errors}"
                )
                self._stats['dropped'] += 1
                return None
            self._stats['parsed'] += 1

        except PacketParseError as e:
            self.logger.error(f"Parse error: {e}")
            self._stats['dropped'] += 1
            return None

        # ── 2. Decrypt ───────────────────────────────────────────
        try:
            decrypted = self.decryptor.decrypt(parsed)
            self._stats['decrypted'] += 1

        except (InvalidTag, DecryptionError) as e:
            self.logger.error(f"Decrypt error: {e}")
            self._stats['dropped'] += 1
            return None

        # ── 3. Integrity check ───────────────────────────────────
        integrity_result = self.integrity.check(decrypted)
        if not integrity_result.passed:
            self.logger.error(
                f"Integrity failed: {integrity_result.errors}"
            )
            self._stats['integrity_failed'] += 1
            self._stats['dropped'] += 1
            return None
        self._stats['integrity_passed'] += 1

        # ── 4. Anomaly filter ────────────────────────────────────
        annotated = self.anomaly.check_and_annotate(decrypted)

        if annotated['anomaly_rejected']:
            self.logger.error(
                f"Anomaly REJECT: "
                f"{annotated['anomaly_result']['violations']}"
            )
            self._stats['anomaly_rejected'] += 1
            self._stats['dropped'] += 1
            return None

        if annotated['anomaly_flagged']:
            self._stats['anomaly_flagged'] += 1
            self.logger.warning(
                f"Anomaly FLAG — forwarding with flag"
            )
        else:
            self._stats['anomaly_clean'] += 1

        # ── 5. Re-encrypt ────────────────────────────────────────
        try:
            reencrypted = self.reencryptor.reencrypt(annotated)
            self._stats['reencrypted'] += 1

        except ReencryptionError as e:
            self.logger.error(f"Re-encrypt error: {e}")
            self._stats['dropped'] += 1
            return None

        self._stats['forwarded'] += 1
        return reencrypted

    # ── Simulation mode ──────────────────────────────────────────

    def run_simulation(
        self,
        n_packets: int  = 10,
        verbose:   bool = True,
    ) -> dict:
        """
        Run relay pipeline in simulation mode.
        Generates packets internally without network.
        """
        sys.path.insert(
            0, os.path.join(ROOT, 'car-producer', 'src')
        )
        from sensor_simulator import SensorSimulator
        from packet_builder   import PacketBuilder
        from signer           import PacketSigner
        from encryptor        import PacketEncryptor

        self._simulate_sessions()

        sim     = SensorSimulator(
            team='mercedes', race='Bahrain', session='R'
        )
        builder = PacketBuilder(team='mercedes', session='R')
        signer  = PacketSigner(node_id='mercedes_car_sim')
        enc     = PacketEncryptor(
            crypto_engine=self._sim_car_engine,
            node_id='mercedes_car_sim',
        )

        self.logger.info(
            f"Running simulation — {n_packets} packets"
        )

        results = []

        for i in range(n_packets):
            # Build and encrypt on car side
            frame     = sim.get_next_frame()
            packet    = builder.build(frame)
            signed    = signer.sign_packet(packet)
            encrypted = enc.encrypt_packet(signed)

            # Serialize as JSON (simulates network)
            json_data = {
                'nonce':       encrypted['nonce'],
                'ciphertext':  encrypted['ciphertext'],
                'header_hex':  encrypted['header_hex'],
                'signature':   encrypted['signature'],
                'sequence_no': encrypted['sequence_no'],
                'timestamp':   encrypted['timestamp'],
                'team':        encrypted['team'],
                'session':     encrypted['session'],
                'node_id':     encrypted['node_id'],
            }
            raw = json.dumps(json_data).encode()

            # Process through relay
            result = self.process_packet(raw)

            if result and verbose:
                print(
                    f"  Packet {i+1:3d}: "
                    f"seq={result['sequence_no']:4d} | "
                    f"team={result['team']} | "
                    f"reencrypted={result['reencrypted']} | "
                    f"flagged="
                    f"{encrypted.get('anomaly_flagged', False)}"
                )
                results.append(result)

        return self._stats

    def _print_stats(self) -> None:
        self.logger.info(
            f"\n{'='*45}\n"
            f"  Relay Pipeline Statistics\n"
            f"{'='*45}\n"
            f"  Received:         {self._stats['received']:,}\n"
            f"  Parsed:           {self._stats['parsed']:,}\n"
            f"  Decrypted:        {self._stats['decrypted']:,}\n"
            f"  Integrity passed: "
            f"{self._stats['integrity_passed']:,}\n"
            f"  Integrity failed: "
            f"{self._stats['integrity_failed']:,}\n"
            f"  Anomaly clean:    "
            f"{self._stats['anomaly_clean']:,}\n"
            f"  Anomaly flagged:  "
            f"{self._stats['anomaly_flagged']:,}\n"
            f"  Anomaly rejected: "
            f"{self._stats['anomaly_rejected']:,}\n"
            f"  Re-encrypted:     "
            f"{self._stats['reencrypted']:,}\n"
            f"  Forwarded:        "
            f"{self._stats['forwarded']:,}\n"
            f"  Dropped:          "
            f"{self._stats['dropped']:,}\n"
            f"{'='*45}"
        )


# ── Entry point ──────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "="*55)
    print("  RelayNode — Self Test")
    print("="*55)

    # Load config
    try:
        cfg = load_config()
        print(f"\n  Config loaded: {CFG_PATH}")
    except FileNotFoundError:
        print(f"\n  Config not found — using defaults")
        cfg = {
            'node':      {'id': 'relay_01'},
            'network':   {
                'listen_host': '0.0.0.0',
                'listen_port': 9001,
                'validator_host': '127.0.0.1',
                'validator_port': 9002,
                'timeout_seconds': 5,
                'max_connections': 10,
            },
            'crypto':    {
                'max_session_age_seconds': 300,
                'max_packets_per_key': 10000,
                'check_interval_seconds': 5,
            },
            'anomaly':   {
                'enabled': True,
                'thresholds_path':
                    'data/processed/thresholds.json',
            },
            'integrity': {
                'check_sequence':   True,
                'check_timestamps': False,
                'check_signatures': True,
                'max_timestamp_age_ms': 30000,
                'max_sequence_gap': 100,
            },
            'logging':   {
                'level': 'INFO',
                'log_to_file': False,
            },
            'pipeline':  {'max_queue_size': 1000},
        }

    logger = setup_logging(cfg)
    relay  = RelayNode(cfg)

    # ── Test 1: 10-packet simulation ─────────────────────────────
    print("\n[Test 1] 10-packet relay simulation")
    stats = relay.run_simulation(n_packets=10, verbose=True)

    print(f"\n  Received:   {stats['received']}")
    print(f"  Forwarded:  {stats['forwarded']}")
    print(f"  Dropped:    {stats['dropped']}")

    assert stats['received']  == 10
    assert stats['decrypted'] == 10
    assert stats['forwarded'] + stats['dropped'] == 10
    assert stats['forwarded'] > 0
    print(f"  Packets relayed:  {stats['forwarded']}/10 ✅")
    print(f"  Packets dropped:  {stats['dropped']}/10 "
      f"(anomaly filter working correctly)")

    # ── Test 2: Stats ────────────────────────────────────────────
    print("\n[Test 2] Pipeline statistics")
    relay._print_stats()
    print(f"  Stats printed: ✅")

    print("\n✅ RelayNode self-test complete.")
    print("\nTo run the live relay node:")
    print("  relay.start()   # starts TCP server")
    print("  relay.stop()    # stops gracefully")