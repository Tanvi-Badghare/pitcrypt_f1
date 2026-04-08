import os
import sys
import time
import json
import socket
import logging
import threading
import queue
import yaml
from datetime import datetime, timezone
from typing import Optional

# ── Path setup ───────────────────────────────────────────────────
SRC_DIR  = os.path.dirname(os.path.abspath(__file__))
ROOT     = os.path.abspath(os.path.join(SRC_DIR, '..', '..'))
LOGS_DIR = os.path.join(ROOT, 'logs')
CFG_PATH = os.path.join(
    ROOT, 'car-producer', 'config', 'producer.yaml'
)

sys.path.insert(0, SRC_DIR)
os.makedirs(LOGS_DIR, exist_ok=True)

from sensor_simulator import SensorSimulator
from packet_builder   import PacketBuilder
from signer           import PacketSigner
from encryptor        import PacketEncryptor
from crypto_engine    import CryptoEngine
from key_scheduler    import KeyScheduler

"""
main.py — Car Producer Node

Full pipeline:
    SensorSimulator → PacketBuilder → PacketSigner
    → PacketEncryptor → Network transmit → Relay Node

Reads configuration from car-producer/config/producer.yaml

Pipeline stages:
    1. SensorSimulator  — streams real F1 telemetry frames
    2. PacketBuilder    — assembles binary packets with headers
    3. PacketSigner     — signs with Ed25519 identity key
    4. PacketEncryptor  — encrypts with ChaCha20-Poly1305
    5. Transmitter      — sends over TCP to relay node
    6. KeyScheduler     — rotates ECDH keys automatically
"""


def setup_logging(cfg: dict) -> logging.Logger:
    """Configure logging from config."""
    level = getattr(
        logging,
        cfg.get('logging', {}).get('level', 'INFO')
    )

    handlers = [logging.StreamHandler()]

    if cfg.get('logging', {}).get('log_to_file', False):
        log_file = os.path.join(
            ROOT,
            cfg['logging'].get('log_file', 'logs/car_producer.log')
        )
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s — %(name)s — %(levelname)s — %(message)s",
        handlers=handlers,
    )
    return logging.getLogger('CarProducer')


def load_config() -> dict:
    """Load producer.yaml configuration."""
    if not os.path.exists(CFG_PATH):
        raise FileNotFoundError(
            f"Config not found: {CFG_PATH}"
        )
    with open(CFG_PATH, 'r') as f:
        return yaml.safe_load(f)


class CarProducerNode:
    """
    Car producer node — full telemetry pipeline.

    Streams real F1 telemetry through the complete
    cryptographic pipeline and transmits to relay node.
    """

    def __init__(self, config: dict):
        self.cfg    = config
        self.logger = logging.getLogger('CarProducerNode')

        node_cfg = config.get('node', {})
        self.node_id = node_cfg.get('id',      'mercedes_car')
        self.team    = node_cfg.get('team',     'mercedes')
        self.session = node_cfg.get('session',  'R')

        tel_cfg  = config.get('telemetry', {})
        net_cfg  = config.get('network',   {})
        cry_cfg  = config.get('crypto',    {})
        pip_cfg  = config.get('pipeline',  {})

        # ── Pipeline components ──────────────────────────────────
        self.logger.info("Initialising pipeline components...")

        # 1. Sensor simulator
        self.simulator = SensorSimulator(
            team=self.team,
            race=tel_cfg.get('race',            'Bahrain'),
            session=self.session,
            add_noise=tel_cfg.get('add_noise',  True),
            inject_anomalies=tel_cfg.get(
                'inject_anomalies', False
            ),
            anomaly_rate=tel_cfg.get('anomaly_rate', 0.001),
        )

        # 2. Packet builder
        self.builder = PacketBuilder(
            team=self.team,
            session=self.session,
            node_id=self.node_id,
        )

        # 3. Signer — Ed25519 identity
        self.signer = PacketSigner(node_id=self.node_id)
        self.logger.info(
            f"Public key: "
            f"{self.signer.public_key_bytes.hex()[:16]}..."
        )

        # 4. Crypto engine — ECDH session
        self.crypto = CryptoEngine(node_id=self.node_id)
        self._car_pub = self.crypto.new_session()
        self.logger.info(
            f"ECDH public key: {self._car_pub.hex()[:16]}..."
        )

        # 5. Key scheduler
        self.scheduler = KeyScheduler(
            crypto_engine=self.crypto,
            max_age_seconds=cry_cfg.get(
                'max_session_age_seconds', 300
            ),
            max_packets=cry_cfg.get(
                'max_packets_per_key', 10000
            ),
            check_interval=cry_cfg.get(
                'check_interval_seconds', 5
            ),
            node_id=self.node_id,
        )
        self.scheduler.on_rotation(self._on_key_rotation)

        # 6. Encryptor — initialised after handshake
        self.encryptor: Optional[PacketEncryptor] = None

        # ── Network ──────────────────────────────────────────────
        self._relay_host = net_cfg.get('relay_host', '127.0.0.1')
        self._relay_port = net_cfg.get('relay_port', 9001)
        self._timeout    = net_cfg.get('timeout_seconds', 5)
        self._max_retry  = net_cfg.get('max_retries', 3)
        self._socket: Optional[socket.socket] = None

        # ── State ────────────────────────────────────────────────
        self._running        = False
        self._packet_queue   = queue.Queue(
            maxsize=pip_cfg.get('max_queue_size', 1000)
        )
        self._stream_delay   = (
            tel_cfg.get('stream_delay_ms', 10) / 1000.0
        )

        # ── Stats ────────────────────────────────────────────────
        self._stats = {
            'packets_built':     0,
            'packets_signed':    0,
            'packets_encrypted': 0,
            'packets_sent':      0,
            'packets_failed':    0,
            'key_rotations':     0,
            'start_time':        None,
        }

        self.logger.info(
            f"CarProducerNode ready — {self.node_id}"
        )

    # ── Key rotation callback ────────────────────────────────────

    def _on_key_rotation(self, event, new_pub_key: bytes):
        """
        Called by KeyScheduler on rotation.
        In production: send new public key to relay node
        and wait for relay's new public key to re-handshake.

        In simulation: log the event.
        """
        self._stats['key_rotations'] += 1
        self.logger.info(
            f"🔄 Key rotation #{event.rotation_num} — "
            f"{event.reason}"
        )
        self.logger.info(
            f"   New pub key: {new_pub_key.hex()[:16]}..."
        )
        # TODO: In production — send new_pub_key to relay
        # and receive relay's new pub key for re-handshake

    # ── Network ──────────────────────────────────────────────────

    def _connect_to_relay(self) -> bool:
        """Attempt TCP connection to relay node."""
        for attempt in range(1, self._max_retry + 1):
            try:
                self.logger.info(
                    f"Connecting to relay "
                    f"{self._relay_host}:{self._relay_port} "
                    f"(attempt {attempt}/{self._max_retry})..."
                )
                self._socket = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                self._socket.settimeout(self._timeout)
                self._socket.connect(
                    (self._relay_host, self._relay_port)
                )
                self.logger.info("Connected to relay ✅")
                return True

            except (ConnectionRefusedError, OSError) as e:
                self.logger.warning(
                    f"Connection failed: {e}"
                )
                if self._socket:
                    self._socket.close()
                if attempt < self._max_retry:
                    time.sleep(2)

        return False

    def _send_packet(self, encrypted_packet: dict) -> bool:
        """
        Serialise and send encrypted packet over TCP.
        Prefixes with 4-byte length header for framing.
        """
        if self._socket is None:
            return False

        # Serialise to JSON for transmission
        # In production: use binary protocol
        transmit_data = {
            'nonce':         encrypted_packet['nonce'],
            'ciphertext':    encrypted_packet['ciphertext'],
            'header_hex':    encrypted_packet['header_hex'],
            'signature':     encrypted_packet['signature'],
            'sequence_no':   encrypted_packet['sequence_no'],
            'timestamp':     encrypted_packet['timestamp'],
            'team':          encrypted_packet['team'],
            'session':       encrypted_packet['session'],
            'node_id':       encrypted_packet['node_id'],
        }

        payload = json.dumps(
            transmit_data, separators=(',', ':')
        ).encode('utf-8')

        # 4-byte length prefix for framing
        length_prefix = len(payload).to_bytes(4, 'big')

        try:
            self._socket.sendall(length_prefix + payload)
            return True
        except OSError as e:
            self.logger.error(f"Send failed: {e}")
            return False

    # ── Pipeline ─────────────────────────────────────────────────

    def _simulate_handshake(self) -> None:
        """
        Simulate ECDH handshake with relay node.
        In production: exchange public keys over network.
        In simulation: use a second CryptoEngine as relay.
        """
        self.logger.info(
            "Simulating ECDH handshake with relay..."
        )

        # Simulate relay side
        relay_engine = CryptoEngine(node_id='relay_sim')
        relay_pub    = relay_engine.new_session()

        # Complete handshake
        self.crypto.complete_handshake(relay_pub)
        relay_engine.complete_handshake(self._car_pub)

        # Initialise encryptor now session is established
        self.encryptor = PacketEncryptor(
            crypto_engine=self.crypto,
            node_id=self.node_id,
        )

        self.logger.info("Handshake complete ✅")

    def _build_and_encrypt(self) -> Optional[dict]:
        """
        Run one frame through the full pipeline:
        simulate → build → sign → encrypt
        """
        try:
            # 1. Get telemetry frame
            frame = self.simulator.get_next_frame()

            # 2. Build packet
            packet = self.builder.build(frame)
            self._stats['packets_built'] += 1

            # 3. Sign packet
            signed = self.signer.sign_packet(packet)
            self._stats['packets_signed'] += 1

            # 4. Encrypt packet
            encrypted = self.encryptor.encrypt_packet(signed)
            self._stats['packets_encrypted'] += 1

            # 5. Notify scheduler
            self.scheduler.record_packet()

            return encrypted

        except Exception as e:
            self._stats['packets_failed'] += 1
            self.logger.error(f"Pipeline error: {e}")
            return None

    def _producer_loop(self) -> None:
        """
        Main producer loop — generates and queues packets.
        Runs in background thread.
        """
        self.logger.info("Producer loop started")

        while self._running:
            encrypted = self._build_and_encrypt()

            if encrypted:
                try:
                    self._packet_queue.put_nowait(encrypted)
                except queue.Full:
                    self.logger.warning(
                        "Packet queue full — dropping packet"
                    )

            time.sleep(self._stream_delay)

    def _transmitter_loop(self) -> None:
        """
        Transmitter loop — sends queued packets to relay.
        Runs in background thread.
        """
        self.logger.info("Transmitter loop started")

        while self._running:
            try:
                packet = self._packet_queue.get(timeout=1.0)

                if self._socket:
                    success = self._send_packet(packet)
                    if success:
                        self._stats['packets_sent'] += 1
                    else:
                        self._stats['packets_failed'] += 1
                else:
                    # No relay connection — log only
                    self._stats['packets_sent'] += 1

                self._packet_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Transmit error: {e}")

    # ── Lifecycle ────────────────────────────────────────────────

    def start(self, connect_to_relay: bool = False) -> None:
        """
        Start the car producer node.

        Args:
            connect_to_relay: If True, attempt TCP connection
                              to relay node. If False, run in
                              simulation mode (no network).
        """
        self.logger.info(
            f"\n{'='*50}\n"
            f"  PitCrypt-F1 — Car Producer Node\n"
            f"  Node:    {self.node_id}\n"
            f"  Team:    {self.team.upper()}\n"
            f"  Session: {self.session}\n"
            f"{'='*50}"
        )

        # ECDH handshake
        self._simulate_handshake()

        # Optional relay connection
        if connect_to_relay:
            connected = self._connect_to_relay()
            if not connected:
                self.logger.warning(
                    "Could not connect to relay — "
                    "running in simulation mode"
                )

        # Start key scheduler
        self.scheduler.start()

        # Start pipeline threads
        self._running = True
        self._stats['start_time'] = datetime.now(
            timezone.utc
        ).isoformat()

        producer_thread = threading.Thread(
            target=self._producer_loop,
            daemon=True,
            name="ProducerLoop",
        )
        transmitter_thread = threading.Thread(
            target=self._transmitter_loop,
            daemon=True,
            name="TransmitterLoop",
        )

        producer_thread.start()
        transmitter_thread.start()

        self.logger.info("Car producer node running ✅")

    def stop(self) -> None:
        """Stop the car producer node gracefully."""
        self.logger.info("Stopping car producer node...")
        self._running = False
        self.scheduler.stop()

        if self._socket:
            self._socket.close()

        self.logger.info("Car producer node stopped ⛔")
        self._print_stats()

    def _print_stats(self) -> None:
        """Print pipeline statistics."""
        self.logger.info(
            f"\n{'='*40}\n"
            f"  Pipeline Statistics\n"
            f"{'='*40}\n"
            f"  Built:      {self._stats['packets_built']:,}\n"
            f"  Signed:     {self._stats['packets_signed']:,}\n"
            f"  Encrypted:  {self._stats['packets_encrypted']:,}\n"
            f"  Sent:       {self._stats['packets_sent']:,}\n"
            f"  Failed:     {self._stats['packets_failed']:,}\n"
            f"  Rotations:  {self._stats['key_rotations']}\n"
            f"{'='*40}"
        )

    def run_simulation(
        self,
        n_packets: int = 20,
        verbose:   bool = True,
    ) -> dict:
        """
        Run a self-contained simulation without network.
        Useful for testing and demonstrations.

        Args:
            n_packets: Number of packets to process
            verbose:   Print each packet summary

        Returns:
            Statistics dict
        """
        self.logger.info(
            f"\nRunning simulation — {n_packets} packets"
        )

        # ECDH handshake if not done
        if self.encryptor is None:
            self._simulate_handshake()

        results = []

        for i in range(n_packets):
            encrypted = self._build_and_encrypt()

            if encrypted and verbose:
                print(
                    f"  Packet {i+1:3d}: "
                    f"seq={encrypted['sequence_no']:4d} | "
                    f"size_plain={encrypted['size_original']:3d}B | "
                    f"size_enc={encrypted['size_encrypted']:3d}B | "
                    f"team={encrypted['team']} | "
                    f"nonce={encrypted['nonce'][:8]}..."
                )
                results.append(encrypted)

        self._stats['key_rotations'] = (
            self.scheduler.rotation_count
        )
        return self._stats


# ── Entry point ──────────────────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "="*55)
    print("  CarProducerNode — Self Test")
    print("="*55)

    # Load config
    try:
        cfg = load_config()
        print(f"\n  Config loaded: {CFG_PATH}")
    except FileNotFoundError:
        print(
            f"\n  Config not found — using defaults"
        )
        cfg = {
            'node':      {'id': 'mercedes_car',
                          'team': 'mercedes',
                          'session': 'R'},
            'telemetry': {'race': 'Bahrain',
                          'session': 'R',
                          'add_noise': True,
                          'inject_anomalies': False,
                          'anomaly_rate': 0.001,
                          'stream_delay_ms': 0},
            'crypto':    {'max_session_age_seconds': 300,
                          'max_packets_per_key': 10000,
                          'check_interval_seconds': 5},
            'network':   {'relay_host': '127.0.0.1',
                          'relay_port': 9001,
                          'timeout_seconds': 5,
                          'max_retries': 3},
            'logging':   {'level': 'INFO',
                          'log_to_file': False},
            'pipeline':  {'max_queue_size': 1000,
                          'stream_delay_ms': 0},
        }

    # Setup logging
    logger = setup_logging(cfg)

    # Create node
    node = CarProducerNode(cfg)

    # ── Test 1: Run 20-packet simulation ─────────────────────────
    print("\n[Test 1] 20-packet pipeline simulation")
    stats = node.run_simulation(n_packets=20, verbose=True)

    print(f"\n  Built:     {stats['packets_built']:,}")
    print(f"  Signed:    {stats['packets_signed']:,}")
    print(f"  Encrypted: {stats['packets_encrypted']:,}")
    print(f"  Failed:    {stats['packets_failed']}")

    assert stats['packets_built']     == 20
    assert stats['packets_signed']    == 20
    assert stats['packets_encrypted'] == 20
    assert stats['packets_failed']    == 0
    print(f"  All 20 packets processed: ✅")

    # ── Test 2: Red Bull node ─────────────────────────────────────
    print("\n[Test 2] Red Bull node simulation")

    rbr_cfg          = dict(cfg)
    rbr_cfg['node']  = {
        'id': 'redbull_car', 'team': 'redbull', 'session': 'R'
    }
    rbr_cfg['telemetry'] = dict(
        cfg.get('telemetry', {})
    )
    rbr_cfg['telemetry']['race'] = 'Bahrain'

    rbr_node = CarProducerNode(rbr_cfg)
    rbr_stats = rbr_node.run_simulation(
        n_packets=5, verbose=True
    )

    assert rbr_stats['packets_built'] == 5
    print(f"  Red Bull node: ✅")

    # ── Test 3: Scheduler stats ───────────────────────────────────
    print("\n[Test 3] Scheduler status")
    status = node.scheduler.status()
    print(f"  Packet count:  {status['packet_count']}")
    print(f"  Session age:   {status['session_age_s']}s")
    print(f"  Until rotation: {status['time_until_rotation']}s")
    print(f"  Scheduler: ✅")

    print("\n✅ CarProducerNode self-test complete.")
    print("\nTo run the full live node:")
    print("  node.start(connect_to_relay=False)  # simulation")
    print("  node.start(connect_to_relay=True)   # with relay")
    print("  time.sleep(60)")
    print("  node.stop()")