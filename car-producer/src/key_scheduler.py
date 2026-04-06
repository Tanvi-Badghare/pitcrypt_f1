import os
import time
import threading
import logging
from typing import Optional, Callable
from datetime import datetime, timezone

"""
key_scheduler.py

Manages automatic key rotation for PitCrypt-F1.

Triggers a key rotation event when EITHER condition is met:
    1. Time-based  — session key has exceeded MAX_SESSION_AGE_SECONDS
    2. Count-based — more than MAX_PACKETS_PER_KEY packets encrypted

On rotation:
    - Calls crypto_engine.rotate_session() to generate new keypair
    - Notifies registered callbacks so relay/validator can re-handshake
    - Logs rotation event with timestamp and reason

Why dual-trigger rotation:
    - Time-based alone: vulnerable if traffic is high
    - Count-based alone: vulnerable if session is long-lived with low traffic
    - Both together: hard expiry regardless of usage pattern
    See: architecture/adr/003-key-rotation-policy.md

Thread safety:
    - Rotation check runs in background thread
    - All state access protected by threading.Lock()
"""

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Rotation policy constants ────────────────────────────────────
MAX_SESSION_AGE_SECONDS = 300       # Rotate after 5 minutes
MAX_PACKETS_PER_KEY     = 10_000    # Rotate after 10,000 packets
CHECK_INTERVAL_SECONDS  = 5         # How often scheduler checks


class RotationEvent:
    """
    Represents a single key rotation event.
    Passed to registered callbacks on rotation.
    """

    def __init__(
        self,
        reason:       str,
        rotation_num: int,
        old_age:      float,
        old_count:    int,
    ):
        self.reason       = reason
        self.rotation_num = rotation_num
        self.old_age      = old_age
        self.old_count    = old_count
        self.timestamp    = datetime.now(timezone.utc).isoformat()

    def __repr__(self) -> str:
        return (
            f"RotationEvent("
            f"#{self.rotation_num}, "
            f"reason={self.reason}, "
            f"age={self.old_age:.1f}s, "
            f"packets={self.old_count})"
        )

    def to_dict(self) -> dict:
        return {
            'rotation_num': self.rotation_num,
            'reason':       self.reason,
            'old_age_s':    round(self.old_age, 2),
            'old_count':    self.old_count,
            'timestamp':    self.timestamp,
        }


class KeyScheduler:
    """
    Background scheduler that monitors session key usage
    and triggers rotation when thresholds are exceeded.

    Usage:
        # Create engine and establish session first
        engine = CryptoEngine(node_id='mercedes_car')
        pub    = engine.new_session()

        # Then attach scheduler
        scheduler = KeyScheduler(crypto_engine=engine)
        scheduler.on_rotation(my_callback)
        scheduler.start()

        # Notify scheduler of each packet encrypted
        scheduler.record_packet()

        # Stop when done
        scheduler.stop()
    """

    def __init__(
        self,
        crypto_engine,                          # CryptoEngine instance
        max_age_seconds:  int   = MAX_SESSION_AGE_SECONDS,
        max_packets:      int   = MAX_PACKETS_PER_KEY,
        check_interval:   float = CHECK_INTERVAL_SECONDS,
        node_id:          str   = 'node',
    ):
        """
        Args:
            crypto_engine:   CryptoEngine instance to rotate
            max_age_seconds: Max session age before rotation
            max_packets:     Max packets before rotation
            check_interval:  How often to check in seconds
            node_id:         Node identifier for logging
        """
        self._engine          = crypto_engine
        self._max_age         = max_age_seconds
        self._max_packets     = max_packets
        self._check_interval  = check_interval
        self._node_id         = node_id

        # State — protected by lock
        self._lock            = threading.Lock()
        self._packet_count    = 0
        self._session_start   = time.time()
        self._rotation_count  = 0
        self._running         = False
        self._thread: Optional[threading.Thread] = None

        # Rotation history
        self._rotation_log    = []

        # Registered callbacks — called on every rotation
        self._callbacks       = []

        # Pending public key from peer after rotation
        self._pending_peer_pub: Optional[bytes] = None

        print(f"\n[KeyScheduler] Initialised for {node_id}")
        print(f"[KeyScheduler] Max age:     {max_age_seconds}s")
        print(f"[KeyScheduler] Max packets: {max_packets:,}")
        print(f"[KeyScheduler] Check every: {check_interval}s")

    # ── Callback registration ────────────────────────────────────

    def on_rotation(self, callback: Callable) -> None:
        """
        Register a callback to be called on key rotation.

        Callback receives a RotationEvent as argument.

        Example:
            def handle_rotation(event: RotationEvent):
                new_pub = event  # Send new pub key to peer
                ...

            scheduler.on_rotation(handle_rotation)
        """
        self._callbacks.append(callback)
        logging.info(
            f"[KeyScheduler] Callback registered: "
            f"{callback.__name__}"
        )

    # ── Packet tracking ──────────────────────────────────────────

    def record_packet(self) -> None:
        """
        Call this after every packet is encrypted.
        Increments the packet counter used for count-based rotation.
        """
        with self._lock:
            self._packet_count += 1

    # ── Rotation logic ───────────────────────────────────────────

    def _should_rotate(self) -> Optional[str]:
        """
        Check if rotation is needed.
        Returns reason string or None.
        """
        with self._lock:
            age   = time.time() - self._session_start
            count = self._packet_count

        if age >= self._max_age:
            return f"age_exceeded ({age:.1f}s >= {self._max_age}s)"

        if count >= self._max_packets:
            return f"count_exceeded ({count:,} >= {self._max_packets:,})"

        return None

    def _do_rotation(self, reason: str) -> None:
        """
        Execute key rotation:
        1. Get current stats
        2. Rotate crypto engine session
        3. Reset counters
        4. Log event
        5. Notify callbacks
        """
        with self._lock:
            old_age   = time.time() - self._session_start
            old_count = self._packet_count
            self._rotation_count += 1
            rotation_num = self._rotation_count

        # Rotate the crypto engine — generates new keypair
        new_pub_key = self._engine.rotate_session()

        # Reset counters
        with self._lock:
            self._packet_count  = 0
            self._session_start = time.time()

        # Build rotation event
        event = RotationEvent(
            reason=reason,
            rotation_num=rotation_num,
            old_age=old_age,
            old_count=old_count,
        )

        # Log
        self._rotation_log.append(event.to_dict())
        logging.info(
            f"[KeyScheduler] 🔄 Rotation #{rotation_num} — "
            f"{reason}"
        )
        logging.info(
            f"[KeyScheduler] New public key: "
            f"{new_pub_key.hex()[:16]}..."
        )

        # Notify all callbacks
        for callback in self._callbacks:
            try:
                callback(event, new_pub_key)
            except Exception as e:
                logging.error(
                    f"[KeyScheduler] Callback error: {e}"
                )

    # ── Background thread ────────────────────────────────────────

    def _run(self) -> None:
        """Background thread — checks rotation conditions."""
        logging.info(
            f"[KeyScheduler] Background thread started"
        )
        while self._running:
            reason = self._should_rotate()
            if reason:
                self._do_rotation(reason)
            time.sleep(self._check_interval)

        logging.info(
            f"[KeyScheduler] Background thread stopped"
        )

    # ── Lifecycle ────────────────────────────────────────────────

    def start(self) -> None:
        """Start background rotation checker."""
        if self._running:
            logging.warning(
                "[KeyScheduler] Already running"
            )
            return

        self._running = True
        self._thread  = threading.Thread(
            target=self._run,
            daemon=True,    # Dies with main thread
            name=f"KeyScheduler-{self._node_id}",
        )
        self._thread.start()
        logging.info("[KeyScheduler] Started ✅")

    def stop(self) -> None:
        """Stop background rotation checker."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=self._check_interval + 1)
        logging.info("[KeyScheduler] Stopped ⛔")

    def force_rotation(self) -> None:
        """
        Manually trigger immediate key rotation.
        Useful for testing or emergency rotation.
        """
        logging.info(
            "[KeyScheduler] Force rotation requested"
        )
        self._do_rotation(reason="manual_force")

    # ── Properties ───────────────────────────────────────────────

    @property
    def packet_count(self) -> int:
        with self._lock:
            return self._packet_count

    @property
    def session_age(self) -> float:
        with self._lock:
            return time.time() - self._session_start

    @property
    def rotation_count(self) -> int:
        with self._lock:
            return self._rotation_count

    @property
    def rotation_log(self) -> list:
        return list(self._rotation_log)

    @property
    def time_until_rotation(self) -> float:
        """Seconds until time-based rotation fires."""
        with self._lock:
            age = time.time() - self._session_start
        return max(0.0, self._max_age - age)

    @property
    def packets_until_rotation(self) -> int:
        """Packets remaining before count-based rotation."""
        with self._lock:
            return max(0, self._max_packets - self._packet_count)

    def status(self) -> dict:
        """Full scheduler status snapshot."""
        with self._lock:
            age   = time.time() - self._session_start
            count = self._packet_count
        return {
            'node_id':              self._node_id,
            'running':              self._running,
            'session_age_s':        round(age, 2),
            'packet_count':         count,
            'rotation_count':       self._rotation_count,
            'time_until_rotation':  round(max(0, self._max_age - age), 2),
            'packets_until_rotation': max(0, self._max_packets - count),
        }


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from crypto_engine import CryptoEngine

    print("\n" + "="*55)
    print("  KeyScheduler — Self Test")
    print("="*55)

    # ── Setup two nodes ──────────────────────────────────────────
    car   = CryptoEngine(node_id='mercedes_car')
    relay = CryptoEngine(node_id='relay_01')

    car_pub   = car.new_session()
    relay_pub = relay.new_session()

    car.complete_handshake(relay_pub)
    relay.complete_handshake(car_pub)

    rotation_events = []

    def on_rotation_callback(event: RotationEvent,
                             new_pub: bytes) -> None:
        """Simulates relay receiving new pub key and re-handshaking."""
        rotation_events.append(event)
        print(
            f"\n  🔄 Rotation #{event.rotation_num} fired!"
            f"\n     Reason:  {event.reason}"
            f"\n     Old age: {event.old_age:.1f}s"
            f"\n     Packets: {event.old_count:,}"
        )
        # Relay generates new session and completes handshake
        new_relay_pub = relay.rotate_session()
        car.complete_handshake(new_pub)
        relay.complete_handshake(new_pub)

    # ── Test 1: Count-based rotation ────────────────────────────
    print("\n[Test 1] Count-based rotation (threshold=10)")

    scheduler = KeyScheduler(
        crypto_engine=car,
        max_age_seconds=9999,   # Disable time rotation
        max_packets=10,         # Low threshold for testing
        check_interval=0.5,
        node_id='mercedes_car',
    )
    scheduler.on_rotation(on_rotation_callback)
    scheduler.start()

    # Simulate 15 packets
    for i in range(15):
        nonce, ct = car.encrypt(b'telemetry_payload', b'header')
        scheduler.record_packet()
        time.sleep(0.1)

    time.sleep(1)
    scheduler.stop()

    print(f"\n  Rotations triggered: {scheduler.rotation_count}")
    assert scheduler.rotation_count >= 1, \
        "Count-based rotation did not fire!"
    print(f"  Count-based rotation: ✅")

    # ── Test 2: Time-based rotation ──────────────────────────────
    print("\n[Test 2] Time-based rotation (threshold=2s)")

    car2   = CryptoEngine(node_id='mercedes_car_2')
    relay2 = CryptoEngine(node_id='relay_02')

    pub2  = car2.new_session()
    rpub2 = relay2.new_session()
    car2.complete_handshake(rpub2)
    relay2.complete_handshake(pub2)

    scheduler2 = KeyScheduler(
        crypto_engine=car2,
        max_age_seconds=2,      # Rotate every 2 seconds
        max_packets=99999,      # Disable count rotation
        check_interval=0.5,
        node_id='mercedes_car_2',
    )

    rotations2 = []

    def callback2(event, new_pub):
        rotations2.append(event)
        print(f"\n  🔄 Time rotation #{event.rotation_num}: "
              f"{event.reason}")

    scheduler2.on_rotation(callback2)
    scheduler2.start()

    print("  Waiting 5 seconds for time-based rotations...")
    time.sleep(5)
    scheduler2.stop()

    print(f"\n  Rotations in 5s: {len(rotations2)}")
    assert len(rotations2) >= 2, \
        "Time-based rotation did not fire enough!"
    print(f"  Time-based rotation: ✅")

    # ── Test 3: Force rotation ───────────────────────────────────
    print("\n[Test 3] Force rotation")

    car3  = CryptoEngine(node_id='mercedes_car_3')
    pub3  = car3.new_session()

    scheduler3 = KeyScheduler(
        crypto_engine=car3,
        max_age_seconds=9999,
        max_packets=99999,
        check_interval=1,
        node_id='mercedes_car_3',
    )

    forced = []
    scheduler3.on_rotation(lambda e, p: forced.append(e))
    scheduler3.start()
    scheduler3.force_rotation()
    time.sleep(0.5)
    scheduler3.stop()

    assert len(forced) == 1
    assert forced[0].reason == 'manual_force'
    print(f"  Force rotation: ✅")

    # ── Test 4: Status snapshot ──────────────────────────────────
    print("\n[Test 4] Status")

    car4  = CryptoEngine(node_id='mercedes_car_4')
    pub4  = car4.new_session()

    scheduler4 = KeyScheduler(
        crypto_engine=car4,
        node_id='mercedes_car_4',
    )

    for _ in range(50):
        scheduler4.record_packet()

    status = scheduler4.status()
    print(f"  Node:              {status['node_id']}")
    print(f"  Packet count:      {status['packet_count']}")
    print(f"  Session age:       {status['session_age_s']}s")
    print(f"  Until rotation:    {status['time_until_rotation']}s")
    print(f"  Packets remaining: {status['packets_until_rotation']}")

    assert status['packet_count'] == 50
    print(f"  Status snapshot: ✅")

    print("\n✅ KeyScheduler self-test complete.")