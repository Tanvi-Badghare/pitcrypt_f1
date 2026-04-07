import os
import sys
import time
import logging
from typing import Optional
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature

"""
signer.py

Ed25519 digital signature layer for PitCrypt-F1.

Every packet produced by the car node is signed with the
car's Ed25519 private key before encryption. The signature
travels with the packet through relay → validator where
signature_verifier.py checks it against the car's registered
public key.

This provides:
    - Authentication  — only the car with the private key
                        could have produced this packet
    - Non-repudiation — the car cannot deny producing a
                        packet bearing its valid signature
    - Integrity       — any modification to the signed data
                        is detected on verification

Why Ed25519 over RSA or ECDSA:
    - 64-byte signatures — compact for high-frequency packets
    - Fast signing and verification
    - No random number dependency during signing — deterministic
    - Resistant to side-channel attacks
    - RFC 8032 standardised
    See: architecture/adr/001-crypto-choice.md

What gets signed:
    The packet header bytes + payload bytes concatenated.
    Signing the header ensures sequence number, timestamp,
    and team ID are all authenticated — not just the payload.
"""

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Constants ────────────────────────────────────────────────────
SIGNATURE_SIZE = 64     # Ed25519 signature is always 64 bytes
PUBLIC_KEY_SIZE = 32    # Ed25519 public key is always 32 bytes


class PacketSigner:
    """
    Signs packets using Ed25519 private key.
    One instance per car node — holds the node's identity keypair.

    The keypair represents the car node's cryptographic identity.
    Private key stays on the car — never transmitted.
    Public key is registered with the validator on startup.
    """

    def __init__(
        self,
        node_id:     str,
        private_key: Optional[Ed25519PrivateKey] = None,
    ):
        """
        Args:
            node_id:     Unique node identifier
                         e.g. 'mercedes_car', 'redbull_car'
            private_key: Existing Ed25519PrivateKey or None
                         to generate a new one automatically
        """
        self.node_id = node_id

        if private_key is not None:
            self._private_key = private_key
            print(f"  [PacketSigner] Loaded existing keypair")
        else:
            self._private_key = Ed25519PrivateKey.generate()
            print(f"  [PacketSigner] Generated new keypair")

        self._public_key    = self._private_key.public_key()
        self._sign_count    = 0
        self._created_at    = time.time()

        print(f"  [PacketSigner] Node:       {node_id}")
        print(
            f"  [PacketSigner] Public key: "
            f"{self.public_key_bytes.hex()[:16]}... (32 bytes)"
        )

    # ── Key export ───────────────────────────────────────────────

    @property
    def public_key_bytes(self) -> bytes:
        """
        32-byte Ed25519 public key.
        Register this with the validator on startup.
        """
        return self._public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

    @property
    def private_key_bytes(self) -> bytes:
        """
        32-byte Ed25519 private key.
        Never transmit this. For local storage only.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )

    # ── Signing ──────────────────────────────────────────────────

    def sign_packet(self, packet: dict) -> dict:
        """
        Sign a packet dict produced by PacketBuilder.build().

        Signs header + payload bytes concatenated.
        Adds 'signature' field to the packet dict.

        Args:
            packet: dict from PacketBuilder.build()
                    Must contain 'header' and 'payload' keys

        Returns:
            Same packet dict with 'signature' key added:
                signature — 64-byte Ed25519 signature as hex str
        """
        if 'header' not in packet or 'payload' not in packet:
            raise ValueError(
                "Packet must contain 'header' and 'payload' keys. "
                "Use PacketBuilder.build() to create packets."
            )

        # Sign header + payload concatenated
        # This authenticates the full packet content
        # including sequence number, timestamp, and team ID
        data_to_sign = packet['header'] + packet['payload']
        signature    = self._private_key.sign(data_to_sign)

        self._sign_count += 1

        signed_packet = dict(packet)
        signed_packet['signature']      = signature.hex()
        signed_packet['signature_bytes'] = signature
        signed_packet['signer_node_id'] = self.node_id
        signed_packet['signed_at']      = (
            datetime.now(timezone.utc).isoformat()
        )

        return signed_packet

    def sign_bytes(self, data: bytes) -> bytes:
        """
        Sign arbitrary bytes directly.
        Returns 64-byte signature.
        """
        return self._private_key.sign(data)

    # ── Properties ───────────────────────────────────────────────

    @property
    def sign_count(self) -> int:
        return self._sign_count

    @property
    def age_seconds(self) -> float:
        return time.time() - self._created_at


class SignatureVerifier:
    """
    Verifies Ed25519 packet signatures.

    Used by validator-node/src/signature_verifier.py
    but defined here so both sides use identical logic.

    Maintains a registry of known node public keys.
    Rejects packets from unknown nodes.
    """

    def __init__(self):
        # node_id → Ed25519PublicKey
        self._registry: dict = {}
        self._verify_count   = 0
        self._fail_count     = 0

        print(f"  [SignatureVerifier] Initialised")

    def register_node(
        self,
        node_id:         str,
        public_key_bytes: bytes,
    ) -> None:
        """
        Register a node's public key.
        Must be called before verifying packets from that node.

        Args:
            node_id:          Node identifier
            public_key_bytes: 32-byte Ed25519 public key
        """
        if len(public_key_bytes) != PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Invalid public key size: "
                f"{len(public_key_bytes)}. "
                f"Expected {PUBLIC_KEY_SIZE}."
            )

        pub_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )
        self._registry[node_id] = pub_key

        logging.info(
            f"  [SignatureVerifier] Registered: {node_id} "
            f"({public_key_bytes.hex()[:16]}...)"
        )

    def verify_packet(self, packet: dict) -> bool:
        """
        Verify signature on a signed packet dict.

        Args:
            packet: Signed packet dict containing:
                    header, payload, signature_bytes,
                    signer_node_id

        Returns:
            True if signature is valid

        Raises:
            ValueError:        Unknown node_id
            InvalidSignature:  Signature verification failed
        """
        node_id = packet.get('signer_node_id')
        if not node_id:
            raise ValueError(
                "Packet missing 'signer_node_id' field."
            )

        if node_id not in self._registry:
            raise ValueError(
                f"Unknown node: '{node_id}'. "
                f"Register public key first."
            )

        if 'header' not in packet or 'payload' not in packet:
            raise ValueError(
                "Packet missing 'header' or 'payload'."
            )

        sig = packet.get('signature_bytes')
        if sig is None:
            # Try hex string fallback
            sig_hex = packet.get('signature')
            if sig_hex:
                sig = bytes.fromhex(sig_hex)
            else:
                raise ValueError(
                    "Packet missing signature."
                )

        data_to_verify = packet['header'] + packet['payload']

        try:
            self._registry[node_id].verify(sig, data_to_verify)
            self._verify_count += 1
            return True

        except InvalidSignature:
            self._fail_count += 1
            raise InvalidSignature(
                f"Invalid signature from node '{node_id}'. "
                f"Packet may have been tampered with."
            )

    def verify_bytes(
        self,
        node_id:   str,
        signature: bytes,
        data:      bytes,
    ) -> bool:
        """
        Verify signature on raw bytes directly.

        Args:
            node_id:   Registered node identifier
            signature: 64-byte Ed25519 signature
            data:      Original signed data

        Returns:
            True if valid

        Raises:
            InvalidSignature if verification fails
        """
        if node_id not in self._registry:
            raise ValueError(f"Unknown node: '{node_id}'")

        self._registry[node_id].verify(signature, data)
        self._verify_count += 1
        return True

    def is_registered(self, node_id: str) -> bool:
        return node_id in self._registry

    @property
    def registered_nodes(self) -> list:
        return list(self._registry.keys())

    @property
    def verify_count(self) -> int:
        return self._verify_count

    @property
    def fail_count(self) -> int:
        return self._fail_count


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from sensor_simulator import SensorSimulator
    from packet_builder   import PacketBuilder
    from cryptography.exceptions import InvalidSignature

    print("\n" + "="*55)
    print("  PacketSigner + SignatureVerifier — Self Test")
    print("="*55)

    # ── Setup ────────────────────────────────────────────────────
    sim      = SensorSimulator(
        team='mercedes', race='Bahrain', session='R'
    )
    builder  = PacketBuilder(team='mercedes', session='R')
    signer   = PacketSigner(node_id='mercedes_car')
    verifier = SignatureVerifier()

    # Register car's public key with verifier
    verifier.register_node(
        'mercedes_car',
        signer.public_key_bytes,
    )

    # ── Test 1: Sign and verify a packet ─────────────────────────
    print("\n[Test 1] Sign and verify packet")

    frame  = sim.get_next_frame()
    packet = builder.build(frame)
    signed = signer.sign_packet(packet)

    print(f"  Signature: {signed['signature'][:24]}... (64 bytes)")
    print(f"  Signed by: {signed['signer_node_id']}")

    result = verifier.verify_packet(signed)
    print(f"  Verification: {result} ✅")

    # ── Test 2: Tampered payload detected ────────────────────────
    print("\n[Test 2] Tampered payload detection")

    tampered          = dict(signed)
    tampered_payload  = bytearray(signed['payload'])
    tampered_payload[5] ^= 0xFF
    tampered['payload'] = bytes(tampered_payload)

    try:
        verifier.verify_packet(tampered)
        print("  ❌ FAIL — tampered packet not detected")
    except InvalidSignature:
        print("  Tampered payload detected: ✅")

    # ── Test 3: Tampered header detected ─────────────────────────
    print("\n[Test 3] Tampered header detection")

    tampered2         = dict(signed)
    tampered_header   = bytearray(signed['header'])
    tampered_header[10] ^= 0xFF
    tampered2['header'] = bytes(tampered_header)

    try:
        verifier.verify_packet(tampered2)
        print("  ❌ FAIL — tampered header not detected")
    except InvalidSignature:
        print("  Tampered header detected: ✅")

    # ── Test 4: Unknown node rejected ────────────────────────────
    print("\n[Test 4] Unknown node rejected")

    unknown        = dict(signed)
    unknown['signer_node_id'] = 'unknown_node'

    try:
        verifier.verify_packet(unknown)
        print("  ❌ FAIL — unknown node not rejected")
    except ValueError as e:
        print(f"  Unknown node rejected: ✅ ({e})")

    # ── Test 5: Sign 10 packets ───────────────────────────────────
    print("\n[Test 5] Sign 10 packets")

    for i in range(10):
        frame  = sim.get_next_frame()
        packet = builder.build(frame)
        signed = signer.sign_packet(packet)
        verifier.verify_packet(signed)

    print(f"  Signed:   {signer.sign_count} packets ✅")
    print(f"  Verified: {verifier.verify_count} packets ✅")
    print(f"  Failed:   {verifier.fail_count}")

    print("\n✅ Signer self-test complete.")