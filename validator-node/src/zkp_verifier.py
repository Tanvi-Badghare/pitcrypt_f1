import os
import sys
import json
import hashlib
import logging
from typing import Optional
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
zkp_verifier.py

Zero-Knowledge Proof packet integrity verifier
at the FIA validator node.

This is a Python implementation of the commitment
verification layer. The full Rust ZKP module
(zkp-module/) implements Pedersen commitments and
Bulletproofs. This Python verifier implements the
hash-based commitment scheme used when the Rust
module is not available.

Commitment scheme:
    Commit phase (car):
        commitment = SHA256(payload_bytes || nonce_bytes)
        The commitment is sent with the packet.
        The nonce prevents brute-force preimage attacks.

    Verify phase (validator):
        Given: commitment, payload_bytes, nonce_bytes
        Compute: SHA256(payload_bytes || nonce_bytes)
        Check:   computed == commitment

Why ZKP for F1 telemetry:
    - FIA stewards can verify packet integrity without
      seeing proprietary team telemetry values
    - Commitment proves data was not modified after
      transmission without revealing the data itself
    - In production: Pedersen commitments via Rust module
      provide cryptographic hiding (not just binding)
    See: docs/ZKP_DESIGN.md
    See: zkp-module/src/commitments.rs

Note on implementation:
    This Python implementation uses hash commitments —
    binding but not hiding (SHA256 is not perfectly hiding).
    The Rust Pedersen implementation provides both
    binding AND hiding properties.
    This file is the verification interface that will
    call the Rust module via FFI when complete.
"""

COMMITMENT_SIZE = 32    # SHA256 output — 32 bytes


class ZKPVerificationError(Exception):
    """Raised when ZKP verification fails."""
    pass


class CommitmentResult:
    """Result of ZKP commitment verification."""

    def __init__(
        self,
        verified:    bool,
        reason:      str,
        commitment:  Optional[str] = None,
        computed:    Optional[str] = None,
    ):
        self.verified   = verified
        self.reason     = reason
        self.commitment = commitment
        self.computed   = computed
        self.verified_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            'verified':    self.verified,
            'reason':      self.reason,
            'commitment':  self.commitment,
            'computed':    self.computed,
            'verified_at': self.verified_at,
        }


class ZKPVerifier:
    """
    Hash-based commitment verifier at the FIA validator.

    Verifies that packet payload was not modified after
    the car computed its commitment. Acts as the Python
    interface to the Rust ZKP module.
    """

    def __init__(self, node_id: str = 'validator'):
        self.node_id          = node_id
        self._verified_count  = 0
        self._failed_count    = 0
        self._skipped_count   = 0

        print(f"  [ZKPVerifier] Initialised: {node_id}")
        print(
            f"  [ZKPVerifier] Mode: "
            f"Hash commitment (Python)"
        )
        print(
            f"  [ZKPVerifier] Production: "
            f"Pedersen commitments (Rust zkp-module/)"
        )

    # ── Commitment generation (car side) ─────────────────────────

    @staticmethod
    def generate_commitment(
        payload_bytes: bytes,
        nonce_bytes:   Optional[bytes] = None,
    ) -> dict:
        """
        Generate a commitment to payload bytes.
        Called on the car side before transmission.

        Args:
            payload_bytes: JSON-encoded telemetry payload
            nonce_bytes:   Random nonce for commitment
                           Generated if not provided

        Returns:
            dict with:
                commitment — hex-encoded SHA256 commitment
                nonce      — hex-encoded nonce used
        """
        if nonce_bytes is None:
            nonce_bytes = os.urandom(32)

        commitment = hashlib.sha256(
            payload_bytes + nonce_bytes
        ).hexdigest()

        return {
            'commitment': commitment,
            'nonce':      nonce_bytes.hex(),
        }

    # ── Commitment verification (validator side) ──────────────────

    def verify_commitment(
        self,
        payload_bytes: bytes,
        commitment:    str,
        nonce:         str,
    ) -> CommitmentResult:
        """
        Verify a hash commitment against decrypted payload.

        Args:
            payload_bytes: Decrypted packet payload bytes
            commitment:    Hex commitment from packet
            nonce:         Hex nonce from packet

        Returns:
            CommitmentResult with verified flag
        """
        try:
            nonce_bytes = bytes.fromhex(nonce)
        except ValueError:
            self._failed_count += 1
            return CommitmentResult(
                verified=False,
                reason='invalid_nonce_format',
            )

        computed = hashlib.sha256(
            payload_bytes + nonce_bytes
        ).hexdigest()

        if computed == commitment:
            self._verified_count += 1
            return CommitmentResult(
                verified=True,
                reason='commitment_valid',
                commitment=commitment,
                computed=computed,
            )
        else:
            self._failed_count += 1
            logging.error(
                f"[ZKPVerifier] 🚨 COMMITMENT MISMATCH — "
                f"node={self.node_id}"
            )
            return CommitmentResult(
                verified=False,
                reason='commitment_mismatch',
                commitment=commitment,
                computed=computed,
            )

    def verify_packet(self, packet: dict) -> CommitmentResult:
        """
        Verify ZKP commitment on a validator packet.

        If packet has no commitment — skips verification
        and returns a skipped result. This allows gradual
        rollout of ZKP without breaking existing pipeline.

        Args:
            packet: Validator packet dict optionally containing:
                    zkp_commitment, zkp_nonce, payload_bytes

        Returns:
            CommitmentResult
        """
        commitment = packet.get('zkp_commitment')
        nonce      = packet.get('zkp_nonce')

        # ── No commitment present — skip ─────────────────────────
        if not commitment or not nonce:
            self._skipped_count += 1
            return CommitmentResult(
                verified=True,
                reason='no_commitment_skipped',
            )

        # ── Get payload bytes ────────────────────────────────────
        payload_bytes = packet.get('payload_bytes')
        if payload_bytes is None:
            self._failed_count += 1
            return CommitmentResult(
                verified=False,
                reason='missing_payload_bytes',
            )

        return self.verify_commitment(
            payload_bytes=payload_bytes,
            commitment=commitment,
            nonce=nonce,
        )

    def verify_batch(
        self, packets: list
    ) -> tuple:
        """
        Verify commitments on a batch of packets.

        Returns:
            (verified_list, failed_list)
        """
        verified = []
        failed   = []

        for packet in packets:
            result = self.verify_packet(packet)
            pkt    = dict(packet)
            pkt['zkp_result'] = result.to_dict()

            if result.verified:
                verified.append(pkt)
            else:
                failed.append(pkt)

        return verified, failed

    # ── Properties ───────────────────────────────────────────────

    @property
    def verified_count(self) -> int:
        return self._verified_count

    @property
    def failed_count(self) -> int:
        return self._failed_count

    @property
    def skipped_count(self) -> int:
        return self._skipped_count


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
    print("  ZKPVerifier — Self Test")
    print("="*55)

    verifier = ZKPVerifier(node_id='fia_validator')

    # ── Test 1: Generate and verify commitment ───────────────────
    print("\n[Test 1] Generate and verify commitment")

    payload = b'{"Speed":287.4,"RPM":12500,"Throttle":98.2}'
    commit_data = ZKPVerifier.generate_commitment(payload)

    print(f"  Commitment: {commit_data['commitment'][:24]}...")
    print(f"  Nonce:      {commit_data['nonce'][:16]}...")

    result = verifier.verify_commitment(
        payload_bytes=payload,
        commitment=commit_data['commitment'],
        nonce=commit_data['nonce'],
    )
    print(f"  Verified:   {result.verified}")
    print(f"  Reason:     {result.reason}")
    assert result.verified is True
    print(f"  Commitment verify: ✅")

    # ── Test 2: Tampered payload fails ───────────────────────────
    print("\n[Test 2] Tampered payload fails")

    tampered = b'{"Speed":999.9,"RPM":12500,"Throttle":98.2}'
    result2  = verifier.verify_commitment(
        payload_bytes=tampered,
        commitment=commit_data['commitment'],
        nonce=commit_data['nonce'],
    )
    print(f"  Verified: {result2.verified}")
    print(f"  Reason:   {result2.reason}")
    assert result2.verified is False
    print(f"  Tampered payload detected: ✅")

    # ── Test 3: Packet with no commitment skipped ────────────────
    print("\n[Test 3] Packet without commitment skipped")

    fake_packet = {
        'sequence_no':  1,
        'payload_bytes': payload,
        'team':         'mercedes',
    }
    result3 = verifier.verify_packet(fake_packet)
    print(f"  Verified: {result3.verified}")
    print(f"  Reason:   {result3.reason}")
    assert result3.verified is True
    assert result3.reason   == 'no_commitment_skipped'
    print(f"  No commitment skipped: ✅")

    # ── Test 4: Packet with valid commitment ─────────────────────
    print("\n[Test 4] Packet with valid commitment")

    packet_with_commit = {
        'sequence_no':    2,
        'payload_bytes':  payload,
        'zkp_commitment': commit_data['commitment'],
        'zkp_nonce':      commit_data['nonce'],
        'team':           'mercedes',
    }
    result4 = verifier.verify_packet(packet_with_commit)
    assert result4.verified is True
    print(f"  Packet commitment verified: ✅")

    # ── Test 5: Full pipeline with ZKP ──────────────────────────
    print("\n[Test 5] Full pipeline ZKP integration")

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

    # Car generates commitment before encrypting
    frame       = sim.get_next_frame()
    packet      = builder.build(frame)
    signed      = signer.sign_packet(packet)

    # Generate ZKP commitment on car side
    commit_info = ZKPVerifier.generate_commitment(
        signed['payload']
    )

    encrypted   = enc.encrypt_packet(signed)
    decrypted   = dec.decrypt(encrypted)
    reencrypted = reenc.reencrypt(decrypted)

    # Validator decrypts
    plaintext = val_eng.decrypt(
        nonce=reencrypted['nonce_bytes'],
        ciphertext=reencrypted['ciphertext_bytes'],
        associated_data=reencrypted['header'],
    )

    # Build validator packet with ZKP fields
    val_packet = dict(reencrypted)
    val_packet['payload_bytes']  = plaintext
    val_packet['zkp_commitment'] = commit_info['commitment']
    val_packet['zkp_nonce']      = commit_info['nonce']

    result5 = verifier.verify_packet(val_packet)
    print(f"  Verified: {result5.verified}")
    assert result5.verified is True
    print(f"  Full pipeline ZKP: ✅")

    # ── Test 6: Batch verification ───────────────────────────────
    print("\n[Test 6] Batch verification")

    batch = []
    for _ in range(5):
        f   = sim.get_next_frame()
        p   = builder.build(f)
        s   = signer.sign_packet(p)
        ci  = ZKPVerifier.generate_commitment(s['payload'])
        e   = enc.encrypt_packet(s)
        d   = dec.decrypt(e)
        r   = reenc.reencrypt(d)
        pt  = val_eng.decrypt(
            nonce=r['nonce_bytes'],
            ciphertext=r['ciphertext_bytes'],
            associated_data=r['header'],
        )
        vp  = dict(r)
        vp['payload_bytes']  = pt
        vp['zkp_commitment'] = ci['commitment']
        vp['zkp_nonce']      = ci['nonce']
        batch.append(vp)

    ok, failed = verifier.verify_batch(batch)
    print(f"  Verified: {len(ok)}")
    print(f"  Failed:   {len(failed)}")
    assert len(ok)     == 5
    assert len(failed) == 0
    print(f"  Batch ZKP: ✅")

    print(f"\n  Verified: {verifier.verified_count}")
    print(f"  Failed:   {verifier.failed_count}")
    print(f"  Skipped:  {verifier.skipped_count}")
    print(f"\n✅ ZKPVerifier self-test complete.")