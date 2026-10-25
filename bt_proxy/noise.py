"""Responder side of the ESPHome Native API's Noise encryption.

ESPHome uses Noise_NNpsk0_25519_ChaChaPoly_SHA256 (https://noiseprotocol.org/
noise.html): both sides prove knowledge of a 32-byte pre-shared key, with
ephemeral X25519 keys for forward secrecy. Implemented here on top of
``cryptography`` because OpenWrt and most distros package it, unlike
``noiseprotocol``.

``cryptography`` is optional, so import this module only when a key is set.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PROTOCOL_NAME = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"
DHLEN = 32
TAGLEN = 16
# Noise caps a message at 65535 bytes, including the AEAD tag.
MAX_PLAINTEXT = 65535 - TAGLEN


def decode_psk(key: str) -> bytes:
    """Decode a base64 key as ESPHome's ``api: encryption: key:`` holds it."""
    psk = base64.b64decode(key.strip(), validate=True)
    if len(psk) != 32:
        raise ValueError(f"encryption key must be 32 bytes, got {len(psk)}")
    return psk


def _hkdf(ck: bytes, ikm: bytes, n: int) -> list[bytes]:
    temp = hmac.digest(ck, ikm, "sha256")
    out = [hmac.digest(temp, b"\x01", "sha256")]
    for i in range(2, n + 1):
        out.append(hmac.digest(temp, out[-1] + bytes((i,)), "sha256"))
    return out


class CipherState:
    """A transport key with its nonce counter."""

    def __init__(self, key: bytes):
        self._aead = ChaCha20Poly1305(key)
        self._n = 0

    def _nonce(self) -> bytes:
        # Noise forbids nonce 2^64-1; a connection won't get near it.
        nonce = b"\x00" * 4 + self._n.to_bytes(8, "little")
        self._n += 1
        return nonce

    def encrypt(self, plaintext: bytes, ad: bytes = b"") -> bytes:
        if len(plaintext) > MAX_PLAINTEXT:
            raise ValueError(
                f"{len(plaintext)} bytes exceeds a Noise message's {MAX_PLAINTEXT}"
            )
        return self._aead.encrypt(self._nonce(), plaintext, ad)

    def decrypt(self, ciphertext: bytes, ad: bytes = b"") -> bytes:
        # The nonce advances even on failure, but the caller drops the
        # connection.
        try:
            return self._aead.decrypt(self._nonce(), ciphertext, ad)
        except InvalidTag:
            raise ValueError("message failed authentication") from None


class NoiseResponder:
    """Noise_NNpsk0 handshake, responder role.

    -> psk, e
    <- e, ee
    """

    def __init__(self, psk: bytes, prologue: bytes):
        self._psk = psk
        # The protocol name exceeds HASHLEN, so h starts as its hash.
        self._h = hashlib.sha256(PROTOCOL_NAME).digest()
        self._ck = self._h
        self._k: CipherState | None = None
        self._mix_hash(prologue)

    def _mix_hash(self, data: bytes) -> None:
        self._h = hashlib.sha256(self._h + data).digest()

    def _mix_key(self, ikm: bytes) -> None:
        self._ck, k = _hkdf(self._ck, ikm, 2)
        self._k = CipherState(k)

    def _mix_key_and_hash(self, ikm: bytes) -> None:
        self._ck, h, k = _hkdf(self._ck, ikm, 3)
        self._mix_hash(h)
        self._k = CipherState(k)

    def _encrypt_and_hash(self, plaintext: bytes) -> bytes:
        assert self._k is not None
        ciphertext = self._k.encrypt(plaintext, self._h)
        self._mix_hash(ciphertext)
        return ciphertext

    def _decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        assert self._k is not None
        plaintext = self._k.decrypt(ciphertext, self._h)
        self._mix_hash(ciphertext)
        return plaintext

    def respond(self, message: bytes) -> tuple[bytes, CipherState, CipherState]:
        """Read the initiator's message and return (reply, send, receive).

        Raises ValueError if the initiator used a different key.
        """
        if len(message) < DHLEN + TAGLEN:
            raise ValueError("handshake message too short")

        # -> psk, e. In psk modes, e is also mixed into the key.
        self._mix_key_and_hash(self._psk)
        re_pub = message[:DHLEN]
        self._mix_hash(re_pub)
        self._mix_key(re_pub)
        self._decrypt_and_hash(message[DHLEN:])

        # <- e, ee
        e = X25519PrivateKey.generate()
        e_pub = e.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._mix_hash(e_pub)
        self._mix_key(e_pub)
        self._mix_key(e.exchange(X25519PublicKey.from_public_bytes(re_pub)))
        reply = e_pub + self._encrypt_and_hash(b"")

        # Split: the initiator sends with the first key.
        k1, k2 = _hkdf(self._ck, b"", 2)
        return reply, CipherState(k2), CipherState(k1)
