"""Transform chain encode/decode/validate operations.

Implements the data transforms used in C2 profiles (base64, base64url,
mask, netbios, prepend, append, etc.) for both encoding outbound data
and validating/decoding inbound data.
"""

from __future__ import annotations

import base64
import struct
from typing import Sequence

from infraguard.profiles.models import Transform


def _base64_encode(data: bytes) -> bytes:
    return base64.b64encode(data)


def _base64_decode(data: bytes) -> bytes:
    # Be lenient with padding
    padded = data + b"=" * (-len(data) % 4)
    return base64.b64decode(padded, validate=False)


def _base64url_encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data)


def _base64url_decode(data: bytes) -> bytes:
    padded = data + b"=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _mask_encode(data: bytes) -> bytes:
    """XOR mask encoding used by Cobalt Strike.

    Prepends a 4-byte random key and XORs the data with it.
    """
    import os

    key = os.urandom(4)
    masked = bytes(b ^ key[i % 4] for i, b in enumerate(data))
    return key + masked


def _mask_decode(data: bytes) -> bytes:
    """Reverse XOR mask: first 4 bytes are the key."""
    if len(data) < 4:
        return data
    key = data[:4]
    return bytes(b ^ key[i % 4] for i, b in enumerate(data[4:]))


def _netbios_encode(data: bytes) -> bytes:
    """NetBIOS encoding (lowercase): each byte -> two lowercase letters."""
    result = bytearray()
    for b in data:
        result.append(ord("a") + (b >> 4))
        result.append(ord("a") + (b & 0xF))
    return bytes(result)


def _netbios_decode(data: bytes) -> bytes:
    result = bytearray()
    for i in range(0, len(data) - 1, 2):
        high = data[i] - ord("a")
        low = data[i + 1] - ord("a")
        result.append((high << 4) | low)
    return bytes(result)


def _netbiosu_encode(data: bytes) -> bytes:
    """NetBIOS encoding (uppercase): each byte -> two uppercase letters."""
    result = bytearray()
    for b in data:
        result.append(ord("A") + (b >> 4))
        result.append(ord("A") + (b & 0xF))
    return bytes(result)


def _netbiosu_decode(data: bytes) -> bytes:
    result = bytearray()
    for i in range(0, len(data) - 1, 2):
        high = data[i] - ord("A")
        low = data[i + 1] - ord("A")
        result.append((high << 4) | low)
    return bytes(result)


def _prepend_encode(data: bytes, value: str) -> bytes:
    return value.encode() + data


def _prepend_decode(data: bytes, value: str) -> bytes:
    prefix = value.encode()
    if data.startswith(prefix):
        return data[len(prefix) :]
    return data


def _append_encode(data: bytes, value: str) -> bytes:
    return data + value.encode()


def _append_decode(data: bytes, value: str) -> bytes:
    suffix = value.encode()
    if data.endswith(suffix):
        return data[: -len(suffix)]
    return data


_ENCODERS = {
    "base64": _base64_encode,
    "base64url": _base64url_encode,
    "mask": _mask_encode,
    "netbios": _netbios_encode,
    "netbiosu": _netbiosu_encode,
}

_DECODERS = {
    "base64": _base64_decode,
    "base64url": _base64url_decode,
    "mask": _mask_decode,
    "netbios": _netbios_decode,
    "netbiosu": _netbiosu_decode,
}


class TransformChain:
    """Execute a sequence of transforms in order.

    Encoding applies transforms in order (first to last).
    Decoding applies transforms in reverse order (last to first).
    """

    def __init__(self, transforms: Sequence[Transform]):
        self.transforms = list(transforms)

    def encode(self, data: bytes) -> bytes:
        """Apply transforms forward (for response wrapping)."""
        result = data
        for t in self.transforms:
            if t.action in ("prepend", "append"):
                if t.action == "prepend":
                    result = _prepend_encode(result, t.value)
                else:
                    result = _append_encode(result, t.value)
            elif t.action == "strrep":
                # strrep is compile-time only, skip at runtime
                continue
            elif t.action == "print":
                continue
            else:
                encoder = _ENCODERS.get(t.action)
                if encoder:
                    result = encoder(result)
        return result

    def decode(self, data: bytes) -> bytes:
        """Reverse transforms (for request validation / data extraction)."""
        result = data
        for t in reversed(self.transforms):
            if t.action in ("prepend", "append"):
                if t.action == "prepend":
                    result = _prepend_decode(result, t.value)
                else:
                    result = _append_decode(result, t.value)
            elif t.action in ("strrep", "print"):
                continue
            else:
                decoder = _DECODERS.get(t.action)
                if decoder:
                    result = decoder(result)
        return result

    def validate_prepend_append(self, data: bytes) -> bool:
        """Check that expected prepend/append patterns are present in the data."""
        for t in self.transforms:
            if t.action == "prepend" and t.value:
                if not data.startswith(t.value.encode()):
                    return False
            elif t.action == "append" and t.value:
                if not data.endswith(t.value.encode()):
                    return False
        return True
