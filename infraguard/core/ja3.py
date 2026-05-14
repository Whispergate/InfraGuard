"""Pure-Python JA3 TLS ClientHello fingerprinting.

JA3 is computed from the raw TLS ClientHello record before the SSL handshake
completes. The fingerprint is the MD5 of a comma-joined string of decimal
values extracted from the ClientHello:

  SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

GREASE values (RFC 8701) are excluded before hashing.

References:
  - https://github.com/salesforce/ja3
  - https://tlsfingerprint.io/
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

# GREASE values as defined in RFC 8701
_GREASE: frozenset[int] = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
})

# TLS record type
_TLS_HANDSHAKE = 0x16
_TLS_CLIENT_HELLO = 0x01


@dataclass
class ClientHelloFields:
    version: int = 0
    cipher_suites: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    elliptic_curves: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)


def parse_client_hello(data: bytes) -> ClientHelloFields | None:
    """Parse raw bytes (may be partial) to extract ClientHello fields.

    Returns None if the data is not a valid/complete TLS ClientHello.
    """
    try:
        return _parse(data)
    except Exception:
        return None


def _parse(data: bytes) -> ClientHelloFields | None:
    if len(data) < 6:
        return None

    # TLS record header: type(1) version(2) length(2)
    if data[0] != _TLS_HANDSHAKE:
        return None

    record_len = struct.unpack(">H", data[3:5])[0]
    if len(data) < 5 + record_len:
        return None  # incomplete record

    # Handshake header: type(1) length(3)
    pos = 5
    if data[pos] != _TLS_CLIENT_HELLO:
        return None

    pos += 4  # skip type + 3-byte length

    fields = ClientHelloFields()

    # ClientHello version (2 bytes)
    if pos + 2 > len(data):
        return None
    fields.version = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2

    # Random (32 bytes)
    pos += 32
    if pos > len(data):
        return None

    # Session ID
    if pos >= len(data):
        return None
    sid_len = data[pos]
    pos += 1 + sid_len

    # Cipher suites
    if pos + 2 > len(data):
        return None
    cs_len = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    cs_end = pos + cs_len
    if cs_end > len(data):
        return None
    while pos < cs_end:
        cs = struct.unpack(">H", data[pos:pos + 2])[0]
        if cs not in _GREASE:
            fields.cipher_suites.append(cs)
        pos += 2

    # Compression methods
    if pos >= len(data):
        return None
    cm_len = data[pos]
    pos += 1 + cm_len

    # Extensions
    if pos + 2 > len(data):
        return fields  # no extensions - still valid
    ext_total_len = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    ext_end = pos + ext_total_len
    if ext_end > len(data):
        ext_end = len(data)

    while pos + 4 <= ext_end:
        ext_type = struct.unpack(">H", data[pos:pos + 2])[0]
        ext_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        pos += 4
        ext_data_end = pos + ext_len

        if ext_type not in _GREASE:
            fields.extensions.append(ext_type)

        # Extension 0x000a: supported_groups (elliptic curves)
        if ext_type == 0x000a and pos + 2 <= ext_data_end:
            curves_len = struct.unpack(">H", data[pos:pos + 2])[0]
            c_pos = pos + 2
            c_end = c_pos + curves_len
            while c_pos + 2 <= min(c_end, ext_data_end):
                curve = struct.unpack(">H", data[c_pos:c_pos + 2])[0]
                if curve not in _GREASE:
                    fields.elliptic_curves.append(curve)
                c_pos += 2

        # Extension 0x000b: ec_point_formats
        elif ext_type == 0x000b and pos < ext_data_end:
            fmt_len = data[pos]
            f_pos = pos + 1
            f_end = f_pos + fmt_len
            while f_pos < min(f_end, ext_data_end):
                fields.ec_point_formats.append(data[f_pos])
                f_pos += 1

        pos = ext_data_end

    return fields


def compute_ja3(fields: ClientHelloFields) -> str:
    """Compute the JA3 fingerprint string and return its MD5 hex digest."""
    ja3_str = (
        f"{fields.version},"
        f"{'-'.join(str(c) for c in fields.cipher_suites)},"
        f"{'-'.join(str(e) for e in fields.extensions)},"
        f"{'-'.join(str(c) for c in fields.elliptic_curves)},"
        f"{'-'.join(str(f) for f in fields.ec_point_formats)}"
    )
    return hashlib.md5(ja3_str.encode()).hexdigest()  # noqa: S324 - JA3 spec requires MD5
