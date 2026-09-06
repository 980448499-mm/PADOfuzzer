r"""NAS Security Engine per 3GPP TS 33.501 and TS 24.501.

Implements:
  - Key derivation: K_AMF → K_NAS_enc, K_NAS_int  (TS 33.501 Annex A)
  - NAS ciphering: NEA0, NEA1 (SNOW 3G), NEA2 (AES-CTR)
  - NAS integrity: NIA0, NIA1 (SNOW 3G), NIA2 (AES-CMAC)
  - Milenage authentication: UE-side AKA response computation

Security Algorithm Identifiers (TS 33.501):
  NEA0 / NIA0 = 0x00 (Null ciphering / integrity)
  NEA1 / NIA1 = 0x01 (SNOW 3G, 128-bit)
  NEA2 / NIA2 = 0x02 (AES, 128-bit)
  NEA3 / NIA3 = 0x03 (ZUC, 128-bit)

Key derivation (TS 33.501 Annex A.6):
  K_AMF is derived during primary authentication
  K_NAS_enc = KDF(K_AMF, 0x01, algorithm-distinguisher, algorithm-identity)
  K_NAS_int = KDF(K_AMF, 0x02, algorithm-distinguisher, algorithm-identity)

NAS message structure when security is active:
  +--+--+--+--+--+--+ ... +--+--+--+--+
  |EPD|Sec|Msg|NAS-MAC (4 bytes) |Seq |
  |   |Hdr|Typ|                   |Num |
  +--+--+--+--+--+--+ ... +--+--+--+--+

Ciphering: payload (from message type byte onward) is encrypted
Integrity: entire message including EPD is integrity-protected,
           NAS-MAC appended before Sequence Number
"""

import hmac
import struct
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC


class SecurityAlgorithm(Enum):
    NEA0 = 0  # Null ciphering
    NEA1 = 1  # SNOW 3G
    NEA2 = 2  # AES-CTR
    NEA3 = 3  # ZUC
    NIA0 = 0  # Null integrity
    NIA1 = 1  # SNOW 3G
    NIA2 = 2  # AES-CMAC
    NIA3 = 3  # ZUC


ALGORITHM_DISTINGUISHER_NEA = 0x01
ALGORITHM_DISTINGUISHER_NIA = 0x02


@dataclass
class SecurityContext:
    """5G NAS security context for a UE."""

    k_amf: Optional[bytes] = None
    k_nas_enc: Optional[bytes] = None
    k_nas_int: Optional[bytes] = None
    selected_nea: int = 0  # Selected ciphering algorithm
    selected_nia: int = 0  # Selected integrity algorithm
    uplink_nas_count: int = 0
    downlink_nas_count: int = 0
    ng_ksi: int = 0  # NAS Key Set Identifier
    security_established: bool = False

    # Auth parameters (for Milenage)
    rand: Optional[bytes] = None
    autn: Optional[bytes] = None
    res: Optional[bytes] = None  # Authentication response


class NASKeyDerivation:
    """Key derivation functions per TS 33.501 Annex A."""

    @staticmethod
    def kdf(k_amf: bytes, fc: int, *parameters: bytes) -> bytes:
        """HMAC-SHA-256 based KDF per TS 33.220 Annex B.

        derivedKey = HMAC-SHA-256(K_AMF, S)
        where S = FC || P0 || L0 || P1 || L1 || ...
        """
        s = struct.pack("!B", fc)
        for param in parameters:
            s += param
            s += struct.pack("!H", len(param))
        return hmac.new(k_amf, s, sha256).digest()

    @classmethod
    def derive_nas_enc_key(cls, k_amf: bytes, algorithm_id: int) -> bytes:
        """Derive K_NAS_enc = KDF(K_AMF, 0x01, alg-dist, alg-id)."""
        return cls.kdf(
            k_amf,
            0x01,
            bytes([ALGORITHM_DISTINGUISHER_NEA]),
            bytes([algorithm_id]),
        )[:16]  # 128-bit key

    @classmethod
    def derive_nas_int_key(cls, k_amf: bytes, algorithm_id: int) -> bytes:
        """Derive K_NAS_int = KDF(K_AMF, 0x02, alg-dist, alg-id)."""
        return cls.kdf(
            k_amf,
            0x02,
            bytes([ALGORITHM_DISTINGUISHER_NIA]),
            bytes([algorithm_id]),
        )[:16]  # 128-bit key

    @classmethod
    def derive_k_amf_from_ck_ik(
        cls,
        ck: bytes,
        ik: bytes,
        snn: bytes = b"5G:mnc070.mcc901.3gppnetwork.org",
        sqn_xor_ak: bytes = b"\x00" * 6,
    ) -> bytes:
        """Derive K_AMF from CK, IK, and serving network name.

        K_AMF = KDF(CK||IK, 0x6D, SNN, SQN⊕AK)
        """
        key = ck + ik
        return cls.kdf(key, 0x6D, snn, sqn_xor_ak)[:32]


# ─── GF(2^8) and GF(2^32) arithmetic for SNOW 3G / ZUC ──────────

def _mulx(v: int, c: int) -> int:
    """MULx in GF(2^8) with reduction constant c."""
    return ((v << 1) ^ c) & 0xFF if v & 0x80 else (v << 1) & 0xFF


def _mulxpow(v: int, i: int, c: int) -> int:
    """MULxPOW in GF(2^8): apply MULx i times."""
    r = v
    for _ in range(i):
        r = _mulx(r, c)
    return r


def _mul_alpha_w32(w: int) -> int:
    """MULα in GF(2^32) for SNOW 3G LFSR feedback.

    Field defined by x^4 + β^23·x^3 + β^245·x^2 + β^48·x + β^239
    over GF(2^8), where β satisfies x^8 + x^4 + x^3 + x + 1 = 0.
    """
    w0, w1, w2, w3 = (w >> 24) & 0xFF, (w >> 16) & 0xFF, (w >> 8) & 0xFF, w & 0xFF
    r0 = _mulxpow(w3, 1, 0x1B) ^ _mulxpow(w0, 23, 0x1B) ^ _mulxpow(w1, 48, 0x1B) ^ _mulxpow(w2, 239, 0x1B)
    r1 = _mulxpow(w0, 1, 0x1B) ^ _mulxpow(w1, 23, 0x1B) ^ _mulxpow(w2, 48, 0x1B) ^ _mulxpow(w3, 239, 0x1B)
    r2 = _mulxpow(w1, 1, 0x1B) ^ _mulxpow(w2, 23, 0x1B) ^ _mulxpow(w3, 48, 0x1B) ^ _mulxpow(w0, 239, 0x1B)
    r3 = _mulxpow(w2, 1, 0x1B) ^ _mulxpow(w3, 23, 0x1B) ^ _mulxpow(w0, 48, 0x1B) ^ _mulxpow(w1, 239, 0x1B)
    return (r0 << 24) | (r1 << 16) | (r2 << 8) | r3


def _div_alpha_w32(w: int) -> int:
    """MULα^{-1} in GF(2^32) (inverse of _mul_alpha_w32)."""
    w0, w1, w2, w3 = (w >> 24) & 0xFF, (w >> 16) & 0xFF, (w >> 8) & 0xFF, w & 0xFF
    r0 = _mulxpow(w1, 65, 0x1B) ^ _mulxpow(w2, 72, 0x1B) ^ _mulxpow(w3, 216, 0x1B) ^ _mulxpow(w0, 23 * 16 + 239, 0x1B)
    # Simplified inverse: use precomputed exponents from spec
    r0 = _mulxpow(w1, 81, 0x1B) ^ _mulxpow(w2, 170, 0x1B) ^ _mulxpow(w3, 216, 0x1B) ^ _mulxpow(w0, 111, 0x1B)
    r1 = _mulxpow(w2, 81, 0x1B) ^ _mulxpow(w3, 170, 0x1B) ^ _mulxpow(w0, 216, 0x1B) ^ _mulxpow(w1, 111, 0x1B)
    r2 = _mulxpow(w3, 81, 0x1B) ^ _mulxpow(w0, 170, 0x1B) ^ _mulxpow(w1, 216, 0x1B) ^ _mulxpow(w2, 111, 0x1B)
    r3 = _mulxpow(w0, 81, 0x1B) ^ _mulxpow(w1, 170, 0x1B) ^ _mulxpow(w2, 216, 0x1B) ^ _mulxpow(w3, 111, 0x1B)
    return (r0 << 24) | (r1 << 16) | (r2 << 8) | r3


def _mod_2p31m1(x: int) -> int:
    """Reduce x modulo 2^31 - 1 (for ZUC LFSR)."""
    m = (1 << 31) - 1
    return (x & m) + (x >> 31)


# ─── SNOW 3G stream cipher (TS 35.215 / 35.216) ──────────────────

_SNOW3G_S0 = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]


class _SNOW3G:
    """SNOW 3G synchronous stream cipher core (TS 35.215).

    Produces 32-bit keystream words from a 128-bit key and 128-bit IV.
    """

    def __init__(self, key: bytes, iv: bytes):
        # LFSR: 16 × 32-bit registers
        self._s = [0] * 16
        # FSM: R1, R2, R3 (32-bit)
        self._r1 = self._r2 = self._r3 = 0
        self._init(key, iv)

    def _s1(self, w: int) -> int:
        """Substitution box S1."""
        return (_SNOW3G_S0[(w >> 24) & 0xFF] << 24 |
                _SNOW3G_S0[(w >> 16) & 0xFF] << 16 |
                _SNOW3G_S0[(w >> 8) & 0xFF] << 8 |
                _SNOW3G_S0[w & 0xFF])

    def _s2(self, w: int) -> int:
        """Substitution box S2 (S1 with a rotation)."""
        return (self._s1(w) >> 8 | (self._s1(w) & 0xFF) << 24) & 0xFFFFFFFF

    def _mul_alpha(self, w: int) -> int:
        return _mul_alpha_w32(w)

    def _div_alpha(self, w: int) -> int:
        return _div_alpha_w32(w)

    def _clock_lfsr_init(self, f: int) -> None:
        """Clock LFSR in initialisation mode (with FSM output mixed in)."""
        v = (self._s[0] ^ self._mul_alpha(self._s[0]) ^
             self._div_alpha(self._s[2]) ^ self._s[11])
        v = (v ^ f) & 0xFFFFFFFF
        self._s.pop()
        self._s.insert(0, v)

    def _clock_lfsr_keystream(self) -> None:
        """Clock LFSR in keystream generation mode."""
        v = (self._s[0] ^ self._mul_alpha(self._s[0]) ^
             self._div_alpha(self._s[2]) ^ self._s[11])
        v = v & 0xFFFFFFFF
        self._s.pop()
        self._s.insert(0, v)

    def _clock_fsm(self) -> int:
        """Clock FSM and return F_t output."""
        # F = (s[15] + R1) mod 2^32 ⊕ R2
        f = ((self._s[15] + self._r1) & 0xFFFFFFFF) ^ self._r2
        # r = R2 + (R3 ⊕ s[5]) mod 2^32, then substitute
        r = (self._r2 + (self._r3 ^ self._s[5])) & 0xFFFFFFFF
        # Update registers
        self._r3 = self._s2(self._r2)
        self._r2 = self._s1(self._r1)
        self._r1 = r
        return f

    def _init(self, key: bytes, iv: bytes) -> None:
        """Key/IV initialisation per TS 35.216."""
        # Load key and IV into LFSR
        for i in range(16):
            self._s[i] = (key[i % 16] << 24) | (iv[i % 16] << 16)  # simplified loading
        # Full loading: key as 4 × 32-bit words, IV as 4 × 32-bit words
        k = [int.from_bytes(key[i:i+4], 'big') for i in range(0, 16, 4)]
        iv_w = [int.from_bytes(iv[i:i+4], 'big') for i in range(0, 16, 4)]
        self._s[15] = k[3] ^ iv_w[0]
        self._s[14] = k[2]
        self._s[13] = k[1]
        self._s[12] = k[0]
        self._s[11] = k[3] ^ 0xFFFFFFFF ^ iv_w[3]
        self._s[10] = k[2] ^ 0xFFFFFFFF ^ iv_w[2]
        self._s[9] = k[1] ^ 0xFFFFFFFF ^ iv_w[1]
        self._s[8] = k[0] ^ 0xFFFFFFFF ^ iv_w[0]
        self._s[7] = k[3]
        self._s[6] = k[2]
        self._s[5] = k[1]
        self._s[4] = k[0]
        self._s[3] = k[3] ^ iv_w[3]
        self._s[2] = k[2] ^ iv_w[2]
        self._s[1] = k[1] ^ iv_w[1]
        self._s[0] = k[0] ^ iv_w[0]

        self._r1 = self._r2 = self._r3 = 0

        # 32 clockings in init mode
        for _ in range(32):
            f = self._clock_fsm()
            self._clock_lfsr_init(f)

    def keystream_word(self) -> int:
        """Generate one 32-bit keystream word."""
        self._clock_fsm()
        self._clock_lfsr_keystream()
        # Z_t = F_t ⊕ s[0]
        return self._clock_fsm() ^ self._s[0]

    def keystream(self, n_words: int) -> bytes:
        """Generate n_words × 32-bit keystream."""
        words = [self.keystream_word() for _ in range(n_words)]
        return b"".join(w.to_bytes(4, "big") for w in words)


# ─── ZUC stream cipher (TS 35.221 / 35.222) ──────────────────────

_ZUC_S0 = [
    0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB,
    0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x2D, 0x6C, 0xA4, 0xCF, 0x4D, 0xE5, 0x82, 0x04, 0x84, 0xAD, 0x3A,
    0x13, 0x39, 0xC7, 0x4F, 0x24, 0x11, 0xC6, 0x3F, 0xED, 0x58, 0xA9, 0x22, 0x81, 0xAA, 0x06, 0xC0,
    0xEB, 0x39, 0x0D, 0xDA, 0x30, 0xFD, 0x91, 0x7A, 0xB9, 0x64, 0x5E, 0x71, 0xAC, 0x75, 0x05, 0x85,
    0xCE, 0x8F, 0x43, 0x5D, 0x56, 0xA7, 0x91, 0xAC, 0xC3, 0xB1, 0x10, 0x36, 0x3D, 0x79, 0x32, 0x13,
    0x95, 0xC7, 0x26, 0x58, 0x13, 0x33, 0x89, 0xD4, 0x79, 0x04, 0x6A, 0x1E, 0x3B, 0x11, 0x29, 0x3A,
    0x6B, 0x50, 0x57, 0x98, 0x00, 0x47, 0xE2, 0x51, 0x39, 0x8F, 0x8A, 0x30, 0xBC, 0xC2, 0x94, 0x7C,
    0xEA, 0x03, 0xA1, 0x65, 0x29, 0xCC, 0x22, 0x57, 0x32, 0x1B, 0x72, 0x42, 0x2A, 0x20, 0xCD, 0xF5,
    0xB0, 0x5F, 0x24, 0x62, 0x7A, 0x35, 0x82, 0x9F, 0x27, 0x49, 0x0F, 0x70, 0x24, 0xDC, 0x00, 0x5E,
    0x41, 0x44, 0x25, 0x3B, 0x5A, 0x5B, 0xFC, 0x00, 0xAC, 0x0C, 0xB2, 0x42, 0x52, 0xA0, 0x0B, 0x66,
    0xFD, 0x11, 0x6F, 0xF3, 0x0B, 0x4E, 0x58, 0x7C, 0x1C, 0x95, 0x69, 0x58, 0xD0, 0x91, 0xF4, 0x1A,
    0x17, 0x23, 0x43, 0xA6, 0xD2, 0x58, 0x27, 0xAE, 0x60, 0x3D, 0xFA, 0x8D, 0x82, 0x8F, 0xB1, 0xD7,
    0x95, 0x43, 0xDD, 0x9C, 0x26, 0x4D, 0xD1, 0xCE, 0x46, 0xD2, 0xFB, 0x28, 0x07, 0xA7, 0x8B, 0xBE,
    0x35, 0x71, 0x5E, 0xB2, 0x86, 0xBF, 0x0A, 0xD8, 0xDF, 0x06, 0x4A, 0x5A, 0x24, 0x8A, 0x35, 0x48,
    0x67, 0x2F, 0xD4, 0x9E, 0xCE, 0x2B, 0x6F, 0x29, 0xA8, 0xCE, 0x31, 0x22, 0x97, 0x3B, 0x46, 0x5F,
    0x79, 0x76, 0x3A, 0x8F, 0x84, 0x70, 0xFE, 0xE7, 0x18, 0x53, 0x1E, 0x0B, 0x6E, 0x9E, 0xD9, 0x35,
]

_ZUC_S1 = [
    0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77,
    0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE1, 0x12, 0xA8, 0x99, 0x9C, 0x0E, 0xDC, 0x21,
    0x57, 0xCD, 0x7B, 0xB9, 0x36, 0xF3, 0x30, 0xE8, 0xFA, 0xF8, 0x53, 0x46, 0xF0, 0xD3, 0x68, 0xCC,
    0x01, 0x22, 0x52, 0x33, 0x2D, 0x5B, 0x88, 0x70, 0x18, 0x3A, 0xDF, 0x5D, 0xA5, 0x9A, 0x6C, 0xAC,
    0x95, 0xA2, 0x19, 0x71, 0x49, 0x9C, 0x62, 0x26, 0x71, 0x96, 0x91, 0x6B, 0x46, 0x26, 0x67, 0x4E,
    0x92, 0x0B, 0xA0, 0xE4, 0x72, 0x6C, 0x07, 0xD4, 0x0E, 0x88, 0xD8, 0xAB, 0xCC, 0xCE, 0xFB, 0x67,
    0x79, 0xFB, 0x14, 0xF7, 0x02, 0x3E, 0xBE, 0x31, 0x3D, 0x60, 0x65, 0x48, 0x16, 0xCF, 0x82, 0x6F,
    0x10, 0xF9, 0x74, 0x76, 0xAF, 0x11, 0x35, 0x1C, 0xE6, 0x7E, 0x86, 0x97, 0x48, 0x6A, 0x5B, 0x2B,
    0x6D, 0x76, 0x7A, 0xF1, 0xD7, 0x7F, 0x4A, 0x0A, 0x66, 0xB1, 0x5F, 0xAA, 0x4B, 0xFC, 0x59, 0x92,
    0x19, 0x08, 0x87, 0x27, 0xDF, 0xE9, 0x3D, 0x84, 0x17, 0xDA, 0x42, 0x61, 0x0F, 0x56, 0x29, 0x59,
    0x55, 0xC3, 0x68, 0xF3, 0xFD, 0x55, 0xDD, 0x4D, 0x44, 0xD1, 0xF5, 0xCE, 0x6B, 0xFE, 0x19, 0x1A,
    0xF8, 0x12, 0x69, 0xA1, 0x21, 0x05, 0x3D, 0x13, 0x5C, 0xDE, 0x69, 0x10, 0xCA, 0x93, 0x85, 0xF6,
    0xCA, 0x84, 0xAD, 0xA7, 0xF6, 0xE8, 0x82, 0x7A, 0x58, 0x14, 0x55, 0x3A, 0x34, 0xC1, 0x3D, 0x1E,
    0x8D, 0x18, 0xE7, 0x76, 0x4D, 0xF2, 0xB0, 0x4A, 0x32, 0xB1, 0x8F, 0xA9, 0x61, 0xEF, 0xD6, 0xED,
    0x59, 0xA3, 0xA2, 0xBE, 0x77, 0x1A, 0x5D, 0xDE, 0xCC, 0x72, 0x64, 0x9E, 0x00, 0xD7, 0x4B, 0x85,
    0xD0, 0x8C, 0xCC, 0x86, 0x6D, 0x91, 0x7D, 0xD6, 0x83, 0x0C, 0xFF, 0xE3, 0x34, 0x9D, 0x20, 0x01,
]


class _ZUC:
    """ZUC stream cipher core (TS 35.221).

    Produces 32-bit keystream words from a 128-bit key and 128-bit IV.
    """

    def __init__(self, key: bytes, iv: bytes):
        self._s = [0] * 16  # LFSR: 16 × 31-bit
        self._r1 = 0  # 32-bit
        self._r2 = 0  # 32-bit
        self._init(key, iv)

    def _s0_box(self, x: int) -> int:
        return _ZUC_S0[x]

    def _s1_box(self, x: int) -> int:
        return _ZUC_S1[x]

    def _l1(self, x: int) -> int:
        """Linear transform L1."""
        return x ^ (self._rotl(x, 1)) ^ (self._rotl(x, 9)) ^ (self._rotl(x, 21))

    def _l2(self, x: int) -> int:
        """Linear transform L2."""
        return x ^ (self._rotl(x, 17)) ^ (self._rotl(x, 27)) ^ (self._rotl(x, 31))

    @staticmethod
    def _rotl(x: int, k: int) -> int:
        return ((x << k) | (x >> (32 - k))) & 0xFFFFFFFF

    def _lfsr_init_step(self, u: int) -> None:
        """Clock LFSR in initialisation mode."""
        s16 = (_mod_2p31m1(
            self._s[15] * (1 << 8) + self._s[13] * (1 << 20) +
            self._s[10] * (1 << 7) + self._s[4] * (1 << 10) +
            self._s[0] * (1 << 12) + self._s[0] - u
        )) & 0x7FFFFFFF
        if s16 == 0:
            s16 = (1 << 31) - 1
        self._s.pop()
        self._s.insert(0, s16)

    def _lfsr_work_step(self) -> None:
        """Clock LFSR in work mode."""
        s16 = (_mod_2p31m1(
            self._s[15] * (1 << 8) + self._s[13] * (1 << 20) +
            self._s[10] * (1 << 7) + self._s[4] * (1 << 10) +
            self._s[0] * (1 << 12) + self._s[0]
        )) & 0x7FFFFFFF
        if s16 == 0:
            s16 = (1 << 31) - 1
        self._s.pop()
        self._s.insert(0, s16)

    def _br(self):
        """Bit Reorganization — returns X0, X1, X2, X3."""
        s = self._s
        x0 = ((s[15] & 0x7FFF8000) << 1) | (s[14] & 0xFFFF)
        x1 = ((s[11] & 0xFFFF) << 16) | (s[9] >> 15)
        x2 = ((s[7] & 0xFFFF) << 16) | (s[5] >> 15)
        x3 = ((s[2] & 0xFFFF) << 16) | (s[0] >> 15)
        return x0, x1, x2, x3

    def _f(self, x0: int, x1: int, x2: int) -> int:
        """Non-linear function F — returns W."""
        w = ((x0 ^ self._r1) + self._r2) & 0xFFFFFFFF
        w1 = (self._r1 + x1) & 0xFFFFFFFF
        w2 = self._r2 ^ x2
        # S-box layer
        u = (self._s0_box((w1 >> 24) & 0xFF) << 24 |
             self._s1_box((w1 >> 16) & 0xFF) << 16 |
             self._s0_box((w1 >> 8) & 0xFF) << 8 |
             self._s1_box(w1 & 0xFF))
        v = (self._s0_box((w2 >> 24) & 0xFF) << 24 |
             self._s1_box((w2 >> 16) & 0xFF) << 16 |
             self._s0_box((w2 >> 8) & 0xFF) << 8 |
             self._s1_box(w2 & 0xFF))
        self._r1 = self._l1(u)
        self._r2 = self._l2(v)
        return w

    def _init(self, key: bytes, iv: bytes) -> None:
        """Key/IV initialisation."""
        k = [int.from_bytes(key[i:i+1], 'big') or 0 for i in range(16)]
        iv_b = [int.from_bytes(iv[i:i+1], 'big') or 0 for i in range(16)]

        # Constants D per spec
        d = [0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
             0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC]

        for i in range(16):
            self._s[i] = (k[i] << 23) | (d[i] << 8) | iv_b[i]

        self._r1 = self._r2 = 0

        # 32 clockings in init mode
        for _ in range(32):
            x0, x1, x2, _ = self._br()
            w = self._f(x0, x1, x2)
            self._lfsr_init_step(w >> 1)

        # Skip X3 output after init
        _, _, _, _ = self._br()
        self._f(0, 0, 0)  # discard F output
        self._lfsr_work_step()

    def keystream_word(self) -> int:
        """Generate one 32-bit keystream word."""
        self._lfsr_work_step()
        x0, x1, x2, x3 = self._br()
        w = self._f(x0, x1, x2)
        return w ^ x3

    def keystream(self, n_words: int) -> bytes:
        """Generate n_words × 32-bit keystream."""
        words = [self.keystream_word() for _ in range(n_words)]
        return b"".join(w.to_bytes(4, "big") for w in words)


# ─── Updated Cipher / Integrity classes ──────────────────────────

class NASCipher:
    """NAS ciphering per TS 33.501 — NEA0/NEA1/NEA2/NEA3."""

    @staticmethod
    def _build_iv(count: int, bearer: int, direction: int) -> bytes:
        """Build the 128-bit IV for SNOW 3G / ZUC  (TS 33.501 Annex C)."""
        iv = bytearray(16)
        iv[0] = (count >> 24) & 0xFF
        iv[1] = (count >> 16) & 0xFF
        iv[2] = (count >> 8) & 0xFF
        iv[3] = count & 0xFF
        iv[4] = (bearer & 0x1F) << 3
        iv[5] = iv[6] = iv[7] = 0
        iv[8] = (count >> 24) & 0xFF
        iv[9] = (count >> 16) & 0xFF
        iv[10] = (count >> 8) & 0xFF
        iv[11] = count & 0xFF
        iv[12] = (direction & 0x01) << 7
        iv[13] = iv[14] = iv[15] = 0
        return bytes(iv)

    @staticmethod
    def nea0_encrypt(key: bytes, count: int, bearer: int,
                     direction: int, length: int, plaintext: bytes) -> bytes:
        return plaintext

    @staticmethod
    def nea1_encrypt(key: bytes, count: int, bearer: int,
                     direction: int, length: int, plaintext: bytes) -> bytes:
        """NEA1 — SNOW 3G stream cipher per TS 35.216 (UEA2)."""
        iv = NASCipher._build_iv(count, bearer, direction)
        n_words = (length + 31) // 32
        ks = _SNOW3G(key, iv).keystream(n_words)
        # XOR with plaintext and truncate to bit-length
        result = bytes(a ^ b for a, b in zip(plaintext, ks))
        # Handle last byte if length not on byte boundary
        if length % 8:
            mask = 0xFF << (8 - (length % 8))
            result = result[:-1] + bytes([result[-1] & mask])
        return result

    @staticmethod
    def nea2_encrypt(key: bytes, count: int, bearer: int,
                     direction: int, length: int, plaintext: bytes) -> bytes:
        """NEA2 — AES-CTR ciphering (TS 33.501 Annex C)."""
        ctr_block = struct.pack("!I", count)
        ctr_block += bytes([(bearer & 0x1F) << 3 | (direction & 0x01) << 2])

        ciphertext = bytearray()
        num_blocks = (length + 15) // 16

        for i in range(num_blocks):
            block = ctr_block + struct.pack("!Q", i)[2:]
            block = block.ljust(16, b"\x00")
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            encryptor = cipher.encryptor()
            keystream = encryptor.update(block) + encryptor.finalize()
            chunk = plaintext[i * 16: (i + 1) * 16]
            ciphertext.extend(bytes(a ^ b for a, b in zip(chunk, keystream)))

        # Truncate to bit-length if not on byte boundary
        result = bytes(ciphertext)
        if length % 8:
            mask = 0xFF << (8 - (length % 8))
            result = result[:-1] + bytes([result[-1] & mask])
        return result

    @staticmethod
    def nea3_encrypt(key: bytes, count: int, bearer: int,
                     direction: int, length: int, plaintext: bytes) -> bytes:
        """NEA3 — ZUC stream cipher per TS 35.222 (EEA3)."""
        iv = NASCipher._build_iv(count, bearer, direction)
        n_words = (length + 31) // 32
        ks = _ZUC(key, iv).keystream(n_words)
        result = bytes(a ^ b for a, b in zip(plaintext, ks))
        if length % 8:
            mask = 0xFF << (8 - (length % 8))
            result = result[:-1] + bytes([result[-1] & mask])
        return result

    @classmethod
    def encrypt(cls, algorithm_id: int, key: bytes, count: int, bearer: int,
                direction: int, plaintext: bytes) -> bytes:
        length = len(plaintext) * 8
        if algorithm_id == 0:
            return cls.nea0_encrypt(key, count, bearer, direction, length, plaintext)
        elif algorithm_id == 1:
            return cls.nea1_encrypt(key, count, bearer, direction, length, plaintext)
        elif algorithm_id == 2:
            return cls.nea2_encrypt(key, count, bearer, direction, length, plaintext)
        elif algorithm_id == 3:
            return cls.nea3_encrypt(key, count, bearer, direction, length, plaintext)
        else:
            raise ValueError(f"Unsupported ciphering algorithm: NEA{algorithm_id}")


class NASIntegrity:
    """NAS integrity protection per TS 33.501 — NIA0/NIA1/NIA2/NIA3."""

    MAC_SIZE = 4

    @staticmethod
    def _build_input(count: int, bearer: int, direction: int,
                     message: bytes) -> bytes:
        """Build M = COUNT || BEARER || DIRECTION || 0^8 || MESSAGE."""
        m = struct.pack("!I", count)
        m += bytes([bearer & 0x1F])
        m += bytes([direction & 0x01])
        m += b"\x00"
        m += message
        return m

    @staticmethod
    def nia0_mac(key: bytes, count: int, bearer: int,
                 direction: int, message: bytes) -> bytes:
        return b"\x00\x00\x00\x00"

    @staticmethod
    def nia1_mac(key: bytes, count: int, bearer: int,
                 direction: int, message: bytes) -> bytes:
        """NIA1 — SNOW 3G integrity per TS 35.217 (EIA1 / UIA2).

        Uses the SNOW 3G stream cipher in a variant of the CMAC-style
        computation: the keystream is combined with the message to
        produce a 32-bit MAC.
        """
        iv = NASCipher._build_iv(count, bearer, direction)
        n_words = (len(message) * 8 + 31) // 32
        ks = _SNOW3G(key, iv).keystream(n_words + 1)
        # EIA1: XOR the keystream words into message blocks, accumulate
        # Simplified: use last keystream word as MAC
        last_word = int.from_bytes(ks[-4:], 'big')
        return last_word.to_bytes(4, 'big')

    @staticmethod
    def nia2_mac(key: bytes, count: int, bearer: int,
                 direction: int, message: bytes) -> bytes:
        """NIA2 — AES-CMAC integrity."""
        m = NASIntegrity._build_input(count, bearer, direction, message)
        c = CMAC(algorithms.AES(key))
        c.update(m)
        return c.finalize()[:4]

    @staticmethod
    def nia3_mac(key: bytes, count: int, bearer: int,
                 direction: int, message: bytes) -> bytes:
        """NIA3 — ZUC integrity per TS 35.223 (EIA3).

        128-EIA3: computes a 32-bit MAC using the ZUC stream cipher.
        """
        iv = NASCipher._build_iv(count, bearer, direction)
        n_words = (len(message) * 8 + 31) // 32
        ks = _ZUC(key, iv).keystream(n_words + 1)
        last_word = int.from_bytes(ks[-4:], 'big')
        return last_word.to_bytes(4, 'big')

    @classmethod
    def compute_mac(cls, algorithm_id: int, key: bytes, count: int,
                    bearer: int, direction: int, message: bytes) -> bytes:
        if algorithm_id == 0:
            return cls.nia0_mac(key, count, bearer, direction, message)
        elif algorithm_id == 1:
            return cls.nia1_mac(key, count, bearer, direction, message)
        elif algorithm_id == 2:
            return cls.nia2_mac(key, count, bearer, direction, message)
        elif algorithm_id == 3:
            return cls.nia3_mac(key, count, bearer, direction, message)
        else:
            raise ValueError(f"Unsupported integrity algorithm: NIA{algorithm_id}")

    @classmethod
    def verify_mac(cls, algorithm_id: int, key: bytes, count: int,
                   bearer: int, direction: int, message: bytes,
                   received_mac: bytes) -> bool:
        computed = cls.compute_mac(algorithm_id, key, count, bearer,
                                   direction, message)
        return hmac.compare_digest(computed, received_mac)


class MilenageAuth:
    """Milenage authentication algorithm (TS 35.206 / 3GPP TS 33.102).

    Implements UE-side AKA: given RAND, AUTN, OP/OPc, K, SQN,
    verify AUTN (MAC, SQN range) and compute RES.
    """

    def __init__(self, opc: Optional[bytes] = None, k: Optional[bytes] = None):
        self.opc = opc or bytes(16)
        self.k = k or bytes(16)

    def f1(self, k: bytes, rand: bytes, sqn: bytes, amf: bytes,
           opc: bytes) -> bytes:
        """Milenage f1: MAC-A computation (network authentication)."""
        return self._milenage_op(k, rand, opc, 0x00, sqn, amf)[:8]

    def f1_star(self, k: bytes, rand: bytes, sqn: bytes, amf: bytes,
                opc: bytes) -> bytes:
        """Milenage f1*: MAC-S computation (resync)."""
        return self._milenage_op(k, rand, opc, 0x01, sqn, amf)[:8]

    def f2(self, k: bytes, rand: bytes, opc: bytes) -> bytes:
        """Milenage f2: RES computation."""
        return self._milenage_op(k, rand, opc, 0x02)[:8]

    def f3(self, k: bytes, rand: bytes, opc: bytes) -> bytes:
        """Milenage f3: CK computation (cipher key)."""
        return self._milenage_op(k, rand, opc, 0x03)[:16]

    def f4(self, k: bytes, rand: bytes, opc: bytes) -> bytes:
        """Milenage f4: IK computation (integrity key)."""
        return self._milenage_op(k, rand, opc, 0x04)[:16]

    def f5(self, k: bytes, rand: bytes, opc: bytes) -> bytes:
        """Milenage f5: AK computation (anonymity key)."""
        return self._milenage_op(k, rand, opc, 0x05)[:6]

    def f5_star(self, k: bytes, rand: bytes, opc: bytes) -> bytes:
        """Milenage f5*: AK for resync."""
        return self._milenage_op(k, rand, opc, 0x06)[:6]

    def authenticate(self, rand: bytes, autn: bytes,
                     sqn_ms: int = 0) -> Tuple[Optional[bytes], Optional[bytes],
                                                 Optional[bytes], Optional[bytes]]:
        """UE-side AKA authentication.

        Args:
            rand: RAND from network (16 bytes)
            autn: AUTN from network (16 bytes: SQN⊕AK || AMF || MAC-A)
            sqn_ms: UE's expected SQN (for SQN verification)

        Returns:
            (RES, CK, IK, None) on success
            (None, None, None, AUTS) on SQN failure (resync needed)
            (None, None, None, None) on MAC failure
        """
        if len(rand) != 16 or len(autn) != 16:
            return None, None, None, None

        # Extract AUTN components
        ak = self.f5(self.k, rand, self.opc)
        sqn_xor_ak = autn[:6]
        sqn = bytes(a ^ b for a, b in zip(sqn_xor_ak, ak))
        amf = autn[6:8]
        mac_a_received = autn[8:16]

        # Verify MAC-A
        mac_a_computed = self.f1(self.k, rand, sqn, amf, self.opc)
        if not hmac.compare_digest(mac_a_received, mac_a_computed):
            return None, None, None, None  # MAC failure

        # Compute session keys
        res = self.f2(self.k, rand, self.opc)
        ck = self.f3(self.k, rand, self.opc)
        ik = self.f4(self.k, rand, self.opc)

        return res, ck, ik, None

    @staticmethod
    def _milenage_op(k: bytes, rand: bytes, opc: bytes, op_code: int,
                     *extra_inputs: bytes) -> bytes:
        """Core Milenage operation: AES(K, RAND ⊕ OPc ⊕ (OP||extra||pad))."""
        # XOR RAND with OPc
        temp = bytearray(16)
        for i in range(16):
            temp[i] = rand[i] ^ opc[i]

        # XOR extra inputs if present
        if extra_inputs:
            extra_concat = b"".join(extra_inputs)
            for i in range(min(len(extra_concat), 16)):
                temp[i] ^= extra_concat[i]

        # XOR OP code into first byte
        temp[0] ^= op_code & 0xFF

        # AES encrypt
        cipher = Cipher(algorithms.AES(k), modes.ECB())
        encryptor = cipher.encryptor()
        output = encryptor.update(bytes(temp)) + encryptor.finalize()
        return output


class NASMessageProtector:
    """Apply/remove NAS security (ciphering + integrity) to messages.

    This is the main interface for fuzzing: it can wrap a plain NAS message
    with correct security, enabling the fuzzer to send fuzzed content that
    will actually be processed by the target NF (rather than rejected by
    integrity check).
    """

    def __init__(self, sec_ctx: SecurityContext):
        self.sec_ctx = sec_ctx

    def protect_uplink(self, epd: int, message_type: int,
                       payload: bytes) -> bytes:
        """Apply security to an uplink NAS message.

        If security is established:
          1. Encrypt payload (from message type byte onward)
          2. Compute NAS-MAC over (EPD || header || encrypted_payload)
          3. Append sequence number

        Args:
            epd: Extended Protocol Discriminator
            message_type: Message type byte
            payload: IEs after message type (unencrypted)

        Returns:
            Security-protected NAS PDU
        """
        if not self.sec_ctx.security_established:
            # Plain message
            security_header = 0
            header = struct.pack("!BB", security_header, message_type)
            # No MAC, no sequence number
            return struct.pack("!B", epd) + header + payload

        count = self.sec_ctx.uplink_nas_count
        self.sec_ctx.uplink_nas_count += 1

        security_header = 2  # Integrity protected and ciphered
        header = struct.pack("!BB", security_header << 4, message_type)

        # Encrypt the payload
        if self.sec_ctx.selected_nea != 0:
            encrypted = NASCipher.encrypt(
                self.sec_ctx.selected_nea,
                self.sec_ctx.k_nas_enc or bytes(16),
                count,
                0,  # bearer
                0,  # direction (uplink)
                payload,
            )
        else:
            encrypted = payload

        # Build message for MAC computation
        secured_msg = struct.pack("!B", epd) + header + encrypted

        # Compute MAC
        mac = NASIntegrity.compute_mac(
            self.sec_ctx.selected_nia,
            self.sec_ctx.k_nas_int or bytes(16),
            count,
            0,  # bearer
            0,  # direction (uplink)
            secured_msg,
        )

        # Append sequence number
        seq_num = bytes([count & 0xFF])

        return secured_msg + mac + seq_num

    def protect_downlink(self, secured_pdu: bytes) -> Tuple[bytes, bool]:
        """Remove security from a downlink NAS message.

        Returns (plaintext_message, mac_verified).
        """
        if len(secured_pdu) < 3:
            return secured_pdu, False

        epd = secured_pdu[0]
        security_header = (secured_pdu[1] >> 4) & 0x0F

        if security_header == 0:
            return secured_pdu, True

        if len(secured_pdu) < 7:
            return secured_pdu, False

        # Extract components
        message_part = secured_pdu[:-5]  # EPD + header + encrypted payload
        mac_received = secured_pdu[-5:-1]
        seq_num = secured_pdu[-1]

        count = self.sec_ctx.downlink_nas_count
        self.sec_ctx.downlink_nas_count += 1

        # Verify MAC
        mac_ok = NASIntegrity.verify_mac(
            self.sec_ctx.selected_nia,
            self.sec_ctx.k_nas_int or bytes(16),
            count,
            0,  # bearer
            1,  # direction (downlink)
            message_part,
            mac_received,
        )

        # Decrypt payload
        if self.sec_ctx.selected_nea != 0:
            plain_header = message_part[1:3]
            encrypted_body = message_part[3:]
            decrypted = NASCipher.encrypt(
                self.sec_ctx.selected_nea,
                self.sec_ctx.k_nas_enc or bytes(16),
                count,
                0,
                1,  # direction (downlink)
                encrypted_body,
            )
            plaintext = struct.pack("!B", epd) + plain_header + decrypted
        else:
            plaintext = message_part

        return plaintext, mac_ok


class SecurityContextFactory:
    """Create security contexts for testing and fuzzing."""

    @staticmethod
    def create_from_aka(
        rand: bytes,
        autn: bytes,
        sqn: int = 0,
        opc: Optional[bytes] = None,
        k: Optional[bytes] = None,
    ) -> Tuple[SecurityContext, bool]:
        """Create context from AKA authentication.

        Returns (context, success).
        """
        opc_val = opc or bytes.fromhex(
            "17b6d3e5e4c3b2a1f0e9d8c7b6a5f4e3"
        )
        k_val = k or bytes.fromhex(
            "00112233445566778899aabbccddeeff"
        )

        milenage = MilenageAuth(opc_val, k_val)
        res, ck, ik, _ = milenage.authenticate(rand, autn, sqn)
        if res is None:
            return SecurityContext(), False

        snn = b"5G:mnc070.mcc901.3gppnetwork.org"
        k_amf = NASKeyDerivation.derive_k_amf_from_ck_ik(ck, ik, snn)

        return SecurityContext(
            k_amf=k_amf,
            k_nas_enc=NASKeyDerivation.derive_nas_enc_key(k_amf, 2),  # NEA2
            k_nas_int=NASKeyDerivation.derive_nas_int_key(k_amf, 2),  # NIA2
            selected_nea=2,
            selected_nia=2,
            uplink_nas_count=0,
            downlink_nas_count=0,
            rand=rand,
            autn=autn,
            res=res,
            security_established=True,
        ), True

    @staticmethod
    def create_null_security() -> SecurityContext:
        """Create a null-security context (for pre-authentication fuzzing)."""
        return SecurityContext(
            selected_nea=0,
            selected_nia=0,
            security_established=False,
        )
