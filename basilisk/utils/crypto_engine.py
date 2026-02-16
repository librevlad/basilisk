"""Crypto engine — hash cracking, RSA attacks, AES attacks, classical ciphers."""

from __future__ import annotations

import hashlib
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hash identification patterns
# ---------------------------------------------------------------------------

HASH_PATTERNS: list[tuple[str, str, int]] = [
    # (regex, name, hashcat_mode)
    (r"^[a-f0-9]{32}$", "MD5", 0),
    (r"^[a-f0-9]{40}$", "SHA-1", 100),
    (r"^[a-f0-9]{64}$", "SHA-256", 1400),
    (r"^[a-f0-9]{128}$", "SHA-512", 1700),
    (r"^\$2[aby]\$\d{2}\$.{53}$", "bcrypt", 3200),
    (r"^\$6\$.+\$.{86}$", "SHA-512 crypt", 1800),
    (r"^\$5\$.+\$.{43}$", "SHA-256 crypt", 7400),
    (r"^\$1\$.+\$.{22}$", "MD5 crypt", 500),
    (r"^\$apr1\$.+\$.{22}$", "Apache MD5", 1600),
    (r"^[a-f0-9]{32}:[a-f0-9]{32}$", "NTLM", 1000),
    (r"^[a-fA-F0-9]{32}$", "NTLM (raw)", 1000),
    (r"^\w+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::", "NetNTLMv1", 5500),
    (r"^\w+::\w+:[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$", "NetNTLMv2", 5600),
    (r"^\$P\$[a-zA-Z0-9./]{31}$", "phpass (WordPress)", 400),
    (r"^\$H\$[a-zA-Z0-9./]{31}$", "phpass", 400),
    (r"^sha256\$[a-zA-Z0-9]+\$[a-f0-9]{64}$", "Django SHA-256", 10000),
    (r"^pbkdf2_sha256\$.+", "Django PBKDF2", 10000),
    (r"^sha1\$.+\$[a-f0-9]{40}$", "Django SHA-1", 124),
    (r"^\{SSHA\}.+", "SSHA (LDAP)", 111),
    (r"^[a-f0-9]{16}$", "MySQL 3.x", 200),
    (r"^\*[A-F0-9]{40}$", "MySQL 4.1+", 300),
]


# ---------------------------------------------------------------------------
# Common password list for quick hash cracking
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "michael", "shadow", "123123",
    "654321", "superman", "qazwsx", "admin", "root", "toor",
    "password1", "Password1", "password123", "admin123", "root123",
    "changeme", "Welcome1", "P@ssw0rd", "Summer2024", "Winter2024",
]


@dataclass
class HashResult:
    """Result of hash identification."""

    hash_value: str
    hash_type: str
    hashcat_mode: int
    cracked: str = ""


@dataclass
class RsaResult:
    """Result of an RSA attack."""

    attack: str
    success: bool
    p: int = 0
    q: int = 0
    d: int = 0
    plaintext: bytes = b""


class CryptoEngine:
    """Cryptographic analysis and attack engine for CTF/HTB challenges."""

    # ------------------------------------------------------------------
    # Hash operations
    # ------------------------------------------------------------------

    @staticmethod
    def identify_hash(hash_value: str) -> list[HashResult]:
        """Identify hash type(s) from a hash string."""
        results = []
        h = hash_value.strip()
        for pattern, name, mode in HASH_PATTERNS:
            if re.match(pattern, h, re.IGNORECASE):
                results.append(HashResult(
                    hash_value=h, hash_type=name, hashcat_mode=mode,
                ))
        return results

    @staticmethod
    def crack_hash(
        hash_value: str, hash_type: str = "md5",
        wordlist: list[str] | None = None,
    ) -> str:
        """Attempt to crack a hash using a wordlist."""
        words = wordlist or COMMON_PASSWORDS
        h = hash_value.strip().lower()

        hash_funcs: dict[str, str] = {
            "md5": "md5",
            "sha1": "sha1",
            "sha-1": "sha1",
            "sha256": "sha256",
            "sha-256": "sha256",
            "sha512": "sha512",
            "sha-512": "sha512",
            "ntlm": "md4",
        }

        func_name = hash_funcs.get(hash_type.lower().replace(" ", ""), "md5")

        for word in words:
            if func_name == "md4":
                # NTLM: MD4 of UTF-16LE encoded password
                computed = hashlib.new(
                    "md4", word.encode("utf-16-le"),
                ).hexdigest()
            else:
                computed = hashlib.new(func_name, word.encode()).hexdigest()

            if computed == h:
                return word
        return ""

    def crack_hashes_batch(
        self, hashes: list[str], hash_type: str = "md5",
        wordlist: list[str] | None = None,
    ) -> dict[str, str]:
        """Crack multiple hashes at once."""
        results = {}
        for h in hashes:
            cracked = self.crack_hash(h, hash_type, wordlist)
            if cracked:
                results[h] = cracked
        return results

    # ------------------------------------------------------------------
    # RSA attacks
    # ------------------------------------------------------------------

    @staticmethod
    def fermat_factor(n: int, max_iterations: int = 1_000_000) -> RsaResult:
        """Factor RSA modulus using Fermat's method (close primes)."""
        a = math.isqrt(n)
        if a * a == n:
            return RsaResult(attack="fermat", success=True, p=a, q=a)
        a += 1
        for _ in range(max_iterations):
            b2 = a * a - n
            b = math.isqrt(b2)
            if b * b == b2:
                p = a + b
                q = a - b
                if p * q == n:
                    return RsaResult(attack="fermat", success=True, p=p, q=q)
            a += 1
        return RsaResult(attack="fermat", success=False)

    @staticmethod
    def wiener_attack(e: int, n: int) -> RsaResult:
        """Wiener's attack on RSA with small private exponent."""
        def continued_fraction(num: int, den: int):
            cf = []
            while den:
                q = num // den
                cf.append(q)
                num, den = den, num - q * den
            return cf

        def convergents(cf):
            convs = []
            h0, h1 = 0, 1
            k0, k1 = 1, 0
            for a in cf:
                h = a * h1 + h0
                k = a * k1 + k0
                convs.append((h, k))
                h0, h1 = h1, h
                k0, k1 = k1, k
            return convs

        cf = continued_fraction(e, n)
        for k, d in convergents(cf):
            if k == 0:
                continue
            phi = (e * d - 1) // k
            # Check if phi is correct
            s = n - phi + 1
            discriminant = s * s - 4 * n
            if discriminant < 0:
                continue
            sqrt_d = math.isqrt(discriminant)
            if sqrt_d * sqrt_d == discriminant:
                p = (s + sqrt_d) // 2
                q = (s - sqrt_d) // 2
                if p * q == n:
                    return RsaResult(
                        attack="wiener", success=True, p=p, q=q, d=d,
                    )
        return RsaResult(attack="wiener", success=False)

    @staticmethod
    def common_factor_attack(n1: int, n2: int) -> RsaResult:
        """Find common factor between two RSA moduli."""
        g = math.gcd(n1, n2)
        if g > 1 and g != n1 and g != n2:
            return RsaResult(
                attack="common_factor", success=True,
                p=g, q=n1 // g,
            )
        return RsaResult(attack="common_factor", success=False)

    @staticmethod
    def small_e_attack(c: int, e: int = 3, n: int = 0) -> RsaResult:
        """Attack RSA with small public exponent (e=3, no padding)."""
        # If m^e < n, then c = m^e and we can just take the eth root
        low, high = 0, n if n else c + 1
        while low < high:
            mid = (low + high) // 2
            val = pow(mid, e)
            if val < c:
                low = mid + 1
            elif val > c:
                high = mid
            else:
                return RsaResult(
                    attack="small_e", success=True,
                    plaintext=mid.to_bytes((mid.bit_length() + 7) // 8, "big"),
                )
        return RsaResult(attack="small_e", success=False)

    @staticmethod
    def rsa_decrypt(c: int, d: int, n: int) -> bytes:
        """Decrypt RSA ciphertext given private key."""
        m = pow(c, d, n)
        return m.to_bytes((m.bit_length() + 7) // 8, "big")

    @staticmethod
    def rsa_private_key(p: int, q: int, e: int) -> int:
        """Compute RSA private exponent d from p, q, e."""
        phi = (p - 1) * (q - 1)
        return pow(e, -1, phi)

    # ------------------------------------------------------------------
    # AES attacks
    # ------------------------------------------------------------------

    @staticmethod
    def detect_ecb(ciphertext: bytes, block_size: int = 16) -> bool:
        """Detect AES-ECB by checking for duplicate blocks."""
        blocks = [
            ciphertext[i:i + block_size]
            for i in range(0, len(ciphertext), block_size)
        ]
        return len(blocks) != len(set(blocks))

    @staticmethod
    def padding_oracle_decrypt(
        ciphertext: bytes,
        oracle_fn,
        block_size: int = 16,
    ) -> bytes:
        """Padding oracle attack on AES-CBC.

        oracle_fn(modified_ciphertext) -> bool (True if padding valid).
        This is the core algorithm; callers provide the oracle function.
        """
        blocks = [
            ciphertext[i:i + block_size]
            for i in range(0, len(ciphertext), block_size)
        ]
        plaintext = b""

        for block_idx in range(1, len(blocks)):
            prev = bytearray(blocks[block_idx - 1])
            current = blocks[block_idx]
            intermediate = bytearray(block_size)

            for byte_pos in range(block_size - 1, -1, -1):
                pad_val = block_size - byte_pos
                # Set already-known bytes
                test_prev = bytearray(prev)
                for j in range(byte_pos + 1, block_size):
                    test_prev[j] = intermediate[j] ^ pad_val

                found = False
                for guess in range(256):
                    test_prev[byte_pos] = guess
                    test_ct = bytes(test_prev) + current
                    if oracle_fn(test_ct):
                        intermediate[byte_pos] = guess ^ pad_val
                        found = True
                        break

                if not found:
                    logger.warning("Padding oracle: byte %d not found", byte_pos)
                    intermediate[byte_pos] = 0

            block_plain = bytes(
                prev[i] ^ intermediate[i] for i in range(block_size)
            )
            plaintext += block_plain

        # Remove PKCS7 padding
        if plaintext:
            pad_len = plaintext[-1]
            if 0 < pad_len <= block_size:
                plaintext = plaintext[:-pad_len]

        return plaintext

    # ------------------------------------------------------------------
    # Classical ciphers
    # ------------------------------------------------------------------

    @staticmethod
    def xor_decrypt(data: bytes, key: bytes) -> bytes:
        """XOR decrypt with repeating key."""
        return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

    @staticmethod
    def xor_single_byte_crack(data: bytes) -> tuple[int, bytes]:
        """Crack single-byte XOR by frequency analysis."""
        best_key = 0
        best_score = -1.0
        english_freq = {
            "e": 12.7, "t": 9.1, "a": 8.2, "o": 7.5, "i": 7.0,
            "n": 6.7, "s": 6.3, "h": 6.1, "r": 6.0, " ": 13.0,
        }

        for key in range(256):
            decrypted = bytes(b ^ key for b in data)
            try:
                text = decrypted.decode("ascii")
            except (UnicodeDecodeError, ValueError):
                continue
            score = sum(
                english_freq.get(c.lower(), 0) for c in text
            )
            if score > best_score:
                best_score = score
                best_key = key

        return best_key, bytes(b ^ best_key for b in data)

    @staticmethod
    def caesar_brute(text: str) -> list[tuple[int, str]]:
        """Brute force all 26 Caesar cipher shifts."""
        results = []
        for shift in range(26):
            decrypted = ""
            for c in text:
                if c.isalpha():
                    base = ord("A") if c.isupper() else ord("a")
                    decrypted += chr((ord(c) - base - shift) % 26 + base)
                else:
                    decrypted += c
            results.append((shift, decrypted))
        return results

    @staticmethod
    def vigenere_crack(
        ciphertext: str, max_key_len: int = 20,
    ) -> tuple[str, str]:
        """Crack Vigenere cipher using Kasiski/frequency analysis."""
        # Filter to alpha only
        filtered = "".join(c.upper() for c in ciphertext if c.isalpha())
        if len(filtered) < 10:
            return "", ""

        # Estimate key length using Index of Coincidence
        best_key_len = 1
        best_ic = 0.0

        for kl in range(1, min(max_key_len + 1, len(filtered) // 2)):
            ic_sum = 0.0
            for offset in range(kl):
                group = filtered[offset::kl]
                if len(group) < 2:
                    continue
                freq = Counter(group)
                n = len(group)
                ic = sum(
                    f * (f - 1) for f in freq.values()
                ) / (n * (n - 1)) if n > 1 else 0
                ic_sum += ic
            avg_ic = ic_sum / kl
            if avg_ic > best_ic:
                best_ic = avg_ic
                best_key_len = kl

        # Recover key using frequency analysis per column
        key = ""
        for offset in range(best_key_len):
            group = filtered[offset::best_key_len]
            best_shift = 0
            best_corr = -1.0
            for shift in range(26):
                shifted = "".join(
                    chr((ord(c) - ord("A") - shift) % 26 + ord("A"))
                    for c in group
                )
                freq = Counter(shifted)
                n = len(shifted)
                corr = sum(
                    f * (f - 1) for f in freq.values()
                ) / (n * (n - 1)) if n > 1 else 0
                if corr > best_corr:
                    best_corr = corr
                    best_shift = shift
            key += chr(best_shift + ord("A"))

        # Decrypt
        decrypted = ""
        ki = 0
        for c in ciphertext:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                shift = ord(key[ki % len(key)]) - ord("A")
                decrypted += chr((ord(c) - base - shift) % 26 + base)
                ki += 1
            else:
                decrypted += c

        return key, decrypted

    @staticmethod
    def entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    @staticmethod
    def frequency_analysis(text: str) -> dict[str, float]:
        """Compute letter frequency distribution."""
        filtered = [c.lower() for c in text if c.isalpha()]
        if not filtered:
            return {}
        total = len(filtered)
        freq = Counter(filtered)
        return {c: (count / total) * 100 for c, count in freq.most_common()}
