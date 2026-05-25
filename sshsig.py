"""
SSH signature (SSHSIG) implementation in pure Python.

Implements the format from OpenSSH PROTOCOL.sshsig so that signatures
produced here verify with `ssh-keygen -Y verify` and vice versa.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    padding,
    rsa,
)
from cryptography.exceptions import InvalidSignature


MAGIC_PREAMBLE = b"SSHSIG"
SIG_VERSION = 0x01
DEFAULT_NAMESPACE = "file"
DEFAULT_HASH = "sha512"
SUPPORTED_HASHES = {"sha256", "sha512"}

ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----"
ARMOR_END = "-----END SSH SIGNATURE-----"


# ---------------------------------------------------------------------------
# SSH wire format helpers
# ---------------------------------------------------------------------------

def _enc_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _enc_uint32(value: int) -> bytes:
    return struct.pack(">I", value)


def _enc_mpint(value: int) -> bytes:
    if value == 0:
        return _enc_string(b"")
    blen = (value.bit_length() + 7) // 8
    raw = value.to_bytes(blen, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _enc_string(raw)


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_string(self) -> bytes:
        if self.pos + 4 > len(self.data):
            raise ValueError("Truncated SSH string length")
        (length,) = struct.unpack(">I", self.data[self.pos : self.pos + 4])
        self.pos += 4
        if self.pos + length > len(self.data):
            raise ValueError("Truncated SSH string body")
        out = self.data[self.pos : self.pos + length]
        self.pos += length
        return out

    def read_uint32(self) -> int:
        if self.pos + 4 > len(self.data):
            raise ValueError("Truncated uint32")
        (value,) = struct.unpack(">I", self.data[self.pos : self.pos + 4])
        self.pos += 4
        return value

    def read_fixed(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("Truncated fixed bytes")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def remaining(self) -> int:
        return len(self.data) - self.pos


# ---------------------------------------------------------------------------
# Public-key wire encoding / decoding
# ---------------------------------------------------------------------------

PublicKey = Union[
    ed25519.Ed25519PublicKey,
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
]
PrivateKey = Union[
    ed25519.Ed25519PrivateKey,
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
]


_EC_CURVE_NAMES = {
    "nistp256": ec.SECP256R1,
    "nistp384": ec.SECP384R1,
    "nistp521": ec.SECP521R1,
}
_EC_KEY_TYPES = {
    "secp256r1": ("ecdsa-sha2-nistp256", "nistp256", hashes.SHA256()),
    "secp384r1": ("ecdsa-sha2-nistp384", "nistp384", hashes.SHA384()),
    "secp521r1": ("ecdsa-sha2-nistp521", "nistp521", hashes.SHA512()),
}


def serialize_public_key(pub: PublicKey) -> bytes:
    """Encode a public key in SSH wire format (the contents of the
    'publickey' string in SSHSIG)."""
    if isinstance(pub, ed25519.Ed25519PublicKey):
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _enc_string(b"ssh-ed25519") + _enc_string(raw)

    if isinstance(pub, rsa.RSAPublicKey):
        numbers = pub.public_numbers()
        return _enc_string(b"ssh-rsa") + _enc_mpint(numbers.e) + _enc_mpint(numbers.n)

    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve_name = pub.curve.name
        if curve_name not in _EC_KEY_TYPES:
            raise ValueError(f"Unsupported EC curve: {curve_name}")
        keytype, ssh_curve, _hash = _EC_KEY_TYPES[curve_name]
        point = pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return (
            _enc_string(keytype.encode())
            + _enc_string(ssh_curve.encode())
            + _enc_string(point)
        )

    raise ValueError(f"Unsupported public key type: {type(pub).__name__}")


def parse_public_key(blob: bytes) -> Tuple[str, PublicKey]:
    """Parse an SSH wire-format public key. Returns (keytype, public_key)."""
    r = _Reader(blob)
    keytype = r.read_string().decode()

    if keytype == "ssh-ed25519":
        raw = r.read_string()
        return keytype, ed25519.Ed25519PublicKey.from_public_bytes(raw)

    if keytype == "ssh-rsa":
        e = int.from_bytes(r.read_string(), "big")
        n = int.from_bytes(r.read_string(), "big")
        return keytype, rsa.RSAPublicNumbers(e, n).public_key()

    if keytype.startswith("ecdsa-sha2-"):
        ssh_curve = r.read_string().decode()
        if ssh_curve not in _EC_CURVE_NAMES:
            raise ValueError(f"Unsupported EC curve: {ssh_curve}")
        curve = _EC_CURVE_NAMES[ssh_curve]()
        point = r.read_string()
        pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, point)
        return keytype, pub

    raise ValueError(f"Unsupported key type: {keytype}")


# ---------------------------------------------------------------------------
# Loading keys from files
# ---------------------------------------------------------------------------

@dataclass
class LoadedKey:
    keytype: str
    private_key: Optional[PrivateKey]
    public_key: PublicKey
    comment: str = ""


def load_private_key(path: Union[str, Path], password: Optional[bytes] = None) -> LoadedKey:
    data = Path(path).read_bytes()
    priv = serialization.load_ssh_private_key(data, password=password)
    pub = priv.public_key()
    keytype = _public_key_type_name(pub)
    return LoadedKey(keytype=keytype, private_key=priv, public_key=pub)


def load_public_key(path: Union[str, Path]) -> LoadedKey:
    """Load an SSH public key file (`id_xxx.pub` style: `ssh-ed25519 AAAA... comment`)."""
    text = Path(path).read_text().strip()
    parts = text.split(None, 2)
    if len(parts) < 2:
        raise ValueError("Public key file does not look like an OpenSSH .pub file")
    keytype, b64, *rest = parts
    blob = base64.b64decode(b64)
    parsed_type, pub = parse_public_key(blob)
    if parsed_type != keytype:
        raise ValueError(
            f"Public key type mismatch: header says {keytype} but body says {parsed_type}"
        )
    comment = rest[0] if rest else ""
    return LoadedKey(keytype=keytype, private_key=None, public_key=pub, comment=comment)


def _public_key_type_name(pub: PublicKey) -> str:
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "ssh-ed25519"
    if isinstance(pub, rsa.RSAPublicKey):
        return "ssh-rsa"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return _EC_KEY_TYPES[pub.curve.name][0]
    raise ValueError(f"Unsupported key type: {type(pub).__name__}")


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair(
    key_type: str,
    private_path: Union[str, Path],
    *,
    password: Optional[bytes] = None,
    comment: str = "",
    rsa_bits: int = 3072,
) -> LoadedKey:
    """Generate a key pair and write `<private_path>` and `<private_path>.pub`."""
    private_path = Path(private_path)

    if key_type == "ed25519":
        priv = ed25519.Ed25519PrivateKey.generate()
    elif key_type == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    elif key_type == "ecdsa-p256":
        priv = ec.generate_private_key(ec.SECP256R1())
    elif key_type == "ecdsa-p384":
        priv = ec.generate_private_key(ec.SECP384R1())
    elif key_type == "ecdsa-p521":
        priv = ec.generate_private_key(ec.SECP521R1())
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    if password:
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=enc,
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    if comment:
        pub_bytes = pub_bytes + b" " + comment.encode()

    private_path.write_bytes(priv_bytes)
    try:
        private_path.chmod(0o600)
    except OSError:
        pass  # e.g. on Windows
    public_path = private_path.with_name(private_path.name + ".pub")
    public_path.write_bytes(pub_bytes + b"\n")

    return LoadedKey(
        keytype=_public_key_type_name(priv.public_key()),
        private_key=priv,
        public_key=priv.public_key(),
        comment=comment,
    )


# ---------------------------------------------------------------------------
# Hashing the message
# ---------------------------------------------------------------------------

def _hash_factory(name: str):
    name = name.lower()
    if name == "sha256":
        return hashlib.sha256
    if name == "sha512":
        return hashlib.sha512
    raise ValueError(f"Unsupported hash algorithm: {name}")


def hash_file(path: Union[str, Path], hash_algo: str = DEFAULT_HASH) -> bytes:
    h = _hash_factory(hash_algo)()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.digest()


def hash_bytes(data: bytes, hash_algo: str = DEFAULT_HASH) -> bytes:
    return _hash_factory(hash_algo)(data).digest()


# ---------------------------------------------------------------------------
# Signing / verifying
# ---------------------------------------------------------------------------

def _build_signed_data(namespace: str, hash_algo: str, message_hash: bytes) -> bytes:
    return (
        MAGIC_PREAMBLE
        + _enc_string(namespace.encode())
        + _enc_string(b"")
        + _enc_string(hash_algo.encode())
        + _enc_string(message_hash)
    )


def _sign_blob(private_key: PrivateKey, blob: bytes) -> Tuple[str, bytes]:
    """Sign `blob` with the private key. Returns (ssh-signature-algo-name, signature-bytes)."""
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        sig = private_key.sign(blob)
        return "ssh-ed25519", sig

    if isinstance(private_key, rsa.RSAPrivateKey):
        # SSHSIG uses rsa-sha2-512 for ssh-rsa keys (modern OpenSSH default).
        sig = private_key.sign(blob, padding.PKCS1v15(), hashes.SHA512())
        return "rsa-sha2-512", sig

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        _kt, _curve, hash_alg = _EC_KEY_TYPES[private_key.curve.name]
        keytype = _EC_KEY_TYPES[private_key.curve.name][0]
        der_sig = private_key.sign(blob, ec.ECDSA(hash_alg))
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(der_sig)
        ssh_sig = _enc_mpint(r) + _enc_mpint(s)
        return keytype, ssh_sig

    raise ValueError(f"Unsupported private key type: {type(private_key).__name__}")


def _verify_blob(public_key: PublicKey, sig_keytype: str, sig_bytes: bytes, blob: bytes) -> None:
    """Raises InvalidSignature on failure."""
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        if sig_keytype != "ssh-ed25519":
            raise InvalidSignature(f"Signature algo {sig_keytype} does not match ed25519 key")
        public_key.verify(sig_bytes, blob)
        return

    if isinstance(public_key, rsa.RSAPublicKey):
        if sig_keytype == "rsa-sha2-512":
            public_key.verify(sig_bytes, blob, padding.PKCS1v15(), hashes.SHA512())
        elif sig_keytype == "rsa-sha2-256":
            public_key.verify(sig_bytes, blob, padding.PKCS1v15(), hashes.SHA256())
        elif sig_keytype == "ssh-rsa":
            public_key.verify(sig_bytes, blob, padding.PKCS1v15(), hashes.SHA1())
        else:
            raise InvalidSignature(f"Signature algo {sig_keytype} does not match RSA key")
        return

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        _kt, _curve, hash_alg = _EC_KEY_TYPES[public_key.curve.name]
        expected_keytype = _EC_KEY_TYPES[public_key.curve.name][0]
        if sig_keytype != expected_keytype:
            raise InvalidSignature(
                f"Signature algo {sig_keytype} does not match curve {public_key.curve.name}"
            )
        r = _Reader(sig_bytes)
        r_val = int.from_bytes(r.read_string(), "big")
        s_val = int.from_bytes(r.read_string(), "big")
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        der_sig = encode_dss_signature(r_val, s_val)
        public_key.verify(der_sig, blob, ec.ECDSA(hash_alg))
        return

    raise InvalidSignature(f"Unsupported public key type: {type(public_key).__name__}")


def _build_signature_blob(
    public_key: PublicKey,
    namespace: str,
    hash_algo: str,
    sig_keytype: str,
    sig_bytes: bytes,
) -> bytes:
    pub_wire = serialize_public_key(public_key)
    sig_wire = _enc_string(sig_keytype.encode()) + _enc_string(sig_bytes)
    return (
        MAGIC_PREAMBLE
        + _enc_uint32(SIG_VERSION)
        + _enc_string(pub_wire)
        + _enc_string(namespace.encode())
        + _enc_string(b"")
        + _enc_string(hash_algo.encode())
        + _enc_string(sig_wire)
    )


def _armor(blob: bytes) -> str:
    b64 = base64.b64encode(blob).decode()
    lines = [b64[i : i + 76] for i in range(0, len(b64), 76)]
    return ARMOR_BEGIN + "\n" + "\n".join(lines) + "\n" + ARMOR_END + "\n"


def _dearmor(text: str) -> bytes:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if ARMOR_BEGIN not in lines or ARMOR_END not in lines:
        raise ValueError("Missing SSH SIGNATURE armor headers")
    begin = lines.index(ARMOR_BEGIN)
    end = lines.index(ARMOR_END)
    if end <= begin:
        raise ValueError("Bad armor ordering")
    body = "".join(lines[begin + 1 : end])
    return base64.b64decode(body)


@dataclass
class ParsedSignature:
    version: int
    public_key: PublicKey
    keytype: str
    namespace: str
    hash_algo: str
    sig_keytype: str
    sig_bytes: bytes
    raw_blob: bytes


def parse_signature(armored: str) -> ParsedSignature:
    blob = _dearmor(armored)
    r = _Reader(blob)
    magic = r.read_fixed(len(MAGIC_PREAMBLE))
    if magic != MAGIC_PREAMBLE:
        raise ValueError("Bad SSHSIG magic preamble")
    version = r.read_uint32()
    if version != SIG_VERSION:
        raise ValueError(f"Unsupported SSHSIG version: {version}")
    pub_wire = r.read_string()
    namespace = r.read_string().decode()
    _reserved = r.read_string()
    hash_algo = r.read_string().decode()
    sig_wire = r.read_string()

    keytype, public_key = parse_public_key(pub_wire)
    sig_r = _Reader(sig_wire)
    sig_keytype = sig_r.read_string().decode()
    sig_bytes = sig_r.read_string()

    return ParsedSignature(
        version=version,
        public_key=public_key,
        keytype=keytype,
        namespace=namespace,
        hash_algo=hash_algo,
        sig_keytype=sig_keytype,
        sig_bytes=sig_bytes,
        raw_blob=blob,
    )


def sign_file(
    file_path: Union[str, Path],
    private_key: PrivateKey,
    *,
    namespace: str = DEFAULT_NAMESPACE,
    hash_algo: str = DEFAULT_HASH,
) -> str:
    """Sign `file_path` and return an armored SSH SIGNATURE string."""
    if hash_algo not in SUPPORTED_HASHES:
        raise ValueError(f"hash_algo must be one of {SUPPORTED_HASHES}")
    message_hash = hash_file(file_path, hash_algo)
    signed_data = _build_signed_data(namespace, hash_algo, message_hash)
    sig_keytype, sig_bytes = _sign_blob(private_key, signed_data)
    sig_blob = _build_signature_blob(
        private_key.public_key(), namespace, hash_algo, sig_keytype, sig_bytes
    )
    return _armor(sig_blob)


def verify_file(
    file_path: Union[str, Path],
    armored_signature: str,
    *,
    expected_public_key: Optional[PublicKey] = None,
    expected_namespace: Optional[str] = None,
) -> ParsedSignature:
    """Verify a signature against `file_path`. Returns the parsed signature on success.

    If `expected_public_key` is provided, the signature's embedded public key
    must match it (otherwise the signature would only prove that *some* key
    signed the file, which is useless for trust).
    """
    parsed = parse_signature(armored_signature)

    if expected_namespace is not None and parsed.namespace != expected_namespace:
        raise InvalidSignature(
            f"Namespace mismatch: expected {expected_namespace!r}, got {parsed.namespace!r}"
        )

    if expected_public_key is not None:
        if serialize_public_key(expected_public_key) != serialize_public_key(parsed.public_key):
            raise InvalidSignature("Signature was made by a different public key")

    message_hash = hash_file(file_path, parsed.hash_algo)
    signed_data = _build_signed_data(parsed.namespace, parsed.hash_algo, message_hash)
    _verify_blob(parsed.public_key, parsed.sig_keytype, parsed.sig_bytes, signed_data)
    return parsed


def public_key_fingerprint(public_key: PublicKey) -> str:
    """SHA256 fingerprint, same format as `ssh-keygen -lf`."""
    blob = serialize_public_key(public_key)
    digest = hashlib.sha256(blob).digest()
    b64 = base64.b64encode(digest).rstrip(b"=").decode()
    return "SHA256:" + b64


def public_key_to_openssh(public_key: PublicKey, comment: str = "") -> str:
    blob = serialize_public_key(public_key)
    b64 = base64.b64encode(blob).decode()
    keytype = _public_key_type_name(public_key)
    line = f"{keytype} {b64}"
    if comment:
        line += " " + comment
    return line
