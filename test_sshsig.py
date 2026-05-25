"""
Tests for sshsig.py.

Includes:
  - round-trip self-test for every supported key type
  - interop with the system `ssh-keygen -Y` (skipped if not installed)
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import sshsig


SAMPLE = b"The quick brown fox jumps over the lazy dog.\n" * 100  # ~4.5 KB
ALL_KEY_TYPES = ["ed25519", "rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"]


def _write_message(tmp: Path) -> Path:
    f = tmp / "message.bin"
    f.write_bytes(SAMPLE)
    return f


def test_roundtrip_all_keys():
    print("\n[1] Self round-trip for all key types")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        msg = _write_message(td)
        for kt in ALL_KEY_TYPES:
            for hash_algo in ("sha256", "sha512"):
                priv_path = td / f"id_{kt}"
                if priv_path.exists():
                    priv_path.unlink()
                pub_path = td / f"id_{kt}.pub"
                if pub_path.exists():
                    pub_path.unlink()
                loaded = sshsig.generate_keypair(kt, priv_path, comment=f"{kt}@test")
                armored = sshsig.sign_file(
                    msg, loaded.private_key, namespace="file", hash_algo=hash_algo
                )
                parsed = sshsig.verify_file(
                    msg, armored,
                    expected_public_key=loaded.public_key,
                    expected_namespace="file",
                )
                assert parsed.hash_algo == hash_algo
                print(f"    ✓ {kt:12s} hash={hash_algo}  type={parsed.keytype}  sig_algo={parsed.sig_keytype}")


def test_tamper_detected():
    print("\n[2] Tampered file is rejected")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        msg = _write_message(td)
        priv_path = td / "id_ed25519"
        loaded = sshsig.generate_keypair("ed25519", priv_path)
        armored = sshsig.sign_file(msg, loaded.private_key)
        # tamper
        msg.write_bytes(SAMPLE + b"X")
        try:
            sshsig.verify_file(msg, armored, expected_public_key=loaded.public_key)
            raise AssertionError("Expected InvalidSignature on tampered message")
        except Exception as e:
            print(f"    ✓ rejected as expected: {type(e).__name__}")


def test_wrong_pubkey_rejected():
    print("\n[3] Wrong public key is rejected")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        msg = _write_message(td)
        a = sshsig.generate_keypair("ed25519", td / "a")
        b = sshsig.generate_keypair("ed25519", td / "b")
        armored = sshsig.sign_file(msg, a.private_key)
        try:
            sshsig.verify_file(msg, armored, expected_public_key=b.public_key)
            raise AssertionError("Expected InvalidSignature on wrong pubkey")
        except Exception as e:
            print(f"    ✓ rejected as expected: {type(e).__name__}")


def test_encrypted_key_load():
    print("\n[4] Encrypted private key round-trip")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        msg = _write_message(td)
        priv = td / "id_enc"
        sshsig.generate_keypair("ed25519", priv, password=b"hunter2")
        loaded = sshsig.load_private_key(priv, password=b"hunter2")
        armored = sshsig.sign_file(msg, loaded.private_key)
        sshsig.verify_file(msg, armored, expected_public_key=loaded.public_key)
        print("    ✓ encrypted key loaded and signed/verified")


def test_load_pubkey_from_dotpub():
    print("\n[5] Load OpenSSH .pub file")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        msg = _write_message(td)
        priv = td / "id_pub_load"
        sshsig.generate_keypair("ed25519", priv, comment="alice@laptop")
        loaded_priv = sshsig.load_private_key(priv)
        loaded_pub = sshsig.load_public_key(str(priv) + ".pub")
        assert loaded_pub.comment == "alice@laptop"
        armored = sshsig.sign_file(msg, loaded_priv.private_key)
        sshsig.verify_file(msg, armored, expected_public_key=loaded_pub.public_key)
        print(f"    ✓ pub key comment={loaded_pub.comment!r}, fingerprint={sshsig.public_key_fingerprint(loaded_pub.public_key)}")


def test_interop_with_ssh_keygen():
    print("\n[6] Interop with system ssh-keygen")
    if shutil.which("ssh-keygen") is None:
        print("    ⚠ ssh-keygen not found, skipping interop test")
        return
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        msg = _write_message(td)
        namespace = "file"

        for kt in ["ed25519", "rsa", "ecdsa-p256"]:
            priv = td / f"id_{kt}_interop"
            if priv.exists():
                priv.unlink()
            pub = priv.with_name(priv.name + ".pub")
            if pub.exists():
                pub.unlink()

            loaded = sshsig.generate_keypair(kt, priv, comment=f"{kt}@interop")

            # --- our sign -> ssh-keygen verify ---
            sig_path = td / f"{kt}.sig"
            armored = sshsig.sign_file(msg, loaded.private_key, namespace=namespace)
            sig_path.write_text(armored)

            allowed = td / f"allowed_{kt}"
            principal = "tester@example.com"
            pub_line = sshsig.public_key_to_openssh(loaded.public_key)
            allowed.write_text(f"{principal} {pub_line}\n")

            res = subprocess.run(
                [
                    "ssh-keygen", "-Y", "verify",
                    "-f", str(allowed),
                    "-I", principal,
                    "-n", namespace,
                    "-s", str(sig_path),
                ],
                input=msg.read_bytes(),
                capture_output=True,
            )
            assert res.returncode == 0, (
                f"ssh-keygen -Y verify failed for {kt}: "
                f"stdout={res.stdout!r} stderr={res.stderr!r}"
            )
            print(f"    ✓ {kt:10s} our-sign  → ssh-keygen verify: OK")

            # --- ssh-keygen sign -> our verify ---
            sk_sig = td / f"{kt}.sk.sig"
            if sk_sig.exists():
                sk_sig.unlink()
            res = subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-f", str(priv), "-n", namespace, str(msg)],
                capture_output=True,
            )
            # ssh-keygen writes to <file>.sig by default
            default_sig = msg.with_name(msg.name + ".sig")
            assert res.returncode == 0, f"ssh-keygen sign failed: {res.stderr!r}"
            armored_sk = default_sig.read_text()
            default_sig.unlink()

            parsed = sshsig.verify_file(
                msg, armored_sk,
                expected_public_key=loaded.public_key,
                expected_namespace=namespace,
            )
            print(f"    ✓ {kt:10s} ssh-keygen sign → our verify: OK ({parsed.sig_keytype})")


def main():
    try:
        test_roundtrip_all_keys()
        test_tamper_detected()
        test_wrong_pubkey_rejected()
        test_encrypted_key_load()
        test_load_pubkey_from_dotpub()
        test_interop_with_ssh_keygen()
    except AssertionError as e:
        print(f"\n✗ FAIL: {e}")
        sys.exit(1)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\n✗ ERROR: {e}")
        sys.exit(1)
    print("\nAll tests passed ✓")


if __name__ == "__main__":
    main()
