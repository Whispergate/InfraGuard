"""Terraform state encryption and decryption using age.

age is a modern encryption tool: https://github.com/FiloSottile/age

Invariants:
- After encrypt_state(): plaintext file is deleted, only .age file remains.
- decrypt_state() writes to a tempfile with 0o600 permissions.
- Both raise RuntimeError on age subprocess failure with the stderr message.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


def encrypt_state(state_path: Path, age_pubkey: str) -> Path:
    """Encrypt a Terraform state file with age and delete the plaintext.

    Runs: ``age -e -r <age_pubkey> <state_path>`` and writes the ciphertext
    to ``<state_path>.age``.  The plaintext is deleted after successful
    encryption.

    Args:
        state_path: Path to the plaintext ``.tfstate`` file.
        age_pubkey: age public key (``age1...`` format) for the recipient.

    Returns:
        Path to the encrypted ``.age`` file.

    Raises:
        RuntimeError: If the age subprocess exits with a non-zero code.
    """
    enc_path = state_path.with_suffix(state_path.suffix + ".age")

    result = subprocess.run(
        ["age", "-e", "-r", age_pubkey, "-o", str(enc_path), str(state_path)],
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"age encryption failed: {result.stderr.decode(errors='replace')}"
        )

    # Delete plaintext only after successful encryption
    state_path.unlink()
    return enc_path


def decrypt_state(enc_path: Path, age_identity: Path) -> Path:
    """Decrypt an age-encrypted Terraform state file to a secure tempfile.

    Runs: ``age -d -i <age_identity> <enc_path>`` and writes the plaintext to
    a temporary file with ``0o600`` permissions.

    Args:
        enc_path: Path to the encrypted ``.tfstate.age`` file.
        age_identity: Path to the age identity (secret key) file.

    Returns:
        Path to the temporary plaintext file (caller is responsible for
        deletion when done).

    Raises:
        RuntimeError: If the age subprocess exits with a non-zero code.
    """
    # Create a secure tempfile first so we can write with restricted perms
    fd, tmp_path_str = tempfile.mkstemp(suffix=".tfstate")
    os.close(fd)
    tmp_path = Path(tmp_path_str)
    tmp_path.chmod(0o600)

    result = subprocess.run(
        ["age", "-d", "-i", str(age_identity), "-o", str(tmp_path), str(enc_path)],
        capture_output=True,
    )
    if result.returncode != 0:
        # Clean up empty tempfile on failure
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"age decryption failed: {result.stderr.decode(errors='replace')}"
        )

    return tmp_path
