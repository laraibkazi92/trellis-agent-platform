# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""The edge keypair: one RSA-3072 key whose private half never leaves the VM.

Central stores per-user credentials as ciphertext sealed to the edge's *public* key
(``core.edge_crypto``); this module owns the only copy of the private half. Three
properties are load-bearing and enforced here rather than documented:

* the key file is ``0400`` -- a loader that accepts a wider mode is a leak waiting
  for the next ``cp`` to widen it;
* the key never lives under the workspace root, so no container bind mount (and no
  tool) can reach it by path;
* nothing in this module prints or serialises the private key -- ``--show`` emits only
  the public SPKI, fingerprint and 16-char key id.

Rotation is an overlap, not a swap: the old key is moved aside as ``edge-key.old``
and kept readable so blobs sealed before the rotation still decrypt while central
catches up. ``--drop-old-key`` ends that window.

Terminology: ``spki_b64`` is base64 DER of the ``SubjectPublicKeyInfo`` -- the exact
bytes the browser feeds to ``crypto.subtle.importKey("spki", ...)``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

DEFAULT_KEY_PATH = "/etc/trellis/edge-key"
EDGE_KEY_ENV = "EDGE_PRIVATE_KEY_PATH"
WORKSPACE_ENV = "WORKSPACE_ROOT"
DEFAULT_WORKSPACE_ROOT = "/app/workspace"

DEFAULT_BITS = 3072
PRIVATE_MODE = 0o400
OLD_KEY_SUFFIX = ".old"
OLD_KEY_MODE = 0o600
DIR_MODE = 0o700


class EdgeKeyError(RuntimeError):
    """A key file that must not be used: wrong place, wrong mode, unparsable."""


@dataclass(frozen=True)
class EdgeKey:
    """A loaded edge key plus the public material central and the browser need."""

    # repr=False: a stray f-string or log call must not reach the private half.
    private_key: RSAPrivateKey = field(repr=False)
    spki_b64: str
    fingerprint: str
    key_id: str

    def public_json(self) -> dict:
        """The shareable view: ``{key_id, fingerprint, spki}``, never the key."""
        return {
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "spki": self.spki_b64,
        }


def fingerprint(spki_der: bytes) -> str:
    """``SHA256:`` + base64(sha256(SPKI DER)) -- the value central pins per edge."""
    digest = hashlib.sha256(spki_der).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii")


def key_id(fp: str) -> str:
    """The 16-char id embedded in the AAD (``fingerprint[7:23]``)."""
    return fp[7:23]


def resolve_path(path: Optional[Union[str, os.PathLike]] = None) -> Path:
    """``--path`` wins, then ``EDGE_PRIVATE_KEY_PATH``, then the packaged default."""
    raw = path if path is not None else (os.getenv(EDGE_KEY_ENV) or DEFAULT_KEY_PATH)
    return Path(raw).expanduser()


def workspace_root() -> Path:
    return Path(os.getenv(WORKSPACE_ENV) or DEFAULT_WORKSPACE_ROOT).expanduser()


def ensure_outside_workspace(path: Path) -> None:
    """The key must never be reachable through a container's workspace mount."""
    target = path.resolve()
    root = workspace_root().resolve()
    if target == root or root in target.parents:
        raise EdgeKeyError(
            f"refusing to use edge key {target}: it is inside the workspace root "
            f"{root}, which is mounted into containers. Move it by setting "
            f"{EDGE_KEY_ENV} to a path outside the workspace, then run "
            f"`trellis-proxy edge-keygen`."
        )


def _public_der(private_key: RSAPrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _from_private_key(private_key: RSAPrivateKey) -> EdgeKey:
    der = _public_der(private_key)
    fp = fingerprint(der)
    return EdgeKey(
        private_key=private_key,
        spki_b64=base64.b64encode(der).decode("ascii"),
        fingerprint=fp,
        key_id=key_id(fp),
    )


def _write_private(target: Path, private_key: RSAPrivateKey) -> None:
    """Write PKCS#8 PEM and pin the mode in the same syscall as the create."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_MODE)
    try:
        # The process umask can only narrow the create mode; chmod makes 0400 the
        # guarantee rather than an accident of the caller's environment.
        os.fchmod(fd, PRIVATE_MODE)
        view = memoryview(pem)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)


def generate(
    path: Optional[Union[str, os.PathLike]] = None, bits: int = DEFAULT_BITS
) -> EdgeKey:
    """Create a fresh keypair at ``path`` (mode 0400, parent 0700).

    Overwrites an existing file: callers that must keep the old key use
    :func:`rotate`.
    """
    target = resolve_path(path)
    ensure_outside_workspace(target)

    parent = target.parent
    if not parent.exists():
        parent.mkdir(parents=True, mode=DIR_MODE)
        # mkdir's mode is umask-masked; the directory holds the only key, so pin it.
        os.chmod(parent, DIR_MODE)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    _write_private(target, private_key)
    return _from_private_key(private_key)


def _load_file(target: Path, allowed_modes: frozenset) -> EdgeKey:
    ensure_outside_workspace(target)
    try:
        st = target.stat()
    except FileNotFoundError:
        raise EdgeKeyError(
            f"edge private key {target} does not exist. Generate one with "
            f"`trellis-proxy edge-keygen`, or point {EDGE_KEY_ENV} at an existing key."
        ) from None
    if not stat.S_ISREG(st.st_mode):
        raise EdgeKeyError(f"edge private key {target} is not a regular file")

    mode = stat.S_IMODE(st.st_mode)
    if mode not in allowed_modes:
        expected = "/".join(oct(m) for m in sorted(allowed_modes))
        raise EdgeKeyError(
            f"edge private key {target} has mode {oct(mode)}, expected {expected}: "
            f"a readable key is a leaked key. Fix it with `chmod 0400 {target}`, or "
            f"point {EDGE_KEY_ENV} at a 0400 file and generate one with "
            f"`trellis-proxy edge-keygen`."
        )

    try:
        private_key = serialization.load_pem_private_key(target.read_bytes(), password=None)
    except (ValueError, TypeError) as exc:
        raise EdgeKeyError(
            f"edge private key {target} is not an unencrypted PEM private key ({exc}). "
            f"Regenerate it with `trellis-proxy edge-keygen`."
        ) from None
    if not isinstance(private_key, RSAPrivateKey):
        raise EdgeKeyError(
            f"edge private key {target} is not an RSA key; the seal format is RSA-OAEP. "
            f"Regenerate it with `trellis-proxy edge-keygen`."
        )
    return _from_private_key(private_key)


def load(path: Optional[Union[str, os.PathLike]] = None) -> EdgeKey:
    """Load the current key; refuse wrong mode, wrong place, or a missing file."""
    return _load_file(resolve_path(path), frozenset({PRIVATE_MODE}))


def old_path(path: Optional[Union[str, os.PathLike]] = None) -> Path:
    target = resolve_path(path)
    return target.with_name(target.name + OLD_KEY_SUFFIX)


def rotate(path: Optional[Union[str, os.PathLike]] = None) -> EdgeKey:
    """Move the current key to ``<path>.old`` (0600) and generate a new one.

    The old key stays loadable via :func:`load_old` for the overlap window; blobs
    sealed to it keep decrypting as long as the caller passes that key object.
    """
    target = resolve_path(path)
    ensure_outside_workspace(target)
    if target.exists():
        kept = old_path(target)
        # os.replace: a crash between the two steps must not leave two "current" keys.
        os.replace(target, kept)
        os.chmod(kept, OLD_KEY_MODE)
    return generate(target)


def drop_old(path: Optional[Union[str, os.PathLike]] = None) -> bool:
    """Delete ``<path>.old``; returns whether a file was removed."""
    kept = old_path(path)
    ensure_outside_workspace(kept)
    try:
        kept.unlink()
    except FileNotFoundError:
        return False
    return True


def load_old(path: Optional[Union[str, os.PathLike]] = None) -> Optional[EdgeKey]:
    """Load the previous key if rotation left one behind, else ``None``."""
    kept = old_path(path)
    ensure_outside_workspace(kept)
    if not kept.exists():
        return None
    return _load_file(kept, frozenset({OLD_KEY_MODE, PRIVATE_MODE}))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trellis-proxy edge-keygen",
        description=(
            "Manage the edge RSA-3072 keypair used to open browser-sealed per-user "
            "credentials. The private key is never printed."
        ),
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--keygen", action="store_true", help="generate a keypair (overwrites)")
    action.add_argument(
        "--rotate", action="store_true", help="keep the current key as .old and generate a new one"
    )
    action.add_argument("--drop-old-key", action="store_true", help="delete the .old key")
    action.add_argument("--show", action="store_true", help="print public material as JSON")
    parser.add_argument(
        "--path",
        help=f"private key path (default: ${EDGE_KEY_ENV} or {DEFAULT_KEY_PATH})",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if args.keygen:
            key = generate(args.path)
            print(f"edge keypair written to {resolve_path(args.path)}")
            print(f"fingerprint: {key.fingerprint}")
            print(f"key id: {key.key_id}")
        elif args.rotate:
            key = rotate(args.path)
            print(f"rotated: {resolve_path(args.path)} (+ {old_path(args.path).name})")
            print(f"fingerprint: {key.fingerprint}")
            print(f"key id: {key.key_id}")
        elif args.drop_old_key:
            kept = old_path(args.path)
            removed = drop_old(args.path)
            print(f"removed {kept}" if removed else f"no old key at {kept}")
        else:
            print(json.dumps(load(args.path).public_json(), sort_keys=True))
    except EdgeKeyError as exc:
        print(f"edge-keygen: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
