"""Bounded terminal-metadata handoff before TCP close; no native credit."""
import errno
import json
import os
from pathlib import Path
import secrets
import stat
import time

SCOPE = "controller_write_window_handoff_only"
MAX_BYTES = 1024
MAX_READS = 128
POLL_NS = 10_000_000
UNVERIFIED = dict(native_os_write_verified=False, physical_send_verified=False,
                  canonical_current_owner_verified=False)


def validate_destination(path):
    path = Path(path)
    if not path.is_absolute() or len(os.fsencode(path)) > 4000 or not path.parent.is_dir():
        raise ValueError("handoff_path_invalid")
    if path.exists() or path.is_symlink():
        raise ValueError("handoff_path_occupied")
    return path


def document(run_nonce, round_nonce):
    return dict(schema_version=1, scope=SCOPE, run_nonce=run_nonce,
                round_nonce=round_nonce, delivered=True, **UNVERIFIED)


def publish(path, run_nonce, round_nonce):
    """One atomic, exclusive publication after both terminal-metadata receipts.

    It acknowledges delivery regardless of native outcomes; it never reads a
    native result or retries a refused owner transaction.
    """
    path = validate_destination(path)
    raw = (json.dumps(document(run_nonce, round_nonce), sort_keys=True) + "\n").encode()
    if len(raw) > MAX_BYTES:
        raise ValueError("handoff_document_capacity")
    pending = path.with_name(path.name + "." + secrets.token_hex(8) + ".pending")
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            if os.write(descriptor, raw) != len(raw):
                raise OSError("handoff_short_write")
        finally:
            os.close(descriptor)
        os.link(pending, path)  # Complete bytes become visible once; never overwrite.
    finally:
        pending.unlink()


def unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("handoff_duplicate_fields")
    return result


def read(path, run_nonce, round_nonce):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
            raise ValueError("handoff_file_invalid")
        raw = os.read(descriptor, MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_BYTES:
        raise ValueError("handoff_file_capacity")
    result = json.loads(raw, object_pairs_hook=unique_object)
    if (result != document(run_nonce, round_nonce) or type(result.get("schema_version")) is not int
            or result.get("delivered") is not True
            or any(result.get(k) is not False for k in UNVERIFIED)):
        raise ValueError("handoff_identity_or_scope_invalid")


def wait(path, run_nonce, round_nonce, original_deadline_ns):
    """At most 128 metadata reads, within the caller's unchanged absolute end."""
    started = time.monotonic_ns()
    state = {"reads": 0}
    try:
        acknowledged, reason = wait_bounded(path, run_nonce, round_nonce, original_deadline_ns, state)
    except KeyboardInterrupt:
        acknowledged, reason = False, "interrupted"
    return dict(scope=SCOPE, acknowledged=acknowledged, reason=reason, reads=state["reads"],
                max_reads=MAX_READS, max_bytes=MAX_BYTES,
                original_deadline_ns=original_deadline_ns,
                started_monotonic_ns=started, completed_monotonic_ns=time.monotonic_ns(),
                **UNVERIFIED)


def wait_bounded(path, run_nonce, round_nonce, original_deadline_ns, state):
    acknowledged, reason = False, "metadata_read_limit"
    for _ in range(MAX_READS):
        if time.monotonic_ns() >= original_deadline_ns:
            reason = "original_deadline"
            break
        state["reads"] += 1
        try:
            read(path, run_nonce, round_nonce)
        except OSError as error:
            if error.errno != errno.ENOENT:
                reason = "handoff_io_unavailable"
                break
        except (ValueError, UnicodeError):
            reason = "handoff_invalid"
            break
        else:
            acknowledged = time.monotonic_ns() < original_deadline_ns
            reason = "delivered" if acknowledged else "original_deadline"
            break
        remaining = original_deadline_ns - time.monotonic_ns()
        if remaining > 0:
            time.sleep(min(POLL_NS, remaining) / 1_000_000_000)
    return acknowledged, reason
