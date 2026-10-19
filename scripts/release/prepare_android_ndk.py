#!/usr/bin/env python3
"""Prepare a verified Flutter-pinned NDK in a new isolated Linux CI directory."""

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import shutil
import stat
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile


CATALOG_URL = "https://dl.google.com/android/repository/repository2-1.xml"
BASE_URL = "https://dl.google.com/android/repository/"
MAX_CATALOG = 8 * 1024**2
MAX_ARCHIVE = 1536 * 1024**2
MAX_EXPANDED = 6 * 1024**3
MAX_MEMBERS = 120000
FLUTTER_EXTENSION = "packages/flutter_tools/gradle/src/main/kotlin/FlutterExtension.kt"


class SetupError(Exception):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True)
class Archive:
    url: str
    bytes: int
    sha1: str
    root: str


def digest(path, algorithm="sha256"):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def required_version(flutter_sdk):
    source = flutter_sdk / FLUTTER_EXTENSION
    if source.stat().st_size > 128 * 1024:
        raise SetupError("flutter_ndk_declaration_invalid", "Flutter extension exceeds input bound")
    raw = source.read_bytes()
    matches = re.findall(rb'^\s*(?:const\s+)?val\s+ndkVersion\s*:\s*String\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', raw, re.M)
    if len(matches) != 1:
        raise SetupError("flutter_ndk_declaration_invalid", "Expected one Flutter ndkVersion declaration")
    return matches[0].decode("ascii"), hashlib.sha256(raw).hexdigest()


def catalog_archive(path, version):
    try:
        root = ET.fromstring(path.read_bytes())
    except ET.ParseError as error:
        raise SetupError("ndk_catalog_invalid", str(error)) from error
    local = lambda tag: tag.rsplit("}", 1)[-1]
    packages = [node for node in root.iter() if local(node.tag) == "remotePackage" and node.get("path") == "ndk;" + version]
    if len(packages) != 1:
        raise SetupError("ndk_catalog_ambiguous", "Required NDK package is absent or duplicated")
    def text(node, name):
        matches = [child for child in node.iter() if local(child.tag) == name]
        if len(matches) != 1 or matches[0].text is None:
            raise SetupError("ndk_catalog_invalid", "NDK archive field is absent or duplicated: " + name)
        return matches[0].text.strip()
    archives = []
    for archive in packages[0].iter():
        if local(archive.tag) != "archive":
            continue
        if text(archive, "host-os") != "linux":
            continue
        name, size, checksum = [text(archive, field) for field in ["url", "size", "checksum"]]
        checksum_node = next(node for node in archive.iter() if local(node.tag) == "checksum")
        if checksum_node.get("type", "sha1") != "sha1":
            raise SetupError("ndk_catalog_invalid", "Unsupported NDK catalog checksum algorithm")
        if not re.fullmatch(r"android-ndk-r[0-9]{1,3}[a-z]?-linux\.zip", name):
            raise SetupError("ndk_archive_url_invalid", "NDK archive must be a relative official Linux package")
        if not re.fullmatch(r"[0-9]{1,12}", size) or not 0 < int(size) <= MAX_ARCHIVE or not re.fullmatch(r"[a-fA-F0-9]{40}", checksum):
            raise SetupError("ndk_catalog_invalid", "Invalid NDK archive size or SHA1")
        archives.append(Archive(BASE_URL + name, int(size), checksum.lower(), name.removesuffix("-linux.zip")))
    if len(archives) != 1:
        raise SetupError("ndk_catalog_ambiguous", "Expected one Linux NDK archive")
    return archives[0]


def first_failure(evidence, value):
    path = evidence / "FIRST-FAILURE.json"
    if not path.exists():
        save(path, value)


def fetch_checked(url, label, limit, check, evidence, end, attempts):
    # Separate files retain the original error and bytes even if the second
    # bounded input download succeeds. No application or CI job is replayed.
    for attempt in range(1, 3):
        seconds = min(240 if label == "ndk" else 30, int(end - time.monotonic()) - 5)
        if seconds <= 0:
            raise SetupError("ndk_input_deadline", "Original toolchain setup deadline expired")
        target = evidence / f"{label}-{attempt}.payload"
        headers = evidence / f"{label}-{attempt}.headers"
        command = [shutil.which("curl") or "curl", "--disable", "--fail", "--silent", "--show-error", "--location",
                   "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "15", "--max-time", str(seconds),
                   "--max-filesize", str(limit), "--dump-header", str(headers), "--output", str(target), "--url", url]
        row = dict(stage=label, attempt=attempt, command=command, payload=target.name)
        try:
            with (evidence / f"{label}-{attempt}.stdout").open("wb") as out, (evidence / f"{label}-{attempt}.stderr").open("wb") as err:
                result = subprocess.run(command, stdout=out, stderr=err, timeout=seconds + 5)
            row["returncode"] = result.returncode
            if result.returncode:
                raise SetupError("ndk_download_failed", f"{label} curl exited {result.returncode}")
            if not target.is_file() or not 0 < target.stat().st_size <= limit:
                raise SetupError("ndk_download_size_invalid", label + " exceeds its input bound")
            value = check(target)
            row.update(result="verified", bytes=target.stat().st_size, sha256=digest(target))
            attempts.append(row)
            save(evidence / "DOWNLOADS.json", attempts)
            return target, value
        except (SetupError, OSError, subprocess.TimeoutExpired) as error:
            row.update(result="failed", reason_code=getattr(error, "code", "ndk_download_process_failed"), detail=str(error))
            if target.is_file():
                row.update(bytes=target.stat().st_size, sha256=digest(target))
            attempts.append(row)
            save(evidence / "DOWNLOADS.json", attempts)
            first_failure(evidence, row)
            if attempt == 2:
                raise SetupError(row["reason_code"], row["detail"]) from error
    raise SetupError("ndk_download_failed", "Input attempts exhausted")


def check_archive(path, archive):
    if path.stat().st_size != archive.bytes or digest(path, "sha1") != archive.sha1:
        raise SetupError("ndk_archive_digest_mismatch", "NDK bytes do not match the official catalog")


def extract_ndk(archive_path, stage, archive, end):
    stage.mkdir(mode=0o700)
    with zipfile.ZipFile(archive_path) as source:
        infos = source.infolist()
        if not 0 < len(infos) <= MAX_MEMBERS or sum(info.file_size for info in infos) > MAX_EXPANDED:
            raise SetupError("ndk_archive_capacity", "NDK member count or expanded bytes exceed bounds")
        names, links, members = set(), set(), []
        for info in infos:
            name = info.filename.rstrip("/")
            parts = PurePosixPath(name).parts
            mode = info.external_attr >> 16
            if not parts or parts[0] != archive.root or "\\" in name or name.startswith("/") or posixpath.normpath(name) != name or any(p in (".", "..") for p in parts) or name in names:
                raise SetupError("ndk_archive_path_invalid", "NDK archive contains a duplicate or escaping path")
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK) or info.file_size > 512 * 1024**2:
                raise SetupError("ndk_archive_member_invalid", "Unsupported NDK archive member")
            if info.is_dir() and (info.file_size != 0 or info.CRC != 0):
                raise SetupError("ndk_archive_member_invalid", "NDK directory entry has a payload")
            names.add(name)
            if stat.S_ISLNK(mode):
                links.add(name)
            members.append((info, name, mode))
        for info, name, mode in members:
            if time.monotonic() >= end:
                raise SetupError("ndk_input_deadline", "Original toolchain setup deadline expired")
            if any(str(parent) in links for parent in PurePosixPath(name).parents):
                raise SetupError("ndk_archive_path_invalid", "NDK archive writes through a symlink")
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if info.is_dir():
                target.mkdir(exist_ok=True)
            elif stat.S_ISLNK(mode):
                if info.file_size > 4096:
                    raise SetupError("ndk_archive_path_invalid", "NDK symlink target exceeds bound")
                link = source.read(info).decode("utf-8")
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), link))
                if not link or "\\" in link or link.startswith("/") or not resolved.startswith(archive.root + "/"):
                    raise SetupError("ndk_archive_path_invalid", "NDK symlink escapes its package")
                target.symlink_to(link)
            else:
                with source.open(info) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                target.chmod((mode & 0o777) or 0o644)
    return stage / archive.root


def inspect_ndk(root, version, evidence, end):
    properties = root / "source.properties"
    if properties.stat().st_size > 16384:
        raise SetupError("ndk_revision_invalid", "NDK source.properties exceeds bound")
    revisions = re.findall(r"^Pkg\.Revision\s*=\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$", properties.read_text(), re.M)
    if revisions != [version]:
        raise SetupError("ndk_revision_mismatch", "NDK source.properties disagrees with Flutter")
    llvm = root / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    for name in ["clang", "llvm-ar", "aarch64-linux-android21-clang", "aarch64-linux-android21-clang++",
                 "aarch64-linux-android23-clang", "aarch64-linux-android23-clang++"]:
        candidate = llvm / name
        if not candidate.is_file() or not os.access(candidate, os.X_OK) or not candidate.resolve().is_relative_to(root.resolve()):
            raise SetupError("ndk_toolchain_invalid", "NDK arm64 compiler or archiver is missing or escapes its root")
    seconds = min(10, int(end - time.monotonic()))
    if seconds <= 0:
        raise SetupError("ndk_input_deadline", "Original toolchain setup deadline expired")
    with (evidence / "clang-version.stdout").open("wb") as out, (evidence / "clang-version.stderr").open("wb") as err:
        result = subprocess.run([str(llvm / "clang"), "--version"], stdout=out, stderr=err, timeout=seconds)
    output = evidence / "clang-version.stdout"
    if result.returncode or not 0 < output.stat().st_size <= 65536 or b"clang" not in output.read_bytes().lower():
        raise SetupError("ndk_compiler_unverified", "NDK clang --version did not complete successfully")
    return dict(source_properties_sha256=digest(properties), compiler_path=str((llvm / "clang").resolve()),
                compiler_sha256=digest((llvm / "clang").resolve()), compiler_version_stdout_sha256=digest(output))


def bind_gradle_properties(properties, root):
    if properties is None:
        return None
    if not properties.is_absolute() or properties.name != "local.properties" or properties.is_symlink():
        raise SetupError("gradle_ndk_properties_invalid", "Expected an absolute regular local.properties path")
    target = properties.parent.resolve(strict=True) / properties.name
    if target.exists() and (not target.is_file() or target.stat().st_size > 128 * 1024):
        raise SetupError("gradle_ndk_properties_invalid", "Gradle local properties exceed input bounds")
    before = target.read_bytes() if target.exists() else b""
    if b"\0" in before:
        raise SetupError("gradle_ndk_properties_invalid", "Gradle local properties contain NUL")
    kept, replaced = [], False
    for line in re.findall(r"[^\r\n]*(?:\r\n|\r|\n|$)", before.decode("latin-1")):
        text = line.lstrip(" \t\f").rstrip("\r\n")
        if not text or text.startswith(("#", "!")):
            kept.append(line)
            continue
        if (len(text) - len(text.rstrip("\\"))) % 2:
            raise SetupError("gradle_ndk_properties_invalid", "Continued local properties are not supported")
        key = re.split(r"[=: \t\f]", text, maxsplit=1)[0]
        if "\\" in key:
            raise SetupError("gradle_ndk_properties_invalid", "Escaped local-property keys are ambiguous")
        if key == "ndk.dir":
            if replaced:
                raise SetupError("gradle_ndk_properties_invalid", "Duplicate ndk.dir property")
            replaced = True
        else:
            kept.append(line)
    escaped = []
    for char in str(root):
        if char == "\t":
            escaped.append("\\t")
        elif char in "\\ :=#!":
            escaped.append("\\" + char)
        elif 0x21 <= ord(char) <= 0x7e:
            escaped.append(char)
        else:
            encoded = char.encode("utf-16-be")
            escaped.extend(f"\\u{int.from_bytes(encoded[i:i + 2], 'big'):04x}" for i in range(0, len(encoded), 2))
    prefix = "".join(kept)
    if prefix and not prefix.endswith(("\n", "\r")):
        prefix += "\n"
    after = (prefix + "ndk.dir=" + "".join(escaped) + "\n").encode("latin-1")
    mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o600
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".p2wlan-ndk-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(after)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        temporary.replace(target)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return dict(path=str(target), before_sha256=hashlib.sha256(before).hexdigest(),
                after_sha256=digest(target), ndk_dir=str(root), other_properties_preserved=True)


def prepare(flutter_sdk, work_dir, github_env, source_commit, android_local_properties=None):
    if not re.fullmatch(r"[a-f0-9]{40}", source_commit):
        raise SetupError("source_commit_invalid", "Expected a complete checkout commit")
    if not work_dir.is_absolute() or any(c in str(work_dir) for c in "\r\n"):
        raise SetupError("ndk_work_directory_invalid", "Work directory must be absolute and single-line")
    parent = work_dir.parent.resolve(strict=True)
    if any((p / ".git").exists() for p in (parent, *parent.parents)):
        raise SetupError("ndk_work_directory_invalid", "NDK work directory must be outside Git checkouts")
    work_dir.mkdir(mode=0o700)  # Exclusive, including existing/dangling symlinks.
    evidence = work_dir / "evidence"
    evidence.mkdir(mode=0o700)
    end = time.monotonic() + 600
    attempts = []
    try:
        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
            raise SetupError("ndk_host_unsupported", "This installer only prepares Linux x86_64 CI toolchains")
        version, flutter_sha = required_version(flutter_sdk.resolve(strict=True))
        catalog, archive = fetch_checked(CATALOG_URL, "catalog", MAX_CATALOG, lambda p: catalog_archive(p, version), evidence, end, attempts)
        vendor, _ = fetch_checked(archive.url, "ndk", archive.bytes, lambda p: check_archive(p, archive), evidence, end, attempts)
        root = extract_ndk(vendor, work_dir / "toolchain", archive, end)
        compiler = inspect_ndk(root, version, evidence, end)
        receipt = dict(schema_version=1, scope="verified_Flutter_NDK_build_input_only", source_commit=source_commit,
                       required_ndk_version=version, flutter_extension_sha256=flutter_sha, catalog_sha256=digest(catalog),
                       official_archive=asdict(archive), downloaded_archive_sha256=digest(vendor), ndk_path=str(root),
                       ZIP_CRC_and_member_bounds_verified=True, compiler=compiler, downloads=attempts, native_os_write_verified=False,
                       physical_send_verified=False, canonical_current_owner_verified=False)
        # Only the fully verified successful input is reclaimed. Earlier failed
        # payloads/commands stay in evidence; the installed compiler stays live.
        vendor.unlink()
        receipt["successful_archive_reclaimed_after_verification"] = True
        receipt["gradle_local_properties"] = bind_gradle_properties(android_local_properties, root)
        values = {key: str(root) for key in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "P2WLAN_ANDROID_NDK_PATH"]}
        with github_env.open("a") as stream:
            stream.write("".join(f"{key}={value}\n" for key, value in values.items()))
        receipt["github_environment_exported_after_verification"] = True
        save(evidence / "VERIFIED.json", receipt)
        return receipt
    except (SetupError, OSError, ValueError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        record = dict(reason_code=getattr(error, "code", "ndk_setup_invalid"), detail=str(error), source_commit=source_commit)
        first_failure(evidence, record)
        save(evidence / "REJECTED.json", record)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flutter-sdk", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--android-local-properties", type=Path)
    args = parser.parse_args()
    try:
        receipt = prepare(args.flutter_sdk, args.work_dir, args.github_env, args.source_commit, args.android_local_properties)
    except (SetupError, OSError, ValueError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        parser.exit(1, json.dumps(dict(reason_code=getattr(error, "code", "ndk_setup_invalid"), detail=str(error))) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
