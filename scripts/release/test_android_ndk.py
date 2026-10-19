#!/usr/bin/env python3
"""Offline NDK input fixtures; these never download or qualify a real NDK/APK."""

import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

import prepare_android_ndk as ndk


VERSION = "28.2.13676358"
ROOT = "android-ndk-r28c"


def package(revision=VERSION, extra=()):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        rows = [("source.properties", f"Pkg.Revision = {revision}\n".encode(), stat.S_IFREG | 0o644),
                ("toolchains/llvm/prebuilt/linux-x86_64/bin/clang", b"#!/bin/sh\nprintf 'fixture clang version 0\\n'\n", stat.S_IFREG | 0o755)]
        for name in ["llvm-ar", "aarch64-linux-android21-clang", "aarch64-linux-android21-clang++",
                     "aarch64-linux-android23-clang", "aarch64-linux-android23-clang++"]:
            rows.append(("toolchains/llvm/prebuilt/linux-x86_64/bin/" + name, b"clang", stat.S_IFLNK | 0o777))
        for name, data, mode in rows:
            info = zipfile.ZipInfo(ROOT + "/" + name)
            info.create_system = 3
            info.external_attr = mode << 16
            archive.writestr(info, data)
        for name, data, mode in extra:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            archive.writestr(info, data)
    return output.getvalue()


def catalog(data):
    return f'''<repository><remotePackage path="ndk;{VERSION}"><archives><archive>
<host-os>linux</host-os><complete><size>{len(data)}</size>
<checksum>{hashlib.sha1(data).hexdigest()}</checksum><url>{ROOT}-linux.zip</url>
</complete></archive></archives></remotePackage></repository>'''.encode()


class NdkInputFixtureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.flutter = self.root / "flutter"
        source = self.flutter / ndk.FLUTTER_EXTENSION
        source.parent.mkdir(parents=True)
        source.write_text('val ndkVersion: String = "' + VERSION + '"\n')
        self.github_env = self.root / "github-env"
        self.github_env.write_text("EXISTING=1\n")
        self.real_run = subprocess.run

    def prepare_fixture(self, data, broken_first=False, local_properties=None):
        calls = []
        def run(command, **kwargs):
            if "--url" not in command:
                return self.real_run(command, **kwargs)
            calls.append(command)
            target = Path(command[command.index("--output") + 1])
            Path(command[command.index("--dump-header") + 1]).write_text("fixture HTTP 200\n")
            if command[-1] == ndk.CATALOG_URL:
                target.write_bytes(catalog(data))
            elif broken_first and target.name == "ndk-1.payload":
                target.write_bytes(b"fixture truncated download")
            else:
                target.write_bytes(data)
            return subprocess.CompletedProcess(command, 0)
        with patch.object(ndk.platform, "system", return_value="Linux"), patch.object(ndk.platform, "machine", return_value="x86_64"), patch.object(ndk.subprocess, "run", side_effect=run):
            result = ndk.prepare(self.flutter, self.root / "work", self.github_env, "1" * 40, local_properties)
        return result, calls

    def test_flutter_version_is_unique_and_invalid_declarations_are_rejected(self):
        self.assertEqual(ndk.required_version(self.flutter)[0], VERSION)
        source = self.flutter / ndk.FLUTTER_EXTENSION
        for text in ['// absent\n', 'val ndkVersion: String = "latest"\n', source.read_text() * 2]:
            source.write_text(text)
            with self.assertRaises(ndk.SetupError):
                ndk.required_version(self.flutter)

    def test_catalog_selects_exact_version_and_rejects_ambiguous_or_escaping_input(self):
        data = package()
        path = self.root / "catalog.xml"
        raw = catalog(data)
        path.write_bytes(raw)
        chosen = ndk.catalog_archive(path, VERSION)
        self.assertEqual((chosen.bytes, chosen.sha1, chosen.root), (len(data), hashlib.sha1(data).hexdigest(), ROOT))
        malformed = [raw.replace(b"ndk;28.2", b"ndk;30.0"), raw.replace(b"</archives>", raw[raw.index(b"<archive>"):raw.index(b"</archive>") + 10] + b"</archives>"),
                     raw.replace((ROOT + "-linux.zip").encode(), b"https://other.invalid/file.zip"),
                     raw.replace(b"<checksum>", b'<checksum type="sha256">'), raw.replace(b"<size>", b"<size></size><size>")]
        for candidate in malformed:
            path.write_bytes(candidate)
            with self.assertRaises(ndk.SetupError):
                ndk.catalog_archive(path, VERSION)

    def test_success_uses_one_verified_root_for_both_builders_and_reclaims_only_success_input(self):
        result, calls = self.prepare_fixture(package())
        root = Path(result["ndk_path"])
        self.assertEqual(result["required_ndk_version"], VERSION)
        self.assertEqual(len(calls), 2)
        env = self.github_env.read_text()
        for key in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "P2WLAN_ANDROID_NDK_PATH"]:
            self.assertIn(f"{key}={root}\n", env)
        self.assertTrue(env.startswith("EXISTING=1\n"))
        self.assertTrue(root.is_dir())
        self.assertTrue((root / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar").is_symlink())
        self.assertFalse((self.root / "work/evidence/ndk-1.payload").exists())
        self.assertTrue(result["successful_archive_reclaimed_after_verification"])
        self.assertTrue(result["ZIP_CRC_and_member_bounds_verified"])
        self.assertFalse((self.root / "work/evidence/FIRST-FAILURE.json").exists())
        self.assertEqual(result["compiler"]["compiler_sha256"], ndk.digest(Path(result["compiler"]["compiler_path"])))
        for flag in ["native_os_write_verified", "physical_send_verified", "canonical_current_owner_verified"]:
            self.assertIs(result[flag], False)

    def test_first_failed_download_payload_and_reason_survive_later_verified_input(self):
        result, calls = self.prepare_fixture(package(), broken_first=True)
        evidence = self.root / "work/evidence"
        first = json.loads((evidence / "FIRST-FAILURE.json").read_text())
        self.assertEqual(first["reason_code"], "ndk_archive_digest_mismatch")
        self.assertEqual((evidence / "ndk-1.payload").read_bytes(), b"fixture truncated download")
        self.assertFalse((evidence / "ndk-2.payload").exists())
        self.assertEqual(len(calls), 3)
        self.assertEqual([r["result"] for r in result["downloads"]], ["verified", "failed", "verified"])

    def test_wrong_package_revision_never_exports_environment(self):
        with self.assertRaises(ndk.SetupError) as raised:
            self.prepare_fixture(package(revision="30.0.16248370"))
        self.assertEqual(raised.exception.code, "ndk_revision_mismatch")
        self.assertEqual(self.github_env.read_text(), "EXISTING=1\n")
        self.assertTrue((self.root / "work/evidence/ndk-1.payload").is_file())
        self.assertTrue((self.root / "work/evidence/REJECTED.json").is_file())

    def test_archive_traversal_and_symlink_escape_do_not_write_outside_staging(self):
        for index, extra in enumerate([[(ROOT + "/../../escape", b"bad", stat.S_IFREG | 0o644)],
                                      [(ROOT + "/escape", b"../../outside", stat.S_IFLNK | 0o777)],
                                      [(ROOT + "/linked", b"inside", stat.S_IFLNK | 0o777), (ROOT + "/linked/file", b"bad", stat.S_IFREG | 0o644)]]):
            data = package(extra=extra)
            path = self.root / f"archive-{index}.zip"
            path.write_bytes(data)
            spec = ndk.Archive(ndk.BASE_URL + ROOT + "-linux.zip", len(data), hashlib.sha1(data).hexdigest(), ROOT)
            with self.assertRaises(ndk.SetupError):
                ndk.extract_ndk(path, self.root / f"stage-{index}", spec, time.monotonic() + 10)
            self.assertFalse((self.root / "escape").exists())
            self.assertFalse((self.root / "outside").exists())

    def test_existing_work_directory_and_checkout_are_refused_without_mutation(self):
        existing = self.root / "existing"
        existing.mkdir()
        marker = existing / "keep"
        marker.write_bytes(b"unchanged")
        with self.assertRaises(OSError):
            ndk.prepare(self.flutter, existing, self.github_env, "1" * 40)
        checkout = self.root / "checkout"
        checkout.mkdir()
        (checkout / ".git").write_text("fixture\n")
        with self.assertRaises(ndk.SetupError):
            ndk.prepare(self.flutter, checkout / "work", self.github_env, "1" * 40)
        self.assertFalse((checkout / "work").exists())
        self.assertEqual(marker.read_bytes(), b"unchanged")
        self.assertEqual(self.github_env.read_text(), "EXISTING=1\n")

    def test_missing_actual_arm64_api23_driver_never_exports_environment(self):
        source = io.BytesIO(package())
        output = io.BytesIO()
        with zipfile.ZipFile(source) as before, zipfile.ZipFile(output, "w") as after:
            for info in before.infolist():
                if not info.filename.endswith("/aarch64-linux-android23-clang"):
                    after.writestr(info, before.read(info))
        with self.assertRaises(ndk.SetupError) as raised:
            self.prepare_fixture(output.getvalue())
        self.assertEqual(raised.exception.code, "ndk_toolchain_invalid")
        self.assertEqual(self.github_env.read_text(), "EXISTING=1\n")

    def test_verified_ndk_binds_local_properties_without_changing_other_keys(self):
        properties = self.root / "local.properties"
        before = b"# keep\r\nsdk.dir=/existing/sdk\nndk.dir=/older\nother.key=unchanged"
        properties.write_bytes(before)
        result, _ = self.prepare_fixture(package(), local_properties=properties)
        root = Path(result["ndk_path"])
        expected = b"# keep\r\nsdk.dir=/existing/sdk\nother.key=unchanged\n" + f"ndk.dir={root}\n".encode()
        self.assertEqual(properties.read_bytes(), expected)
        self.assertEqual(result["gradle_local_properties"]["before_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(result["gradle_local_properties"]["after_sha256"], ndk.digest(properties))
        self.assertIn(f"ANDROID_NDK_HOME={root}\n", self.github_env.read_text())
        escaped_root = self.root / "ndk value#x:\u00e9"
        escaped_root.mkdir()
        ndk.bind_gradle_properties(properties, escaped_root)
        self.assertTrue(properties.read_bytes().endswith(b"ndk.dir=" + str(self.root).encode() + b"/ndk\\ value\\#x\\:\\u00e9\n"))

    def test_symlink_and_ambiguous_gradle_properties_do_not_mutate_or_export(self):
        original = self.root / "original-properties"
        original.write_bytes(b"unchanged\n")
        properties = self.root / "local.properties"
        properties.symlink_to(original)
        with self.assertRaises(ndk.SetupError) as raised:
            self.prepare_fixture(package(), local_properties=properties)
        self.assertEqual(raised.exception.code, "gradle_ndk_properties_invalid")
        self.assertEqual(original.read_bytes(), b"unchanged\n")
        self.assertEqual(self.github_env.read_text(), "EXISTING=1\n")
        self.assertTrue(properties.is_symlink())
        for i, data in enumerate([b"ndk.dir=/a\nndk.dir=/b\n", b"ndk\\.dir=/a\n", b"sdk.dir=/continued\\\nvalue\n"]):
            directory = self.root / str(i)
            directory.mkdir()
            path = directory / "local.properties"
            path.write_bytes(data)
            with self.assertRaises(ndk.SetupError):
                ndk.bind_gradle_properties(path, self.root)
            self.assertEqual(path.read_bytes(), data)

    def test_member_capacity_deadline_and_directory_payloads_are_rejected(self):
        data = package()
        path = self.root / "bounded.zip"
        path.write_bytes(data)
        spec = ndk.Archive(ndk.BASE_URL + ROOT + "-linux.zip", len(data), hashlib.sha1(data).hexdigest(), ROOT)
        for index, setting in enumerate(["MAX_EXPANDED", "MAX_MEMBERS"]):
            with patch.object(ndk, setting, 1), self.assertRaises(ndk.SetupError):
                ndk.extract_ndk(path, self.root / f"bounded-stage-{index}", spec, time.monotonic() + 10)
        with self.assertRaises(ndk.SetupError):
            ndk.extract_ndk(path, self.root / "expired-stage", spec, time.monotonic() - 1)
        path.write_bytes(package(extra=[(ROOT + "/bad-directory/", b"unexpected", stat.S_IFDIR | 0o755)]))
        with self.assertRaises(ndk.SetupError):
            ndk.extract_ndk(path, self.root / "directory-stage", spec, time.monotonic() + 10)


if __name__ == "__main__":
    unittest.main()
