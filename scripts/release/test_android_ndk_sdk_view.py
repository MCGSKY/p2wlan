import hashlib
from pathlib import Path
import tempfile
import time
import unittest

from prepare_android_sdk_view import prepare_sdk_view, SdkViewError
import prepare_android_ndk as ndk
import test_android_ndk as fixture
from unittest.mock import patch


class SdkViewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.sdk = self.base / "original-sdk"
        self.work = self.base / "isolated-work"
        self.ndk = self.work / "toolchain" / "checked-ndk"
        self.sdk.mkdir()
        self.ndk.mkdir(parents=True)
        (self.ndk / "source.properties").write_text("Pkg.Revision = 28.2.13676358\n")
        (self.sdk / "platforms").mkdir()
        (self.sdk / "platforms" / "original").write_bytes(b"original platform bytes")

    def prepare(self, version="28.2.13676358"):
        return prepare_sdk_view(self.sdk, self.work, self.ndk, version)

    def test_actual_sdk_discovery_sees_checked_version_and_original_platform(self):
        receipt = self.prepare()
        view = Path(receipt["sdk_root"])
        discovered = sorted(p.name for p in (view / "ndk").iterdir()
                            if p.is_dir() and (p / "source.properties").is_file())
        self.assertEqual(discovered, ["28.2.13676358"])
        self.assertEqual((view / "ndk/28.2.13676358").resolve(), self.ndk)
        self.assertEqual((view / "platforms").resolve(), self.sdk / "platforms")
        self.assertEqual((view / "platforms/original").read_bytes(), b"original platform bytes")
        self.assertEqual(receipt["source_properties_sha256"], hashlib.sha256(
            (self.ndk / "source.properties").read_bytes()).hexdigest())
        self.assertFalse(receipt["original_sdk_entries_replaced"])

    def test_existing_broken_same_version_and_other_installed_version_are_preserved(self):
        old = self.sdk / "ndk/28.2.13676358"
        old.mkdir(parents=True)
        (old / "truncated.zip").write_bytes(b"original failed download prefix")
        other = self.sdk / "ndk/27.0.12077973"
        other.mkdir()
        (other / "source.properties").write_text("Pkg.Revision=27.0.12077973\n")
        view = Path(self.prepare()["sdk_root"])
        self.assertEqual((old / "truncated.zip").read_bytes(), b"original failed download prefix")
        self.assertFalse(old.is_symlink())
        self.assertEqual((view / "ndk/28.2.13676358").resolve(), self.ndk)
        self.assertEqual((view / "ndk/27.0.12077973").resolve(), other)

    def test_mismatched_or_missing_checked_revision_rejects_before_view_creation(self):
        for data in [b"Pkg.Revision=27.0.12077973\n", b"", b"Pkg.Revision=28.2.13676358\nPkg.Revision=28.2.13676358\n"]:
            (self.ndk / "source.properties").write_bytes(data)
            with self.assertRaises(SdkViewError):
                self.prepare()
            self.assertFalse((self.work / "sdk-view").exists())

    def test_existing_sdk_view_is_never_overwritten(self):
        self.prepare()
        marker = self.work / "sdk-view/original-marker"
        marker.write_bytes(b"keep original view")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(marker.read_bytes(), b"keep original view")

    def test_expired_original_setup_deadline_creates_no_sdk_view(self):
        with self.assertRaises(SdkViewError) as raised:
            prepare_sdk_view(self.sdk, self.work, self.ndk, "28.2.13676358", end=time.monotonic() - 1)
        self.assertEqual(raised.exception.code, "ndk_input_deadline")
        self.assertFalse((self.work / "sdk-view").exists())

    def test_relative_overlapping_and_oversized_sdk_inputs_reject(self):
        with self.assertRaises(SdkViewError):
            prepare_sdk_view(Path("relative"), self.work, self.ndk, "28.2.13676358")
        with self.assertRaises(SdkViewError):
            prepare_sdk_view(self.work, self.work, self.ndk, "28.2.13676358")
        for i in range(257):
            (self.sdk / ("component-" + str(i))).touch()
        with self.assertRaises(SdkViewError):
            self.prepare()
        self.assertFalse((self.work / "sdk-view").exists())


class SdkPrepareIntegration(unittest.TestCase):
    def setUp(self):
        fixture.NdkInputFixtureTests.setUp(self)
        self.sdk = self.root / "original-sdk"
        self.sdk.mkdir()
        (self.sdk / "platforms").mkdir()
        (self.sdk / "platforms/original").write_bytes(b"original platform")
        self.properties = self.root / "local.properties"
        self.properties.write_text("sdk.dir=" + str(self.sdk) + "\n")

    def prepare(self):
        original = ndk.prepare

        def with_sdk(*args, **kwargs):
            return original(*args, **kwargs, android_sdk_root=self.sdk)

        with patch.object(ndk, "prepare", with_sdk):
            return fixture.NdkInputFixtureTests.prepare_fixture(
                self, fixture.package(), local_properties=self.properties
            )

    def test_both_sdk_environment_paths_expose_exact_checked_input_after_verification(self):
        receipt, calls = self.prepare()
        view = Path(receipt["android_sdk_view"]["sdk_root"])
        required = receipt["required_ndk_version"]
        root = Path(receipt["ndk_path"])
        self.assertEqual((view / "ndk" / required).resolve(), root)
        self.assertEqual((view / "platforms/original").read_bytes(), b"original platform")
        env = dict(line.split("=", 1) for line in self.github_env.read_text().splitlines())
        self.assertEqual(env["EXISTING"], "1")
        self.assertEqual(env["ANDROID_HOME"], str(view))
        self.assertEqual(env["ANDROID_SDK_ROOT"], str(view))
        for key in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "P2WLAN_ANDROID_NDK_PATH"]:
            self.assertEqual(env[key], str(root))
        self.assertTrue(receipt["ZIP_CRC_and_member_bounds_verified"])
        self.assertTrue(receipt["github_environment_exported_after_verification"])
        self.assertEqual(len(calls), 2)
        self.assertIn("sdk.dir=" + str(self.sdk), self.properties.read_text())
        self.assertIn("ndk.dir=" + str(root), self.properties.read_text())

    def test_same_version_host_corruption_is_not_overwritten_or_selected(self):
        bad = self.sdk / "ndk" / fixture.VERSION
        bad.mkdir(parents=True)
        original = bad / "failed-prefix.zip"
        original.write_bytes(b"preserve original SDK failure bytes")
        receipt, _ = self.prepare()
        view = Path(receipt["android_sdk_view"]["sdk_root"])
        self.assertEqual(original.read_bytes(), b"preserve original SDK failure bytes")
        self.assertFalse(bad.is_symlink())
        self.assertEqual((view / "ndk" / fixture.VERSION).resolve(), Path(receipt["ndk_path"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
