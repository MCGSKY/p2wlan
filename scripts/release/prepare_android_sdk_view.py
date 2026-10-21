"""Expose a checked NDK to Flutter's SDK-side-by-side discovery."""

from itertools import islice
import hashlib
import re
import time


class SdkViewError(ValueError):
    def __init__(self, code, detail):
        super().__init__(detail)
        self.code = code


def prepare_sdk_view(android_sdk_root, work_dir, ndk_root, version, end=None):
    """Create an exclusive SDK view without replacing the original SDK."""
    def check_deadline():
        if end is not None and time.monotonic() >= end:
            raise SdkViewError("ndk_input_deadline", "Original toolchain setup deadline expired")

    check_deadline()
    if not android_sdk_root.is_absolute() or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SdkViewError("ndk_sdk_view_input_invalid", "Expected an absolute SDK and a complete NDK version")
    sdk = android_sdk_root.resolve(strict=True)
    work = work_dir.resolve(strict=True)
    ndk = ndk_root.resolve(strict=True)
    if not sdk.is_dir() or not ndk.is_dir() or sdk.is_relative_to(work) or work.is_relative_to(sdk):
        raise SdkViewError("ndk_sdk_view_input_invalid", "SDK and work directories must be separate")
    properties = ndk / "source.properties"
    if not properties.is_file() or properties.stat().st_size > 65536:
        raise SdkViewError("ndk_sdk_view_revision_invalid", "Checked NDK source properties are missing or oversized")
    raw = properties.read_bytes()
    revisions = re.findall(rb"^\s*Pkg\.Revision\s*=\s*([^\r\n]+)", raw, re.M)
    if revisions != [version.encode("ascii")]:
        raise SdkViewError("ndk_sdk_view_revision_invalid", "Checked NDK does not match the required version")
    components = list(islice(sdk.iterdir(), 257))
    prior_ndks = list(islice((sdk / "ndk").iterdir(), 257)) if (sdk / "ndk").is_dir() else []
    if len(components) > 256 or len(prior_ndks) > 256:
        raise SdkViewError("ndk_sdk_view_capacity", "SDK component listing exceeds bounds")
    view = work / "sdk-view"
    check_deadline()
    view.mkdir(mode=0o700)
    for source in components:
        check_deadline()
        if source.name != "ndk":
            (view / source.name).symlink_to(source, target_is_directory=source.is_dir())
    versions = view / "ndk"
    versions.mkdir(mode=0o700)
    for source in prior_ndks:
        check_deadline()
        if source.name != version:
            (versions / source.name).symlink_to(source, target_is_directory=source.is_dir())
    installed = versions / version
    installed.symlink_to(ndk, target_is_directory=True)
    if not installed.is_dir() or installed.resolve(strict=True) != ndk:
        raise SdkViewError("ndk_sdk_view_binding_invalid", "SDK view does not resolve to the checked NDK")
    check_deadline()
    return dict(sdk_root=str(view), original_sdk_root=str(sdk), ndk_path=str(installed),
                resolved_ndk_path=str(ndk), required_ndk_version=version,
                source_properties_sha256=hashlib.sha256(raw).hexdigest(),
                original_sdk_entries_replaced=False, checked_ndk_exposed_to_Flutter_sdk_discovery=True)
