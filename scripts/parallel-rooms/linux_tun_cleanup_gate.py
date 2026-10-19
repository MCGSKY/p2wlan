"""Cleanup-only admission for an independent measurement; no native credit."""
import argparse
import json
from pathlib import Path
import re
import stat


MAX_REPORT_BYTES = 4 * 1024 * 1024
SCOPES = {
    "linux-tun-application": "linux_same_host_kernel_tun_application",
    "linux-tun-recovery": "linux_same_host_kernel_tun_application_blackhole_recovery",
    "linux-tun-server-stall": "linux_same_host_kernel_tun_udp_application_server_pause",
    "linux-tun-relay-udp": "linux_same_host_kernel_tun_relay_application",
    "linux-tun-relay-tcp": "linux_same_host_kernel_tun_relay_application",
}


class AdmissionFailure(ValueError):
    pass


def unique_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise AdmissionFailure("report_invalid")
    return value


def read_reports(root):
    reports = {}
    for name in SCOPES:
        path = Path(root) / name / "report.json"
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                raise AdmissionFailure("report_unavailable")
            with path.open("rb") as source:
                raw = source.read(MAX_REPORT_BYTES + 1)
            if len(raw) > MAX_REPORT_BYTES:
                raise AdmissionFailure("report_too_large")
            reports[name] = json.loads(raw, object_pairs_hook=unique_object)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise AdmissionFailure("report_unavailable_or_invalid") from error
    return reports


def check_cleanup(report):
    network = report.get("network_cleanup")
    control = report.get("kernel_control_cleanup")
    if (report.get("cleanup_complete") is not True or not isinstance(network, dict)
            or network.get("admitted") is not True or network.get("complete") is not True
            or network.get("remaining") != [] or not isinstance(control, dict)
            or control.get("complete") is not True or control.get("errors") != []):
        raise AdmissionFailure("cleanup_unproven")
    groups = report.get("process_cleanup")
    limits = report.get("limits")
    cap = limits.get("process_groups") if isinstance(limits, dict) else None
    if (type(cap) is not int or not 0 < cap <= 11 or not isinstance(groups, list)
            or not 0 < len(groups) <= cap):
        raise AdmissionFailure("original_process_groups_unproven")
    for group in groups:
        if (not isinstance(group, dict)
                or any(group.get(k) is not True for k in
                       ["complete", "group_absent", "child_reaped", "anchor_reaped"])
                or any(type(group.get(k)) is not int or group[k] <= 0 for k in
                       ["original_child_pid", "original_anchor_pid"])):
            raise AdmissionFailure("original_process_groups_unproven")


def admit(reports, head, run_id, attempt):
    if (any(type(v) is not str for v in [head, run_id, attempt])
            or not re.fullmatch(r"[0-9a-f]{40}", head)
            or any(not re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in [run_id, attempt])):
        raise AdmissionFailure("invocation_identity_invalid")
    if not isinstance(reports, dict) or set(reports) != set(SCOPES):
        raise AdmissionFailure("original_five_reports_required")
    identifiers = set()
    for name, scope in SCOPES.items():
        report = reports[name]
        if not isinstance(report, dict) or report.get("scope") != scope:
            raise AdmissionFailure("scope_mismatch")
        if report.get("source_commit") != head:
            raise AdmissionFailure("foreign_source")
        if (report.get("github_run_id") != run_id
                or report.get("github_run_attempt") != attempt):
            raise AdmissionFailure("foreign_run")
        identifier = report.get("run_id")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise AdmissionFailure("experiment_identity_unproven")
        identifiers.add(identifier)
        check_cleanup(report)
    return dict(scope="original_five_cleanup_admission_only", allowed=True,
                reports=5, canonical_current_owner_verified=False,
                native_os_write_verified=False, physical_send_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-root", required=True, type=Path)
    parser.add_argument("--head", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt", required=True)
    args = parser.parse_args()
    try:
        result = admit(read_reports(args.reports_root), args.head, args.run_id, args.attempt)
    except AdmissionFailure as error:
        print(json.dumps(dict(scope="original_five_cleanup_admission_only",
                              allowed=False, reason=str(error))))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
