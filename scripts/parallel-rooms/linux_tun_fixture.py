"""Shared actual namespace/daemon/room startup; no application or native credit."""
import json
import secrets


def prepare(harness, lab, report):
    original, relay_fixture = harness.original, harness.relay_fixture
    endpoint, digest = harness.endpoint, harness.digest
    info = json.loads(original.run([str(lab.args.daemon), "--build-info"]).stdout)
    if info.get("git_commit") != lab.args.head or info.get("binary_sha256") != digest(lab.args.daemon):
        raise RuntimeError("original daemon/source/binary identity mismatch")
    lab.setup()
    relay_mode = getattr(lab.args, "relay_application", None)
    if relay_mode:
        relay_fixture.start(lab, report)
    else:
        lab.spawn("control", "control", [str(lab.args.control)], env={"PORT": "8080", "DB_PATH": str(lab.root / "control.db"),
                                                                  "JWT_SECRET": secrets.token_hex(32)})
    lab.wait("control readiness", lambda: lab.http("control", "/health"), 20)
    password = secrets.token_urlsafe(24)
    users = {label: lab.http("control", "/api/v1/register", method="POST",
                            body={"email": label + "@parallel.example", "password": password}) for label in ("a", "b")}
    room = lab.http("control", "/api/v1/rooms", method="POST", token=users["b"]["token"],
                    body={"name": "Linux TUN application evidence", "password": password})["room"]
    lab.http("control", "/api/v1/rooms/join", method="POST", token=users["a"]["token"],
             body={"room_code": room["room_code"], "password": password})
    for name, label in (("a1", "a"), ("b1", "b")):
        lab.daemon(name, label, room, users[label]["token"], 41001)
    initial = {name: lab.wait(name + " readiness", lambda name=name: endpoint(lab, name)) for name in ("a1", "b1")}
    if relay_mode:
        relay_fixture.wait(lab, initial, report)
    else:
        for name, peer in (("a1", "b1"), ("b1", "a1")):
            # Wait for the original committed encrypted Direct readiness; no
            # probe request is sent/retried to turn a failed run into a pass.
            lab.wait(name + " original Direct readiness", lambda name=name, peer=peer: any(
                p.get("node_id") == initial[peer]["node_id"] and p.get("online") is True
                and p.get("active_path") == "direct" for p in lab.status(name).get("peers", [])
            ))
    snapshots = {name: endpoint(lab, name, initial[peer]["virtual_ip"]) for name, peer in (("a1", "b1"), ("b1", "a1"))}
    if snapshots["a1"]["node_id"] == snapshots["b1"]["node_id"]:
        raise RuntimeError("two original endpoint identities collapsed")
    report["endpoint_routes_before"] = snapshots
    report["kernel_environment_verified"] = True
    lab.capture_stage("kernel_tun_routes_ready", successful=True)
    return initial, snapshots, users, room
