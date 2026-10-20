//! Full startup controls in isolated test processes. No system TUN, route
//! changes, native-credit assertion, or external STUN service is involved.
use super::*;

const CHILD_CASE: &str = "P2WLAN_STARTUP_POLICY_TEST_CHILD";

fn isolated(test_name: &str, case: &str) {
    if std::env::var(CHILD_CASE).as_deref() == Ok(case) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                match case {
                    "relay-only" => observe_startup(PathPolicy::RelayOnly, true, false).await,
                    "legacy" => observe_startup(PathPolicy::DirectFirst, false, false).await,
                    "direct" => {
                        // Auto is also the CLI's --prefer-relay policy: Relay
                        // preference must keep Direct upgrade workers alive.
                        for policy in [
                            PathPolicy::Auto,
                            PathPolicy::DirectFirst,
                            PathPolicy::Score,
                            PathPolicy::DirectSticky,
                        ] {
                            observe_startup(policy, true, true).await;
                        }
                    }
                    _ => panic!("unknown startup control case"),
                }
            });
        return;
    }
    // Isolate the existing TUN-disable environment switch from other tests.
    // Only this owned child can be terminated by the bounded test watchdog.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(CHILD_CASE, case)
        .env("P2WLAN_DISABLE_TUN", "1")
        .env_remove("P2WLAN_OS_REQUEST_CONTROL_FD")
        .env_remove("P2WLAN_OS_REQUEST_CONTROL_SOCKET")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(90);
    let ended = loop {
        if child.try_wait().unwrap().is_some() {
            break true;
        }
        if Instant::now() >= end {
            child.kill().unwrap();
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1 passed; 0 failed; 0 ignored"),
        "child did not execute its exact startup control: status={} stdout={stdout} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        ended && output.status.success(),
        "startup child {case}: ended={ended} status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn observe_startup(policy: PathPolicy, prefer_direct: bool, direct_expected: bool) {
    let mut config =
        Config::generate_default("http://127.0.0.1:1", "startup-policy-control").unwrap();
    config.config_path = None;
    config.network.manual = true;
    config.network.validate_overlay = false;
    config.network.udp_bind = "127.0.0.1:0".into();
    config.network.fresh_mapping_harness_loopback = true;
    config.network.upnp_enabled = false;
    config.network.socket_pool_enabled = false;
    config.network.stun_timeout_ms = 20;
    config.diagnostics.enabled = false;
    config.relay.servers.clear();
    config.relay.path_policy = policy;
    config.relay.prefer_direct = prefer_direct;
    // Unused malformed Direct-only sources would fail the old startup path.
    // The enabled cases use the existing explicit clear value, without DNS.
    let source = if direct_expected { "none" } else { "[" };
    config.network.stun_servers = vec![source.into()];
    config.network.udp_observers = vec![source.into()];
    let mut daemon = Daemon::new(config);
    let manager = daemon.task_manager.clone();
    let shutdown = daemon.shutdown_tx.clone();
    let udp_slot = daemon.udp_transport.clone();
    let runtime_stun = daemon.runtime_stun_servers.clone();
    let mut run = tokio::spawn(async move { daemon.run().await });
    let required = [
        "network-outbound",
        "relay-peer-validation",
        "relay-peer-probe",
        "handshake-maintenance",
    ];
    let startup = timeout(Duration::from_secs(8), async {
        loop {
            if run.is_finished() {
                return Err("daemon exited before workers were installed");
            }
            let statuses = manager.task_statuses().await;
            if required
                .iter()
                .all(|name| statuses.iter().any(|task| task.name == *name))
                && (!direct_expected || udp_slot.read().await.is_some())
            {
                return Ok(statuses);
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let udp_address = udp_slot
        .read()
        .await
        .as_ref()
        .map(|udp| udp.local_addr().unwrap());
    shutdown.send_replace(true);
    let result = timeout(Duration::from_secs(7), &mut run).await;
    let statuses = startup
        .expect("bounded startup observation expired")
        .expect("startup failed");
    result
        .expect("owned daemon did not join")
        .expect("daemon task panicked")
        .expect("daemon returned an error");
    for name in required {
        assert!(
            statuses
                .iter()
                .any(|task| task.name == name && task.running && task.error.is_none()),
            "retained worker {name} was not running: {statuses:?}"
        );
    }
    for name in ["direct-first-deadline", "direct-probe", "udp-direct"] {
        let task = statuses.iter().find(|task| task.name == name);
        assert_eq!(
            task.is_some(),
            direct_expected,
            "actual worker {name}: {statuses:?}"
        );
        if let Some(task) = task {
            assert!(task.running && task.error.is_none());
        }
    }
    assert_eq!(udp_address.is_some(), direct_expected);
    assert!(runtime_stun.read().await.is_empty());
    assert!(udp_slot.read().await.is_none());
    assert!(manager.task_statuses().await.is_empty());
    if let Some(address) = udp_address {
        let rebound =
            std::net::UdpSocket::bind(address).expect("owned UDP bind was not released after join");
        drop(rebound);
    }
}

#[test]
fn relay_only_skips_direct_dns_workers_and_bind() {
    isolated(
        "tests::startup_policy::relay_only_skips_direct_dns_workers_and_bind",
        "relay-only",
    );
}

#[test]
fn legacy_prefer_direct_false_skips_direct_workers() {
    isolated(
        "tests::startup_policy::legacy_prefer_direct_false_skips_direct_workers",
        "legacy",
    );
}

#[test]
fn direct_capable_policies_register_workers_and_release_bind_after_join() {
    isolated("tests::startup_policy::direct_capable_policies_register_workers_and_release_bind_after_join", "direct");
}
