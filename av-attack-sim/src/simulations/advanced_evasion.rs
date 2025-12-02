//! Advanced evasion techniques (2024-2025).

use crate::framework::{AttackSimulation, AttackSimulator, SimulationExecution, Tactic};
use std::sync::Arc;

pub fn register(simulator: &mut AttackSimulator) {
    // io_uring syscall bypass
    simulator.register(AttackSimulation {
        id: "adv-001".to_string(),
        name: "io_uring Activity Check".to_string(),
        technique_id: "T1014.io_uring".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Check for io_uring syscall bypass".to_string(),
        expected_alert: "io_uring monitoring active".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["ls -la /proc/*/fd 2>/dev/null | grep io_uring | head -5 || echo 'no io_uring activity'".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // eBPF rootkit check
    simulator.register(AttackSimulation {
        id: "adv-002".to_string(),
        name: "eBPF Program Enumeration".to_string(),
        technique_id: "T1014.ebpf".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Enumerate loaded eBPF programs".to_string(),
        expected_alert: "eBPF monitoring active".to_string(),
        should_detect: true,
        requires_root: true,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "bpftool prog list 2>/dev/null | head -10 || echo 'bpftool not available'"
                    .to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // Direct syscall detection
    simulator.register(AttackSimulation {
        id: "adv-003".to_string(),
        name: "Direct Syscall Pattern".to_string(),
        technique_id: "T1106".to_string(),
        tactic: Tactic::Execution,
        description: "Check for direct syscall detection".to_string(),
        expected_alert: "Direct syscall monitoring active".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![r#"cat > /tmp/winncore-syscall-test.c << 'EOF'
#include <unistd.h>
int main() {
    asm volatile(
        "mov x8, #64\n"
        "svc #0\n"
    );
    return 0;
}
EOF"#
                .to_string()],
            cleanup: vec!["rm -f /tmp/winncore-syscall-test.c".to_string()],
            artifacts: vec!["/tmp/winncore-syscall-test.c".to_string()],
        }),
    });

    // Container escape pattern
    simulator.register(AttackSimulation {
        id: "adv-004".to_string(),
        name: "Container Escape Pattern".to_string(),
        technique_id: "T1611".to_string(),
        tactic: Tactic::PrivilegeEscalation,
        description: "Container escape technique detection".to_string(),
        expected_alert: "Container escape attempt detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "ls -la /var/run/docker.sock 2>/dev/null || echo 'no docker socket'".to_string(),
                "cat /proc/1/cgroup 2>/dev/null | grep -E 'docker|lxc|kubepods' | head -1 || echo 'not in container'".to_string(),
            ],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // Process injection (ptrace)
    simulator.register(AttackSimulation {
        id: "adv-005".to_string(),
        name: "Ptrace Process Injection".to_string(),
        technique_id: "T1055.008".to_string(),
        tactic: Tactic::DefenseEvasion,
        description: "Ptrace-based process injection".to_string(),
        expected_alert: "Process injection detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec!["grep -l 'TracerPid:[[:space:]]*[1-9]' /proc/*/status 2>/dev/null | wc -l || echo '0'".to_string()],
            cleanup: vec![],
            artifacts: vec![],
        }),
    });

    // LD_PRELOAD injection
    simulator.register(AttackSimulation {
        id: "adv-006".to_string(),
        name: "LD_PRELOAD Hijack".to_string(),
        technique_id: "T1574.006".to_string(),
        tactic: Tactic::Persistence,
        description: "LD_PRELOAD library injection".to_string(),
        expected_alert: "LD_PRELOAD hijack detected".to_string(),
        should_detect: true,
        requires_root: false,
        executor: Arc::new(|| SimulationExecution {
            commands: vec![
                "cat /etc/ld.so.preload 2>/dev/null || echo 'no ld.so.preload'".to_string(),
                "echo '/tmp/evil.so' > /tmp/winncore-ldpreload-test".to_string(),
            ],
            cleanup: vec!["rm -f /tmp/winncore-ldpreload-test".to_string()],
            artifacts: vec!["/tmp/winncore-ldpreload-test".to_string()],
        }),
    });
}
