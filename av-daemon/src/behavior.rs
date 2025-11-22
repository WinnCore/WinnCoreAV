#![allow(dead_code)]
//! Skeleton eBPF behavioral monitor to align with the Phase 2 architecture.
//! This module is feature-gated (`behavior_monitor`) so normal builds are
//! unaffected until BPF artifacts and aya setup are wired in.

use anyhow::Result;
use aya::{
    programs::{KProbe, TracePoint},
    Ebpf,
};
use bytes::BytesMut;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub enum BehavioralEvent {
    SuspiciousProcessSpawn {
        pid: u32,
        ppid: u32,
        comm: String,
        timestamp: u64,
    },
    SuspiciousNetworkActivity {
        pid: u32,
        dest_ip: String,
        dest_port: u16,
        protocol: String,
        timestamp: u64,
    },
    FileModification {
        pid: u32,
        path: String,
        operation: String,
        timestamp: u64,
    },
    PrivilegeEscalation {
        pid: u32,
        old_uid: u32,
        new_uid: u32,
        syscall: String,
        timestamp: u64,
    },
}

/// Runtime controller for eBPF probes. Actual BPF bytecode loading is deferred
/// until BPF assets are added to the repo.
pub struct BehavioralMonitor {
    bpf: Option<Ebpf>,
    event_tx: mpsc::UnboundedSender<BehavioralEvent>,
    tasks: Vec<JoinHandle<()>>,
}

impl BehavioralMonitor {
    pub fn new(event_tx: mpsc::UnboundedSender<BehavioralEvent>) -> Result<Self> {
        Ok(Self {
            bpf: None,
            event_tx,
            tasks: Vec::new(),
        })
    }

    pub fn load_programs(&mut self, bytes: &[u8]) -> Result<()> {
        let mut bpf = Ebpf::load(bytes)?;

        if let Some(program) = bpf.program_mut("trace_exec") {
            let tp: &mut TracePoint = program.try_into()?;
            tp.load()?;
            tp.attach("sched", "sched_process_exec")?;
        }

        if let Some(program) = bpf.program_mut("trace_connect") {
            let kp: &mut KProbe = program.try_into()?;
            kp.load()?;
            kp.attach("tcp_connect", 0)?;
        }

        self.bpf = Some(bpf);
        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        // TODO: wire perf event consumption once BPF bytecode is added.
        if self.bpf.is_none() {
            return Ok(());
        }
        Ok(())
    }

    pub async fn stop(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

fn parse_exec_event(_buf: &mut BytesMut) -> Option<BehavioralEvent> {
    // Placeholder until BPF structs are defined.
    None
}
