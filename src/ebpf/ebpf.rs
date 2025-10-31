use crate::ssh::ssh::SshSession;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("eBPF not supported on kernel")]
    NotSupported,

    #[error("Compilation failed: {0}")]
    CompilationError(String),

    #[error("Load failed: {0}")]
    LoadError(String),

    #[error("SSH error: {0}")]
    SshError(#[from] crate::ssh::ssh::SshError),
}

pub type Result<T> = std::result::Result<T, EbpfError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfProgram {
    pub id: String,
    pub name: String,
    pub program_type: ProgramType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProgramType {
    AvcMonitor,
    ContextTransition,
    Performance,
    Custom(String),
}

/// Check if eBPF is supported on the host
pub async fn check_support(session: &SshSession) -> Result<bool> {
    info!("Checking eBPF support on {}", session.host());

    // Check kernel version
    let kernel_output = session.execute("uname -r").await?;
    let version = kernel_output.trim();

    // Parse major version
    let major: u32 = version
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if major < 4 {
        warn!("Kernel version {} is too old for eBPF", version);
        return Ok(false);
    }

    // Check for BPF filesystem
    let bpf_check = session.execute("ls /sys/fs/bpf 2>/dev/null || echo 'not_found'").await?;
    if bpf_check.trim() == "not_found" {
        warn!("BPF filesystem not mounted");
        // Try to mount it
        let _ = session.execute_sudo("mount -t bpf none /sys/fs/bpf").await;
    }

    // Check for required tools
    let has_bpftool = session.execute("which bpftool").await.is_ok();
    let has_clang = session.execute("which clang").await.is_ok();

    if !has_bpftool {
        warn!("bpftool not found on {}", session.host());
    }

    if !has_clang {
        warn!("clang not found on {}", session.host());
    }

    Ok(true)
}

/// Load a simple AVC monitor program
pub async fn load_avc_monitor(session: &SshSession) -> Result<EbpfProgram> {
    info!("Loading AVC monitor on {}", session.host());

    if !check_support(session).await? {
        return Err(EbpfError::NotSupported);
    }

    let program_id = format!("avc_monitor_{}", uuid::Uuid::new_v4().simple());
    let program_source = generate_avc_monitor_source();

    // Write source to remote
    let source_path = format!("/tmp/{}.c", program_id);
    let write_cmd = format!("cat > {} << 'EOF'\n{}\nEOF", source_path, program_source);
    session.execute(&write_cmd).await?;

    // Compile
    let obj_path = format!("/tmp/{}.o", program_id);
    let compile_cmd = format!(
        "clang -O2 -target bpf -c {} -o {} 2>&1 || echo 'COMPILATION_FAILED'",
        source_path, obj_path
    );

    let compile_output = session.execute(&compile_cmd).await?;
    if compile_output.contains("COMPILATION_FAILED") {
        return Err(EbpfError::CompilationError(compile_output));
    }

    // Load program
    let load_cmd = format!(
        "bpftool prog load {} /sys/fs/bpf/{} 2>&1 || echo 'LOAD_FAILED'",
        obj_path, program_id
    );

    let load_output = session.execute_sudo(&load_cmd).await?;
    if load_output.contains("LOAD_FAILED") {
        return Err(EbpfError::LoadError(load_output));
    }

    // Clean up source files
    let _ = session.execute(&format!("rm -f {} {}", source_path, obj_path)).await;

    Ok(EbpfProgram {
        id: program_id.clone(),
        name: "AVC Monitor".to_string(),
        program_type: ProgramType::AvcMonitor,
    })
}

/// Unload an eBPF program
pub async fn unload_program(session: &SshSession, program_id: &str) -> Result<()> {
    info!("Unloading program {} on {}", program_id, session.host());

    let rm_cmd = format!("rm -f /sys/fs/bpf/{}", program_id);
    session.execute_sudo(&rm_cmd).await?;

    Ok(())
}

/// List loaded eBPF programs
pub async fn list_programs(session: &SshSession) -> Result<Vec<String>> {
    info!("Listing eBPF programs on {}", session.host());

    let output = session.execute("ls /sys/fs/bpf/ 2>/dev/null || echo ''").await?;

    let programs: Vec<String> = output
        .lines()
        .filter(|line| !line.is_empty())
        .map(|s| s.to_string())
        .collect();

    Ok(programs)
}

/// Generate simple AVC monitor source
fn generate_avc_monitor_source() -> &'static str {
    r#"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/avc_audit_post_callback")
int trace_avc(struct pt_regs *ctx) {
    char msg[] = "AVC event detected";
    bpf_ringbuf_output(&events, msg, sizeof(msg), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
"#
}

use uuid;