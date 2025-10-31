use serde::{Deserialize, Serialize};
use crate::selinux::selinux::SelinuxStatus;
use crate::ebpf::ebpf::{EbpfProgram, ProgramType};
use chrono::{DateTime, Utc};

// ========== Connection Models ==========

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRequest {
    #[validate(length(min = 1, max = 255))]
    pub host: String,
    #[validate(range(min = 1, max = 65535))]
    pub port: u16,
    #[validate(length(min = 1, max = 100))]
    pub username: String,
    pub auth: AuthMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthMethod {
    Password { password: String },
    PrivateKey {
        key: String,
        passphrase: Option<String>
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub alias: Option<String>,
    pub tags: Vec<String>,
    pub status: ConnectionStatus,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Error(String),
}

// ========== SELinux Models ==========

#[derive(Debug, Serialize, Deserialize)]
pub struct SelinuxStatusResponse {
    pub host: String,
    pub status: SelinuxStatus,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetSelinuxModeRequest {
    #[validate(custom = "validate_selinux_mode")]
    pub mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SelinuxBoolean {
    pub name: String,
    pub value: bool,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SelinuxBooleansResponse {
    pub host: String,
    pub booleans: Vec<SelinuxBoolean>,
    pub total: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetBooleanRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub value: bool,
    #[serde(default)]
    pub persistent: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AvcDenial {
    pub timestamp: Option<DateTime<Utc>>,
    pub raw: String,
    pub parsed: Option<ParsedAvcDenial>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParsedAvcDenial {
    pub source_context: String,
    pub target_context: String,
    pub class: String,
    pub permission: String,
    pub pid: Option<u32>,
    pub comm: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AvcDenialsResponse {
    pub host: String,
    pub denials: Vec<AvcDenial>,
    pub total: usize,
    pub time_range_minutes: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetContextRequest {
    #[validate(length(min = 1, max = 4096))]
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContextResponse {
    pub path: String,
    pub context: String,
    pub user: String,
    pub role: String,
    pub type_: String,
    pub level: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RestoreContextRequest {
    #[validate(length(min = 1, max = 4096))]
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
}

// ========== eBPF Models ==========

#[derive(Debug, Serialize, Deserialize)]
pub struct EbpfSupportResponse {
    pub supported: bool,
    pub kernel_version: String,
    pub has_bpftool: bool,
    pub has_clang: bool,
    pub bpf_fs_mounted: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoadProgramRequest {
    pub program_type: ProgramType,
    pub name: Option<String>,
    pub custom_source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramResponse {
    pub program: EbpfProgram,
    pub loaded_at: DateTime<Utc>,
    pub host: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramListResponse {
    pub host: String,
    pub programs: Vec<String>,
    pub total: usize,
}

// ========== Batch Operations ==========

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchOperationRequest {
    #[validate(length(min = 1, max = 100))]
    pub connection_ids: Vec<String>,
    pub operation: BatchOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BatchOperation {
    GetSelinuxStatus,
    SetSelinuxMode { mode: String },
    GetAvcDenials { minutes: u32 },
    RestoreContext { path: String, recursive: bool },
    ExecuteCommand { command: String, use_sudo: bool },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchOperationResponse {
    pub operation_id: String,
    pub results: Vec<BatchResult>,
    pub summary: BatchSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchResult {
    pub connection_id: String,
    pub host: String,
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchSummary {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub total_duration_ms: u64,
}

// ========== Command Execution ==========

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteCommandRequest {
    #[validate(length(min = 1, max = 10000))]
    pub command: String,
    #[serde(default)]
    pub use_sudo: bool,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    30
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
}

// ========== Health & Monitoring ==========

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub version: String,
    pub uptime_seconds: u64,
    pub active_connections: usize,
    pub total_requests: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

// ========== Error Response ==========

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub request_id: String,
}

// ========== Validation Functions ==========

fn validate_selinux_mode(mode: &str) -> Result<(), validator::ValidationError> {
    match mode.to_lowercase().as_str() {
        "enforcing" | "permissive" => Ok(()),
        _ => {
            let mut error = validator::ValidationError::new("invalid_mode");
            error.message = Some("Mode must be 'enforcing' or 'permissive'".into());
            Err(error)
        }
    }
}

// ========== Pagination ==========

#[derive(Debug, Serialize, Deserialize)]
pub struct PaginationParams {
    #[validate(range(min = 1, max = 100))]
    #[serde(default = "default_page_size")]
    pub page_size: usize,
    #[validate(range(min = 1))]
    #[serde(default = "default_page")]
    pub page: usize,
}

fn default_page_size() -> usize {
    20
}

fn default_page() -> usize {
    1
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, total: usize, page: usize, page_size: usize) -> Self {
        let total_pages = (total + page_size - 1) / page_size;
        Self {
            items,
            total,
            page,
            page_size,
            total_pages,
        }
    }
}