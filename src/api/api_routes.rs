use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post, delete, put},
    Json, Router,
};
use std::sync::Arc;
use std::time::Instant;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use validator::Validate;

use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::api::{api_error::{ApiError, ApiResult}, api_models::*, api_connection_manager::ConnectionManager, api_models};
use crate::ebpf::ebpf;
use crate::selinux::selinux;

pub struct AppState {
    pub connection_manager: ConnectionManager,
    pub start_time: Instant,
    pub request_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            connection_manager: ConnectionManager::new(),
            start_time: Instant::now(),
            request_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
}


#[derive(OpenApi)]
#[openapi(
    paths(
        health_check,
        create_connection,
        list_connections,
        get_connection,
        delete_connection,
        test_connection,
        get_selinux_status,
        set_selinux_mode,
        get_selinux_booleans,
        set_selinux_boolean,
        get_avc_denials,
        get_context,
        restore_context,
        check_ebpf_support,
        list_ebpf_programs,
        load_ebpf_program,
        unload_ebpf_program,
        execute_command,
        batch_operation
    ),
    tags(
        (name = "health", description = "Service health"),
        (name = "connections", description = "Manage SSH connections"),
        (name = "selinux", description = "SELinux operations"),
        (name = "ebpf", description = "eBPF operations"),
        (name = "batch", description = "Batch operations")
    )
)]
struct ApiDoc;


pub fn create_router() -> Router {
    let state = Arc::new(AppState::new());

    Router::new()
        .merge(
            SwaggerUi::new("/swagger-ui")
                .url("/api-docs/openapi.json", ApiDoc::openapi())
        )
        // Health check
        .route("/health", get(health_check))

        // Connection management
        .route("/connections", post(create_connection))
        .route("/connections", get(list_connections))
        .route("/connections/{id}", get(get_connection))
        .route("/connections/{id}", delete(delete_connection))
        .route("/connections/{id}/test", post(test_connection))

        // SELinux operations
        .route("/connections/{id}/selinux/status", get(get_selinux_status))
        .route("/connections/{id}/selinux/mode", put(set_selinux_mode))
        .route("/connections/{id}/selinux/booleans", get(get_selinux_booleans))
        .route("/connections/{id}/selinux/booleans", put(set_selinux_boolean))
        .route("/connections/{id}/selinux/denials", get(get_avc_denials))
        .route("/connections/{id}/selinux/context", get(get_context))
        .route("/connections/{id}/selinux/restore", post(restore_context))

        // eBPF operations
        .route("/connections/{id}/ebpf/support", get(check_ebpf_support))
        .route("/connections/{id}/ebpf/programs", get(list_ebpf_programs))
        .route("/connections/{id}/ebpf/programs", post(load_ebpf_program))
        .route("/connections/{id}/ebpf/programs/{program_id}", delete(unload_ebpf_program))

        // Command execution
        .route("/connections/{id}/execute", post(execute_command))

        // Batch operations
        .route("/batch", post(batch_operation))

        // Add middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                ),
        )
        .with_state(state)
}

// ========== Health Check ==========

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, body = HealthResponse)
    ),
    tag = "health"
)]
async fn health_check(State(state): State<Arc<AppState>>) -> ApiResult<Json<HealthResponse>> {
    let uptime = state.start_time.elapsed().as_secs();
    let requests = state.request_counter.load(std::sync::atomic::Ordering::Relaxed);
    let active_connections = state.connection_manager.active_connection_count().await;

    Ok(Json(HealthResponse {
        status: HealthStatus::Healthy,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        active_connections,
        total_requests: requests,
    }))
}

// ========== Connection Management ==========

#[utoipa::path(
    post,
    path = "/connections",
    request_body = ConnectionRequest,
    responses(
        (status = 201, body = ConnectionInfo),
        (status = 422, body = ErrorResponse)
    ),
    tag = "connections"
)]
async fn create_connection(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectionRequest>,
) -> ApiResult<(StatusCode, Json<ConnectionInfo>)> {
    req.validate()?;

    let id = state
        .connection_manager
        .add_connection(
            &req.host,
            req.port,
            &req.username,
            req.auth,
            req.alias,
            req.tags,
        )
        .await?;

    let info = state.connection_manager.get_connection_info(&id).await?;

    Ok((StatusCode::CREATED, Json(info)))
}

#[utoipa::path(
    get,
    path = "/connections",
    params(
        ("page" = usize, Query, description = "Page number", example = 1),
        ("page_size" = usize, Query, description = "Items per page", example = 20)
    ),
    responses(
        (status = 200, body = PaginatedResponse<ConnectionInfo>)
    ),
    tag = "connections"
)]
async fn list_connections(
    State(state): State<Arc<AppState>>,
    Query(mut pagination): Query<PaginationParams>,
) -> ApiResult<Json<PaginatedResponse<ConnectionInfo>>> {
    pagination.validate()?;

    let connections = state.connection_manager.list_connections().await;
    let total = connections.len();

    let start = (pagination.page - 1) * pagination.page_size;
    let end = (start + pagination.page_size).min(total);
    let items = connections[start..end].to_vec();

    Ok(Json(PaginatedResponse::new(
        items,
        total,
        pagination.page,
        pagination.page_size,
    )))
}

#[utoipa::path(
    get,
    path = "/connections/{id}",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    responses(
        (status = 200, body = ConnectionInfo),
        (status = 404, body = ErrorResponse)
    ),
    tag = "connections"
)]
async fn get_connection(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<ConnectionInfo>> {
    let info = state
        .connection_manager
        .get_connection_info(&id)
        .await
        .map_err(|_| ApiError::ConnectionNotFound(id))?;

    Ok(Json(info))
}

#[utoipa::path(
    delete,
    path = "/connections/{id}",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, body = ErrorResponse)
    ),
    tag = "connections"
)]
async fn delete_connection(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    state
        .connection_manager
        .remove_connection(&id)
        .await
        .map_err(|_| ApiError::ConnectionNotFound(id))?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/connections/{id}/test",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    responses(
        (status = 200, description = "Connection test result")
    ),
    tag = "connections"
)]
async fn test_connection(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let result = state
        .connection_manager
        .test_connection(&id)
        .await
        .map_err(|_| ApiError::ConnectionNotFound(id.clone()))?;

    Ok(Json(serde_json::json!({
        "connection_id": id,
        "connected": result,
        "timestamp": chrono::Utc::now()
    })))
}

// ========== SELinux Operations ==========

#[utoipa::path(
    get,
    path = "/connections/{id}/selinux/status",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    responses(
        (status = 200, body = SelinuxStatusResponse),
        (status = 404, body = ErrorResponse)
    ),
    tag = "selinux"
)]
async fn get_selinux_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<SelinuxStatusResponse>> {
    let session = state.connection_manager.get_session(&id).await?;
    let status = selinux::get_status(&*session).await?;

    Ok(Json(SelinuxStatusResponse {
        host: session.host().to_string(),
        status,
        timestamp: chrono::Utc::now(),
    }))
}

#[utoipa::path(
    put,
    path = "/connections/{id}/selinux/mode",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    request_body = SetSelinuxModeRequest,
    responses(
        (status = 200, body = SelinuxStatusResponse)
    ),
    tag = "selinux"
)]
async fn set_selinux_mode(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(mut req): Json<SetSelinuxModeRequest>,
) -> ApiResult<StatusCode> {
    req.validate()?;

    let session = state.connection_manager.get_session(&id).await?;
    let mode = match req.mode.to_lowercase().as_str() {
        "enforcing" => selinux::SelinuxStatus::Enforcing,
        "permissive" => selinux::SelinuxStatus::Permissive,
        _ => return Err(ApiError::ValidationError("Invalid mode".to_string())),
    };

    selinux::set_mode(&*session, mode).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/connections/{id}/selinux/booleans",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    responses(
        (status = 200, body = SelinuxBooleansResponse)
    ),
    tag = "selinux"
)]
async fn get_selinux_booleans(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<SelinuxBooleansResponse>> {
    let session = state.connection_manager.get_session(&id).await?;
    let booleans = selinux::get_booleans(&*session).await?;

    let response_booleans: Vec<SelinuxBoolean> = booleans
        .into_iter()
        .map(|(name, value)| SelinuxBoolean {
            name,
            value,
            description: None,
        })
        .collect();

    let total = response_booleans.len();

    Ok(Json(SelinuxBooleansResponse {
        host: session.host().to_string(),
        booleans: response_booleans,
        total,
    }))
}

#[utoipa::path(
    put,
    path = "/connections/{id}/selinux/booleans",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    request_body = SetBooleanRequest,
    responses(
        (status = 200, body = SelinuxBooleansResponse)
    ),
    tag = "selinux"
)]
async fn set_selinux_boolean(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(mut req): Json<SetBooleanRequest>,
) -> ApiResult<StatusCode> {
    req.validate()?;

    let session = state.connection_manager.get_session(&id).await?;
    selinux::set_boolean(&*session, &req.name, req.value).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/connections/{id}/selinux/denials",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    responses(
        (status = 200, body = AvcDenialsResponse)
    ),
    tag = "selinux"
)]
async fn get_avc_denials(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<serde_json::Value>,
) -> ApiResult<Json<AvcDenialsResponse>> {
    let minutes = params
        .get("minutes")
        .and_then(|v| v.as_u64())
        .unwrap_or(10) as u32;

    let session = state.connection_manager.get_session(&id).await?;
    let denials = selinux::get_recent_denials(&*session, minutes).await?;

    let avc_denials: Vec<AvcDenial> = denials
        .into_iter()
        .map(|raw| AvcDenial {
            timestamp: None,
            raw,
            parsed: None,
        })
        .collect();

    let total = avc_denials.len();

    Ok(Json(AvcDenialsResponse {
        host: session.host().to_string(),
        denials: avc_denials,
        total,
        time_range_minutes: minutes,
    }))
}

#[utoipa::path(
    get,
    path = "/connections/{id}/selinux/context",
    params(
        ("id" = String, Path, description = "Connection id"),
        ("path" = String, Query, description = "Path to check context")
    ),
    responses(
        (status = 200, body = ContextResponse)
    ),
    tag = "selinux"
)]
async fn get_context(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(mut req): Json<GetContextRequest>,
) -> ApiResult<Json<ContextResponse>> {
    req.validate()?;

    let session = state.connection_manager.get_session(&id).await?;
    let context = selinux::get_context(&*session, &req.path).await?;

    // Parse the context (simplified parsing)
    let parts: Vec<&str> = context.split(':').collect();

    Ok(Json(ContextResponse {
        path: req.path,
        context: context.clone(),
        user: parts.get(0).unwrap_or(&"").to_string(),
        role: parts.get(1).unwrap_or(&"").to_string(),
        type_: parts.get(2).unwrap_or(&"").to_string(),
        level: parts.get(3).map(|s| s.to_string()),
    }))
}

#[utoipa::path(
    post,
    path = "/connections/{id}/selinux/restore",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    request_body = RestoreContextRequest,
    responses(
        (status = 200, body = ContextResponse)
    ),
    tag = "selinux"
)]
async fn restore_context(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(mut req): Json<RestoreContextRequest>,
) -> ApiResult<StatusCode> {
    req.validate()?;

    let session = state.connection_manager.get_session(&id).await?;
    selinux::restore_context(&*session, &req.path, req.recursive).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ========== eBPF Operations ==========

#[utoipa::path(
    get,
    path = "/connections/{id}/ebpf/support",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    responses(
        (status = 200, body = EbpfSupportResponse)
    ),
    tag = "ebpf"
)]
async fn check_ebpf_support(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<EbpfSupportResponse>> {
    let session = state.connection_manager.get_session(&id).await?;

    let supported = ebpf::check_support(&*session).await?;
    let kernel_version = session.execute("uname -r").await.unwrap_or_default().trim().to_string();
    let has_bpftool = session.execute("which bpftool").await.is_ok();
    let has_clang = session.execute("which clang").await.is_ok();
    let bpf_fs = session.execute("ls /sys/fs/bpf 2>/dev/null").await.is_ok();

    let mut issues = Vec::new();
    if !has_bpftool {
        issues.push("bpftool not installed".to_string());
    }
    if !has_clang {
        issues.push("clang not installed".to_string());
    }
    if !bpf_fs {
        issues.push("BPF filesystem not mounted".to_string());
    }

    Ok(Json(EbpfSupportResponse {
        supported,
        kernel_version,
        has_bpftool,
        has_clang,
        bpf_fs_mounted: bpf_fs,
        issues,
    }))
}

#[utoipa::path(
    get,
    path = "/connections/{id}/ebpf/programs",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    responses(
        (status = 200, body = ProgramListResponse)
    ),
    tag = "ebpf"
)]
async fn list_ebpf_programs(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<ProgramListResponse>> {
    let session = state.connection_manager.get_session(&id).await?;
    let programs = ebpf::list_programs(&*session).await?;
    let total = programs.len();

    Ok(Json(ProgramListResponse {
        host: session.host().to_string(),
        programs,
        total,
    }))
}

#[utoipa::path(
    post,
    path = "/connections/{id}/ebpf/programs",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    request_body = LoadProgramRequest,
    responses(
        (status = 201, body = ProgramResponse)
    ),
    tag = "ebpf"
)]
async fn load_ebpf_program(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<LoadProgramRequest>,
) -> ApiResult<(StatusCode, Json<ProgramResponse>)> {
    let session = state.connection_manager.get_session(&id).await?;

    let program = match req.program_type {
        ebpf::ProgramType::AvcMonitor => {
            ebpf::load_avc_monitor(&*session).await?
        }
        _ => {
            return Err(ApiError::BadRequest("Unsupported program type".to_string()));
        }
    };

    Ok((StatusCode::CREATED, Json(ProgramResponse {
        program,
        loaded_at: chrono::Utc::now(),
        host: session.host().to_string(),
    })))
}

#[utoipa::path(
    delete,
    path = "/connections/{id}/ebpf/programs/{program_id}",
    params(
        ("id" = String, Path, description = "Connection id"),
        ("program_id" = String, Path, description = "Program identifier")
    ),
    responses(
        (status = 204, description = "Unloaded")
    ),
    tag = "ebpf"
)]
async fn unload_ebpf_program(
    State(state): State<Arc<AppState>>,
    Path((id, program_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let session = state.connection_manager.get_session(&id).await?;
    ebpf::unload_program(&*session, &program_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ========== Command Execution ==========

#[utoipa::path(
    post,
    path = "/connections/{id}/execute",
    params(
        ("id" = String, Path, description = "Connection id")
    ),
    responses(
        (status = 200, description = "Command execution result")
    ),
    tag = "connections"
)]
async fn execute_command(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(mut req): Json<ExecuteCommandRequest>,
) -> ApiResult<Json<CommandResponse>> {
    req.validate()?;

    let start = Instant::now();
    let session = state.connection_manager.get_session(&id).await?;

    let output = if req.use_sudo {
        session.execute_sudo(&req.command).await
    } else {
        session.execute(&req.command).await
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    match output {
        Ok(stdout) => Ok(Json(CommandResponse {
            stdout,
            stderr: String::new(),
            exit_code: 0,
            duration_ms,
        })),
        Err(e) => Ok(Json(CommandResponse {
            stdout: String::new(),
            stderr: e.to_string(),
            exit_code: 1,
            duration_ms,
        })),
    }
}

// ========== Batch Operations ==========

#[utoipa::path(
    post,
    path = "/batch",
    request_body = BatchOperationRequest,
    responses(
        (status = 200, body = BatchOperationResponse)
    ),
    tag = "batch"
)]
async fn batch_operation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(mut req): Json<BatchOperationRequest>,
) -> ApiResult<Json<BatchOperationResponse>> {
    req.validate()?;

    let operation_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();
    let mut results = Vec::new();

    for conn_id in &req.connection_ids {
        let result_start = Instant::now();

        let result = match &req.operation {
            BatchOperation::GetSelinuxStatus => {
                execute_batch_selinux_status(&state, conn_id).await
            }
            BatchOperation::ExecuteCommand { command, use_sudo } => {
                execute_batch_command(&state, conn_id, command, *use_sudo).await
            }
            _ => BatchResult {
                connection_id: conn_id.clone(),
                host: String::new(),
                success: false,
                data: None,
                error: Some("Operation not implemented".to_string()),
                duration_ms: 0,
            },
        };

        results.push(BatchResult {
            duration_ms: result_start.elapsed().as_millis() as u64,
            ..result
        });
    }

    let successful = results.iter().filter(|r| r.success).count();
    let failed = results.len() - successful;
    let total_duration_ms = start.elapsed().as_millis() as u64;

    Ok(Json(BatchOperationResponse {
        operation_id,
        results,
        summary: BatchSummary {
            total: req.connection_ids.len(),
            successful,
            failed,
            total_duration_ms,
        },
    }))
}

// Helper functions for batch operations
async fn execute_batch_selinux_status(
    state: &Arc<AppState>,
    conn_id: &str,
) -> BatchResult {
    match state.connection_manager.get_session(conn_id).await {
        Ok(session) => match selinux::get_status(&*session).await {
            Ok(status) => BatchResult {
                connection_id: conn_id.to_string(),
                host: session.host().to_string(),
                success: true,
                data: Some(serde_json::to_value(&status).unwrap()),
                error: None,
                duration_ms: 0,
            },
            Err(e) => BatchResult {
                connection_id: conn_id.to_string(),
                host: session.host().to_string(),
                success: false,
                data: None,
                error: Some(e.to_string()),
                duration_ms: 0,
            },
        },
        Err(e) => BatchResult {
            connection_id: conn_id.to_string(),
            host: String::new(),
            success: false,
            data: None,
            error: Some(e.to_string()),
            duration_ms: 0,
        },
    }
}

async fn execute_batch_command(
    state: &Arc<AppState>,
    conn_id: &str,
    command: &str,
    use_sudo: bool,
) -> BatchResult {
    match state.connection_manager.get_session(conn_id).await {
        Ok(session) => {
            let output = if use_sudo {
                session.execute_sudo(command).await
            } else {
                session.execute(command).await
            };

            match output {
                Ok(stdout) => BatchResult {
                    connection_id: conn_id.to_string(),
                    host: session.host().to_string(),
                    success: true,
                    data: Some(serde_json::json!({ "output": stdout })),
                    error: None,
                    duration_ms: 0,
                },
                Err(e) => BatchResult {
                    connection_id: conn_id.to_string(),
                    host: session.host().to_string(),
                    success: false,
                    data: None,
                    error: Some(e.to_string()),
                    duration_ms: 0,
                },
            }
        }
        Err(e) => BatchResult {
            connection_id: conn_id.to_string(),
            host: String::new(),
            success: false,
            data: None,
            error: Some(e.to_string()),
            duration_ms: 0,
        },
    }
}