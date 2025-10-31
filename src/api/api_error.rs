use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde_json::json;
use thiserror::Error;
use tracing::error;
use crate::api::api_models::ErrorResponse;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Connection not found: {0}")]
    ConnectionNotFound(String),

    #[error("SSH error: {0}")]
    SshError(#[from] crate::ssh::ssh::SshError),

    #[error("SELinux error: {0}")]
    SelinuxError(#[from] crate::selinux::selinux::SelinuxError),

    #[error("eBPF error: {0}")]
    EbpfError(#[from] crate::ebpf::ebpf::EbpfError),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Authorization failed")]
    AuthorizationFailed,

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Service unavailable")]
    ServiceUnavailable,

    #[error("Timeout")]
    Timeout,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),
}

impl ApiError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::ConnectionNotFound(_) => StatusCode::NOT_FOUND,
            Self::ValidationError(_) | Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::AuthenticationFailed => StatusCode::UNAUTHORIZED,
            Self::AuthorizationFailed => StatusCode::FORBIDDEN,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Timeout => StatusCode::REQUEST_TIMEOUT,
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::SshError(_) | Self::SelinuxError(_) | Self::EbpfError(_) => {
                StatusCode::BAD_GATEWAY
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_type(&self) -> &str {
        match self {
            Self::ConnectionNotFound(_) => "connection_not_found",
            Self::SshError(_) => "ssh_error",
            Self::SelinuxError(_) => "selinux_error",
            Self::EbpfError(_) => "ebpf_error",
            Self::ValidationError(_) => "validation_error",
            Self::AuthenticationFailed => "authentication_failed",
            Self::AuthorizationFailed => "authorization_failed",
            Self::BadRequest(_) => "bad_request",
            Self::InternalError(_) => "internal_error",
            Self::ServiceUnavailable => "service_unavailable",
            Self::Timeout => "timeout",
            Self::RateLimitExceeded => "rate_limit_exceeded",
            Self::Conflict(_) => "conflict",
            Self::AnyhowError(_) => "internal_error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let request_id = uuid::Uuid::new_v4().to_string();

        // Log the error
        match status {
            StatusCode::INTERNAL_SERVER_ERROR | StatusCode::BAD_GATEWAY => {
                error!(
                    request_id = %request_id,
                    error = %self,
                    "API error occurred"
                );
            }
            _ => {
                tracing::debug!(
                    request_id = %request_id,
                    error = %self,
                    "API error occurred"
                );
            }
        }

        let error_response = ErrorResponse {
            error: self.error_type().to_string(),
            message: self.to_string(),
            details: None,
            request_id,
        };

        (status, Json(error_response)).into_response()
    }
}

// Helper function for validation errors from the validator crate
impl From<validator::ValidationErrors> for ApiError {
    fn from(err: validator::ValidationErrors) -> Self {
        let messages: Vec<String> = err
            .field_errors()
            .into_iter()
            .map(|(field, errors)| {
                let error_messages: Vec<String> = errors
                    .iter()
                    .map(|e| e.message.as_ref()
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| e.code.to_string()))
                    .collect();
                format!("{}: {}", field, error_messages.join(", "))
            })
            .collect();

        ApiError::ValidationError(messages.join("; "))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

// Middleware for catching panics and converting them to errors
pub async fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let details = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic".to_string()
    };

    error!("Panic occurred: {}", details);

    let error_response = ErrorResponse {
        error: "internal_error".to_string(),
        message: "An internal error occurred".to_string(),
        details: Some(json!({ "panic": details })),
        request_id: uuid::Uuid::new_v4().to_string(),
    };

    (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
}