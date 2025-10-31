use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};
use crate::ssh::ssh::SshSession;

#[derive(Error, Debug)]
pub enum SelinuxError {
    #[error("SELinux not installed")]
    NotInstalled,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("SSH error: {0}")]
    SshError(#[from] crate::ssh::ssh::SshError),
}

pub type Result<T> = std::result::Result<T, SelinuxError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelinuxStatus {
    Enforcing,
    Permissive,
    Disabled,
    NotInstalled,
}

impl std::fmt::Display for SelinuxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelinuxStatus::Enforcing => write!(f, "Enforcing"),
            SelinuxStatus::Permissive => write!(f, "Permissive"),
            SelinuxStatus::Disabled => write!(f, "Disabled"),
            SelinuxStatus::NotInstalled => write!(f, "Not Installed"),
        }
    }
}

/// Get SELinux status
pub async fn get_status(session: &SshSession) -> Result<SelinuxStatus> {
    info!("Getting SELinux status on {}", session.host());

    // Check if SELinux is installed
    match session.execute("which getenforce").await {
        Ok(_) => {},
        Err(_) => return Ok(SelinuxStatus::NotInstalled),
    }

    // Get current status
    let output = session.execute("getenforce").await?;
    let status = output.trim().to_lowercase();

    match status.as_str() {
        "enforcing" => Ok(SelinuxStatus::Enforcing),
        "permissive" => Ok(SelinuxStatus::Permissive),
        "disabled" => Ok(SelinuxStatus::Disabled),
        _ => Err(SelinuxError::ParseError(format!("Unknown status: {}", status))),
    }
}

/// Set SELinux mode
pub async fn set_mode(session: &SshSession, mode: SelinuxStatus) -> Result<()> {
    info!("Setting SELinux mode to {} on {}", mode, session.host());

    let command = match mode {
        SelinuxStatus::Enforcing => "setenforce 1",
        SelinuxStatus::Permissive => "setenforce 0",
        _ => return Err(SelinuxError::ParseError("Cannot set to Disabled or NotInstalled".into())),
    };

    session.execute_sudo(command).await?;
    Ok(())
}

/// Get SELinux booleans
pub async fn get_booleans(session: &SshSession) -> Result<Vec<(String, bool)>> {
    info!("Getting SELinux booleans on {}", session.host());

    let output = session.execute("getsebool -a").await?;
    let mut booleans = Vec::new();

    for line in output.lines() {
        if let Some(pos) = line.find("-->") {
            let name = line[..pos].trim().to_string();
            let value = line[pos + 3..].trim() == "on";
            booleans.push((name, value));
        }
    }

    Ok(booleans)
}

/// Set SELinux boolean
pub async fn set_boolean(session: &SshSession, name: &str, value: bool) -> Result<()> {
    info!("Setting SELinux boolean {} to {} on {}", name, value, session.host());

    let value_str = if value { "on" } else { "off" };
    let command = format!("setsebool {} {}", name, value_str);

    session.execute_sudo(&command).await?;
    Ok(())
}

/// Get recent AVC denials
pub async fn get_recent_denials(session: &SshSession, minutes: u32) -> Result<Vec<String>> {
    info!("Getting recent AVC denials from last {} minutes on {}", minutes, session.host());

    let command = format!("ausearch -m AVC -ts -{} 2>/dev/null || true", minutes);
    let output = session.execute_sudo(&command).await?;

    let denials: Vec<String> = output
        .lines()
        .filter(|line| line.contains("type=AVC"))
        .map(|s| s.to_string())
        .collect();

    Ok(denials)
}

/// Get SELinux contexts for a path
pub async fn get_context(session: &SshSession, path: &str) -> Result<String> {
    debug!("Getting context for {} on {}", path, session.host());

    let command = format!("ls -Z {}", path);
    let output = session.execute(&command).await?;

    // Parse the context from ls -Z output
    let parts: Vec<&str> = output.split_whitespace().collect();
    if !parts.is_empty() {
        Ok(parts[0].to_string())
    } else {
        Err(SelinuxError::ParseError("Failed to parse context".into()))
    }
}

/// Restore file contexts
pub async fn restore_context(session: &SshSession, path: &str, recursive: bool) -> Result<()> {
    info!("Restoring context for {} on {}", path, session.host());

    let flags = if recursive { "-R" } else { "" };
    let command = format!("restorecon {} {}", flags, path);

    session.execute_sudo(&command).await?;
    Ok(())
}