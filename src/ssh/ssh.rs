use async_ssh2_tokio::client::{Client, AuthMethod, ServerCheckMethod};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Error, Debug)]
pub enum SshError {
    #[error("Connection failed: {0}")]
    ConnectionError(String),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Command execution failed: {0}")]
    CommandError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SshError>;

/// SSH connection manager
pub struct SshManager {
    // We can add connection pooling later if needed
}

impl SshManager {
    pub fn new() -> Self {
        Self {}
    }

    /// Connect to a host with password authentication
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<SshSession> {
        info!("Connecting to {}:{} as {}", host, port, username);

        let addr = format!("{}:{}", host, port);
        let client = Client::connect(
            addr.parse().map_err(|e| SshError::ConnectionError(format!("Invalid address: {}", e)))?,
            username,
            AuthMethod::Password(password.to_string()),
            ServerCheckMethod::NoCheck, //TODO: use known host list
        )
            .await
            .map_err(|e| SshError::ConnectionError(format!("Failed to connect: {}", e)))?;

        Ok(SshSession {
            client: Arc::new(client),
            host: host.to_string(),
            username: username.to_string(),
        })
    }

    /// Connect with SSH key authentication
    pub async fn connect_with_key(
        &self,
        host: &str,
        port: u16,
        username: &str,
        private_key: &str,
        passphrase: Option<String>,
    ) -> Result<SshSession> {
        info!("Connecting to {}:{} as {} with key", host, port, username);

        let addr = format!("{}:{}", host, port);
        let client = Client::connect(
            addr.parse().map_err(|e| SshError::ConnectionError(format!("Invalid address: {}", e)))?,
            username,
            AuthMethod::PublicKey {
                key: private_key.to_string(),
                passphrase,
            },
            ServerCheckMethod::NoCheck, //TODO: use known host list
        )
            .await
            .map_err(|e| SshError::ConnectionError(format!("Failed to connect: {}", e)))?;

        Ok(SshSession {
            client: Arc::new(client),
            host: host.to_string(),
            username: username.to_string(),
        })
    }
}

/// An active SSH session
pub struct SshSession {
    client: Arc<Client>,
    host: String,
    username: String,
}

impl SshSession {
    /// Execute a command
    pub async fn execute(&self, command: &str) -> Result<String> {
        debug!("Executing command on {}: {}", self.host, command);

        let output = self.client
            .execute(command)
            .await
            .map_err(|e| SshError::CommandError(format!("Failed to execute command: {}", e)))?;

        if output.exit_status != 0 {
            if !output.stderr.is_empty() {
                return Err(SshError::CommandError(format!(
                    "Command failed with status {}: {}",
                    output.exit_status,
                    output.stderr
                )));
            }
        }

        Ok(output.stdout)
    }

    /// Execute a command with sudo
    pub async fn execute_sudo(&self, command: &str) -> Result<String> {
        let sudo_command = format!("sudo -n {}", command);
        self.execute(&sudo_command).await
    }

    /// Test the connection
    pub async fn test_connection(&self) -> Result<bool> {
        match self.execute("echo 'test'").await {
            Ok(output) => Ok(output.trim() == "test"),
            Err(_) => Ok(false),
        }
    }

    /// Get host info
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get username
    pub fn username(&self) -> &str {
        &self.username
    }
}