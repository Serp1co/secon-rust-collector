use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, anyhow};
use chrono::Utc;
use tracing::{info, warn, error};
use crate::api::api_models::{AuthMethod, ConnectionInfo, ConnectionStatus};
use crate::ssh::ssh::{SshManager, SshSession};

pub type ConnectionId = String;

/// Connection metadata
#[derive(Clone)]
struct ConnectionMetadata {
    info: ConnectionInfo,
    session: Option<Arc<SshSession>>,
    auth: AuthMethod,
}

/// Manages multiple SSH connections
pub struct ConnectionManager {
    connections: Arc<RwLock<HashMap<ConnectionId, ConnectionMetadata>>>,
    ssh_manager: Arc<SshManager>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            ssh_manager: Arc::new(SshManager::new()),
        }
    }

    /// Add a new connection
    pub async fn add_connection(
        &self,
        host: &str,
        port: u16,
        username: &str,
        auth: AuthMethod,
        alias: Option<String>,
        tags: Vec<String>,
    ) -> Result<ConnectionId> {
        let id = uuid::Uuid::new_v4().to_string();

        // Try to establish the connection
        let session = match &auth {
            AuthMethod::Password { password } => {
                self.ssh_manager
                    .connect_with_uname_password(host, port, username, password)
                    .await?
            }
            AuthMethod::PublicKey { key_path } => {
                self.ssh_manager
                    .connect_with_public_key(host, port, username, key_path)
                    .await?
            }
            _ => {panic!("Method {:?} is not supported", auth);}
        };

        // Test the connection
        if !session.test_connection().await? {
            return Err(anyhow!("Connection test failed"));
        }

        let info = ConnectionInfo {
            id: id.clone(),
            host: host.to_string(),
            port,
            username: username.to_string(),
            alias,
            tags,
            status: ConnectionStatus::Connected,
            created_at: Utc::now(),
            last_used: Some(Utc::now()),
        };

        let metadata = ConnectionMetadata {
            info,
            session: Some(Arc::new(session)),
            auth,
        };

        let mut connections = self.connections.write().await;
        connections.insert(id.clone(), metadata);

        info!("Added connection {} to {}@{}", id, username, host);
        Ok(id)
    }

    /// Get a connection session
    pub async fn get_session(&self, connection_id: &str) -> Result<Arc<SshSession>> {
        let mut connections = self.connections.write().await;

        let metadata = connections
            .get_mut(connection_id)
            .ok_or_else(|| anyhow!("Connection {} not found", connection_id))?;

        // Update last used time
        metadata.info.last_used = Some(Utc::now());

        // Check if we have an active session
        if let Some(session) = &metadata.session {
            // Test if it's still alive
            if session.test_connection().await.unwrap_or(false) {
                return Ok(Arc::clone(session));
            }
            warn!("Connection {} is dead, attempting to reconnect", connection_id);
        }

        // Need to reconnect
        let new_session = match &metadata.auth {
            AuthMethod::Password { password } => {
                self.ssh_manager
                    .connect_with_uname_password(&metadata.info.host, metadata.info.port, &metadata.info.username, password)
                    .await?
            }
            AuthMethod::PublicKey { key_path} => {
                self.ssh_manager
                    .connect_with_public_key(
                        &metadata.info.host,
                        metadata.info.port,
                        &metadata.info.username,
                        key_path,
                    )
                    .await?
            }
            _ => {panic!("Method {:?} is not supported", metadata.auth);}
        };

        let session = Arc::new(new_session);
        metadata.session = Some(Arc::clone(&session));
        metadata.info.status = ConnectionStatus::Connected;

        info!("Reconnected to {}", connection_id);
        Ok(session)
    }

    /// Remove a connection
    pub async fn remove_connection(&self, connection_id: &str) -> Result<()> {
        let mut connections = self.connections.write().await;
        connections
            .remove(connection_id)
            .ok_or_else(|| anyhow!("Connection {} not found", connection_id))?;

        info!("Removed connection {}", connection_id);
        Ok(())
    }

    /// List all connections
    pub async fn list_connections(&self) -> Vec<ConnectionInfo> {
        let connections = self.connections.read().await;
        connections
            .values()
            .map(|m| m.info.clone())
            .collect()
    }

    /// Get connection info
    pub async fn get_connection_info(&self, connection_id: &str) -> Result<ConnectionInfo> {
        let connections = self.connections.read().await;
        connections
            .get(connection_id)
            .map(|m| m.info.clone())
            .ok_or_else(|| anyhow!("Connection {} not found", connection_id))
    }

    /// Test a connection
    pub async fn test_connection(&self, connection_id: &str) -> Result<bool> {
        let session = self.get_session(connection_id).await?;
        Ok(session.test_connection().await?)
    }

    /// Update connection status
    pub async fn update_status(&self, connection_id: &str, status: ConnectionStatus) -> Result<()> {
        let mut connections = self.connections.write().await;
        let metadata = connections
            .get_mut(connection_id)
            .ok_or_else(|| anyhow!("Connection {} not found", connection_id))?;

        metadata.info.status = status;
        Ok(())
    }

    /// Get connections by tag
    pub async fn get_connections_by_tag(&self, tag: &str) -> Vec<ConnectionInfo> {
        let connections = self.connections.read().await;
        connections
            .values()
            .filter(|m| m.info.tags.contains(&tag.to_string()))
            .map(|m| m.info.clone())
            .collect()
    }

    /// Get active connection count
    pub async fn active_connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections
            .values()
            .filter(|m| matches!(m.info.status, ConnectionStatus::Connected))
            .count()
    }

    /// Reconnect all disconnected connections
    pub async fn reconnect_all(&self) -> HashMap<ConnectionId, Result<()>> {
        let mut results = HashMap::new();
        let connection_ids: Vec<ConnectionId> = {
            let connections = self.connections.read().await;
            connections
                .iter()
                .filter(|(_, m)| !matches!(m.info.status, ConnectionStatus::Connected))
                .map(|(id, _)| id.clone())
                .collect()
        };

        for id in connection_ids {
            let result = self.get_session(&id).await.map(|_| ());
            results.insert(id, result);
        }

        results
    }

    /// Execute command on multiple connections
    pub async fn execute_on_multiple(
        &self,
        connection_ids: &[String],
        command: &str,
        use_sudo: bool,
    ) -> HashMap<ConnectionId, Result<String>> {
        let mut results = HashMap::new();

        for id in connection_ids {
            let result = async {
                let session = self.get_session(id).await?;
                if use_sudo {
                    session.execute_sudo(command).await.map_err(Into::into)
                } else {
                    session.execute(command).await.map_err(Into::into)
                }
            }.await;

            results.insert(id.clone(), result);
        }

        results
    }

    /// Health check all connections
    pub async fn health_check_all(&self) -> HashMap<ConnectionId, bool> {
        let mut results = HashMap::new();
        let connection_ids: Vec<ConnectionId> = {
            let connections = self.connections.read().await;
            connections.keys().cloned().collect()
        };

        for id in connection_ids {
            let is_healthy = self.test_connection(&id).await.unwrap_or(false);

            // Update status based on health
            let status = if is_healthy {
                ConnectionStatus::Connected
            } else {
                ConnectionStatus::Error("Health check failed".to_string())
            };

            let _ = self.update_status(&id, status).await;
            results.insert(id, is_healthy);
        }

        results
    }
}

impl Clone for ConnectionManager {
    fn clone(&self) -> Self {
        Self {
            connections: Arc::clone(&self.connections),
            ssh_manager: Arc::clone(&self.ssh_manager),
        }
    }
}