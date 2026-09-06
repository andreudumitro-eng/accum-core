//! Configuration management for ACCUM node

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    pub network: NetworkConfig,
    pub mining: MiningConfig,
    pub storage: StorageConfig,
    pub logging: LoggingConfig,
    pub rpc: RpcConfig, 
}

/// Node settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub data_dir: String,
}

/// Network settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub port: u16,
    pub bootnodes: Vec<String>,
    pub max_peers: usize,
}

/// Mining settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningConfig {
    pub enabled: bool,
    pub threads: usize,
    pub address: Option<String>,
    pub bond: u64,
}

/// Storage settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub cache_size_mb: usize,
}

/// Logging settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
}

/// RPC settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    pub enabled: bool,
    pub port: u16,
    pub host: String,
}

impl Config {
    /// Load config from file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
    
    /// Create default config
    pub fn default() -> Self {
        Self {
            node: NodeConfig {
                name: "accum-node".to_string(),
                data_dir: "./data".to_string(),
            },
            network: NetworkConfig {
                port: 30333,
                bootnodes: vec![],
                max_peers: 50,
            },
            mining: MiningConfig {
                enabled: true,
                threads: 2,
                address: None,
                bond: 10_000_000,
            },
            storage: StorageConfig {
                cache_size_mb: 256,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
            },
            rpc: RpcConfig {
                enabled: true,
                port: 8545,
                host: "0.0.0.0".to_string(),
            },
        }
    }
    
    /// Save default config to file
    pub fn save_default<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn std::error::Error>> {
        let config = Self::default();
        let toml = toml::to_string_pretty(&config)?;
        fs::write(path, toml)?;
        Ok(())
    }  
}