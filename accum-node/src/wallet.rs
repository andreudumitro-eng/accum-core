// ============================================================
// WALLET - Хранение и управление кошельком
// ============================================================

use crate::types::{MinerId, Timestamp};
use crate::storage::ProductionStorage;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use dirs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub miner_id: MinerId,
    pub address: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WalletFile {
    pub address: String,
    pub miner_id: String,
    pub private_key: String,
    pub public_key: String,
    pub created_at: Timestamp,
}

impl Wallet {
    pub fn load_or_create(storage: &ProductionStorage) -> Result<Self, String> {
        let wallet_path = dirs::home_dir()
            .ok_or("Cannot find home dir")?
            .join(".accum")
            .join("wallet.json");
        
        // 1. Пытаемся загрузить из файла
        if wallet_path.exists() {
            println!("🔑 Loading wallet from {}", wallet_path.display());
            let content = fs::read_to_string(&wallet_path)
                .map_err(|e| format!("Failed to read wallet: {}", e))?;
            let wallet_data: WalletFile = serde_json::from_str(&content)
                .map_err(|e| format!("Invalid wallet file: {}", e))?;
            
            let secret_key = hex::decode(&wallet_data.private_key)
                .map_err(|_| "Invalid private key format")?;
            
            let wallet = Wallet::from_secret_key(&secret_key)?;
            
            if wallet.address != wallet_data.address {
                return Err("Wallet address mismatch!".to_string());
            }
            
            println!("✅ Wallet loaded: {}", wallet.address);
            return Ok(wallet);
        }
        
        // 2. Пытаемся загрузить из базы
        if let Some(wallet_data) = storage.get_state::<Vec<u8>>("wallet")? {
            println!("🔑 Loading wallet from database...");
            let secret_key: [u8; 32] = wallet_data.try_into()
                .map_err(|_| "Invalid wallet data")?;
            let wallet = Wallet::from_secret_key(&secret_key)?;
            wallet.save_to_file()?;
            return Ok(wallet);
        }
        
        // 3. Создаем новый кошелек
        println!("🆕 No wallet found, creating new wallet...");
        let wallet = Wallet::generate()?;
        wallet.save_to_file()?;
        
        let _ = storage.save_state("wallet", &wallet.secret_key.to_vec());
        
        println!("✅ New wallet created!");
        println!("📫 Address: {}", wallet.address);
        println!("🆔 Miner ID: {}", hex::encode(&wallet.miner_id));
        println!("📜 Private Key: {}", hex::encode(&wallet.secret_key));
        println!("⚠️  BACKUP YOUR WALLET FILE: ~/.accum/wallet.json");
        
        Ok(wallet)
    }
    
    pub fn save_to_file(&self) -> Result<(), String> {
        let wallet_path = dirs::home_dir()
            .ok_or("Cannot find home dir")?
            .join(".accum")
            .join("wallet.json");
        
        let wallet_file = WalletFile {
            address: self.address.clone(),
            miner_id: hex::encode(&self.miner_id),
            private_key: hex::encode(&self.secret_key),
            public_key: hex::encode(&self.public_key),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let content = serde_json::to_string_pretty(&wallet_file)
            .map_err(|e| format!("Failed to serialize wallet: {}", e))?;
        
        fs::create_dir_all(wallet_path.parent().unwrap())
            .map_err(|e| format!("Failed to create .accum directory: {}", e))?;
        
        fs::write(&wallet_path, content)
            .map_err(|e| format!("Failed to save wallet: {}", e))?;
        
        Ok(())
    }
}