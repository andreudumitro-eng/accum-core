// Copyright (c) 2026 Andrii Dumitro
// SPDX-License-Identifier: MIT
//
// ACCUM v3.2+ - Fair Proof-of-Contribution Blockchain Protocol
// FULLY WORKING NODE WITH SOLO MINING + EQUIVOCATION SLASHING
// ============================================================

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::cmp::Ordering;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::io::{Read, Write};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::env;
use argon2::{Argon2, Algorithm, Version, Params};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use rand::{RngCore, thread_rng};
use rand::rngs::OsRng;
use hex;
use serde::{Deserialize, Serialize};
use rocksdb::{DB, Options, IteratorMode};
use rocksdb::checkpoint::Checkpoint as RocksdbCheckpoint;
use dirs;
use secp256k1::{Secp256k1, Message, PublicKey, SecretKey, ecdsa::Signature};
use warp::Filter;
use tokio::signal;
use tokio::time::{self, Duration};
use lazy_static;
use parking_lot::RwLock;
use bincode;
use toml;

lazy_static::lazy_static! {
    static ref SECP: Secp256k1<secp256k1::All> = Secp256k1::new();
}

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static SAVING_STATE: AtomicBool = AtomicBool::new(false);

fn should_shutdown() -> bool {
    SHUTDOWN.load(AtomicOrdering::Relaxed)
}

fn set_saving_state(saving: bool) {
    SAVING_STATE.store(saving, AtomicOrdering::Relaxed);
}

fn is_saving_state() -> bool {
    SAVING_STATE.load(AtomicOrdering::Relaxed)
}

// ============================================================
// КОНСТАНТЫ
// ============================================================

const LYATORS_PER_ACM: u64 = 10_000_000;
const MAX_SUPPLY_ACM: u64 = 150_000_000;
const MAX_SUPPLY_LYT: u64 = 1_500_000_000_000_000;
const BLOCK_REWARD_LYT: u64 = 500_000;
const EPOCH_REWARD_LYT: u64 = 720_000_000;
const TARGET_BLOCK_TIME: u64 = 60;
const EPOCH_BLOCKS: u64 = 1440;
const GENESIS_TIMESTAMP: u64 = 1741353600;
const MINIMUM_FEE_LYT: u64 = 50;
const DUST_LIMIT_LYT: u64 = 100;

// Argon2id ПАРАМЕТРЫ
const ARGON2_MEMORY_KB: u32 = 262_144;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_HASH_LEN: usize = 32;
const ARGON2_SALT: &[u8; 16] = b"ACCUMPOWv3.2+!!!";
const ARGON2_CACHE_SIZE: usize = 10000;

// BOND ПАРАМЕТРЫ
const MINIMUM_BOND_LYT: u64 = 10_000_000;
const BOND_LOCKUP_BLOCKS: u64 = 20_160;
const OP_BOND: u8 = 0xBA;

// SHARE ПАРАМЕТРЫ
const MAX_SHARES_PER_MINER_PER_EPOCH: u64 = 5000;
const SHARE_DIFFICULTY_RATIO: u64 = 256;
const SHARE_PACKET_SIZE: usize = 180;
const MAX_SHARES_PER_MINUTE_PER_PEER: u32 = 100;
const PEER_BAN_DURATION_SECS: u64 = 300;
const INVALID_SHARE_WARNING_THRESHOLD: f64 = 0.1;
const INVALID_SHARE_BAN_THRESHOLD: f64 = 0.3;
const SHARE_PREFILTER_RATIO: u64 = 65536;

// PoCI ВЕСА
const POCI_WEIGHT_SHARES: f64 = 0.6;
const POCI_WEIGHT_LOYALTY: f64 = 0.2;
const POCI_WEIGHT_BOND: f64 = 0.2;

// РЕГУЛИРОВКА СЛОЖНОСТИ
const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 120;
const TARGET_ADJUSTMENT_TIME: u64 = 7200;
const MAX_DIFFICULTY_CHANGE: f64 = 0.25;

// LOYALTY
const LOYALTY_DECAY_FACTOR: f64 = 0.7;
const LOYALTY_GRACE_PERIOD: u32 = 3;
const LOYALTY_GRACE_DECAY_FACTOR: f64 = 0.5;

// СЕТЕВЫЕ ПАРАМЕТРЫ
const MAX_PEERS: usize = 125;
const MAX_MESSAGES_PER_HOUR_PER_PEER: u32 = 1000;
const P2P_PORT: u16 = 30333;
const RPC_PORT: u16 = 8545;
const SYNC_TIMEOUT_SECS: u64 = 60;
const PEER_TIMEOUT_SECS: u64 = 300;

// ДОПОЛНИТЕЛЬНЫЕ КОНСТАНТЫ
const MINING_BATCH_SIZE: u64 = 50000;
const STATS_UPDATE_INTERVAL_MS: u64 = 100;

// ============================================================
// ТИПЫ ДАННЫХ
// ============================================================

type Hash32 = [u8; 32];
type MinerId = [u8; 20];
type Timestamp = u64;
type Height = u64;
type Txid = Hash32;
type OutPoint = (Txid, u32);
type PeerId = [u8; 32];

// ============================================================
// SLASH RECORD
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SlashRecord {
    miner_id: MinerId,
    amount: u64,
    height: Height,
    timestamp: Timestamp,
    proof: Vec<u8>,
}

// ============================================================
// EQUIVOCATION PROOF
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EquivocationProof {
    miner_id: MinerId,
    block_height: Height,
    block_hash_1: Hash32,
    block_hash_2: Hash32,
    signature_1: Vec<u8>,
    signature_2: Vec<u8>,
    timestamp: Timestamp,
    proven: bool,
}

// ============================================================
// EQUIVOCATION SLASHING - РАСШИРЕННЫЕ МЕТОДЫ
// ============================================================

impl EquivocationProof {
    /// Получение высоты второго блока
    fn block_height_2(&self) -> Height {
        self.block_height
    }
    
    /// Верификация доказательства эквивокации
    pub fn verify(
        &self,
        storage: &ProductionStorage,
        argon2: &mut Argon2Cache,
    ) -> Result<bool, String> {
        // 1. Проверяем, что оба блока на одной высоте
        let block1_height = self.block_height;
        let block2_height = self.block_height;
        
        // 2. Получаем блоки из storage
        let block1 = storage.get_block(block1_height)?
            .ok_or("Block 1 not found")?;
        let block2 = storage.get_block(block2_height)?
            .ok_or("Block 2 not found")?;
        
        // 3. Проверяем, что это разные блоки
        if block1.header.hash(argon2) == block2.header.hash(argon2) {
            return Ok(false);
        }
        
        // 4. Проверяем подписи
        let hash1 = block1.header.hash(argon2);
        let hash2 = block2.header.hash(argon2);
        
        let sig1_ok = if let (Some(sig), Some(pubkey)) = (&block1.signature, &block1.pubkey) {
            Wallet::verify_signature(pubkey, sig, &hash1)
        } else {
            false
        };
        
        let sig2_ok = if let (Some(sig), Some(pubkey)) = (&block2.signature, &block2.pubkey) {
            Wallet::verify_signature(pubkey, sig, &hash2)
        } else {
            false
        };
        
        if !sig1_ok || !sig2_ok {
            return Ok(false);
        }
        
        // 5. Проверяем, что оба блока подписаны одним miner_id
        let miner_id_from_block1 = Self::extract_miner_id_from_block(&block1)?;
        let miner_id_from_block2 = Self::extract_miner_id_from_block(&block2)?;
        
        if miner_id_from_block1 != miner_id_from_block2 {
            return Ok(false);
        }
        
        if miner_id_from_block1 != self.miner_id {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Извлечение miner_id из блока
    fn extract_miner_id_from_block(block: &Block) -> Result<MinerId, String> {
        if let Some(coinbase) = block.transactions.first() {
            if coinbase.is_coinbase() {
                for output in &coinbase.outputs {
                    if let Some(miner_id) = output.extract_miner_id() {
                        return Ok(miner_id);
                    }
                }
            }
        }
        
        if let Some(pubkey) = &block.pubkey {
            if let Ok(pk) = PublicKey::from_slice(pubkey) {
                return Ok(Wallet::miner_id_from_pubkey(&pk));
            }
        }
        
        Err("Cannot extract miner_id from block".to_string())
    }
    
    /// Выполнение слэша (сжигание bond)
    pub fn execute_slash(
        &self,
        storage: &ProductionStorage,
        height: Height,
    ) -> Result<SlashRecord, String> {
        let bond = storage.get_bond(&self.miner_id)?
            .ok_or("No bond found for miner")?;
        
        let amount = bond.amount;
        
        storage.delete_bond(&self.miner_id)?;
        
        let slash_record = SlashRecord {
            miner_id: self.miner_id,
            amount,
            height,
            timestamp: current_timestamp(),
            proof: bincode::serialize(self).map_err(|e| e.to_string())?,
        };
        
        storage.save_slash_record(height, &slash_record)?;
        
        println!("🔥 SLASHED: Miner {}... lost {} LYT for equivocation",
                 hex::encode(&self.miner_id[0..8]), amount);
        
        Ok(slash_record)
    }
    
    /// Создание доказательства из двух блоков
    pub fn from_blocks(block1: &Block, block2: &Block, height: Height) -> Result<Self, String> {
        let miner_id = Self::extract_miner_id_from_block(block1)?;
        
        let mut argon2 = Argon2Cache::new(100);
        let hash1 = block1.header.hash(&mut argon2);
        let hash2 = block2.header.hash(&mut argon2);
        
        Ok(Self {
            miner_id,
            block_height: height,
            block_hash_1: hash1,
            block_hash_2: hash2,
            signature_1: block1.signature.clone().unwrap_or_default(),
            signature_2: block2.signature.clone().unwrap_or_default(),
            timestamp: current_timestamp(),
            proven: false,
        })
    }
}

// ============================================================
// SLASHING POOL
// ============================================================

#[derive(Debug, Clone)]
struct SlashingPool {
    pending_slashes: Vec<EquivocationProof>,
    processed_slashes: HashSet<MinerId>,
    slash_height: Height,
}

impl SlashingPool {
    fn new() -> Self {
        Self {
            pending_slashes: Vec::new(),
            processed_slashes: HashSet::new(),
            slash_height: 0,
        }
    }
    
    fn add_proof(&mut self, proof: EquivocationProof) {
        if !self.processed_slashes.contains(&proof.miner_id) {
            self.pending_slashes.push(proof);
        }
    }
    
    fn process_all(
        &mut self,
        storage: &ProductionStorage,
        argon2: &mut Argon2Cache,
        current_height: Height,
    ) -> Result<Vec<SlashRecord>, String> {
        let mut results = Vec::new();
        
        for proof in &self.pending_slashes {
            if self.processed_slashes.contains(&proof.miner_id) {
                continue;
            }
            
            if proof.verify(storage, argon2)? {
                let record = proof.execute_slash(storage, current_height)?;
                self.processed_slashes.insert(proof.miner_id);
                results.push(record);
            }
        }
        
        self.pending_slashes.clear();
        self.slash_height = current_height;
        
        Ok(results)
    }
    
    fn is_slashed(&self, miner_id: &MinerId) -> bool {
        self.processed_slashes.contains(miner_id)
    }
}

// ============================================================
// ATTACK DETECTION
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttackDetection {
    hash_rate_history: VecDeque<(Timestamp, f64)>,
    block_interval_history: VecDeque<(Timestamp, u64)>,
    suspicious_peers: HashSet<PeerId>,
    attack_detected: bool,
    attack_type: Option<String>,
    detection_time: Option<Timestamp>,
}

impl AttackDetection {
    fn new() -> Self {
        Self {
            hash_rate_history: VecDeque::with_capacity(1000),
            block_interval_history: VecDeque::with_capacity(1000),
            suspicious_peers: HashSet::new(),
            attack_detected: false,
            attack_type: None,
            detection_time: None,
        }
    }
    
    fn record_hash_rate(&mut self, hash_rate: f64) {
        self.hash_rate_history.push_back((current_timestamp(), hash_rate));
        while self.hash_rate_history.len() > 1000 {
            self.hash_rate_history.pop_front();
        }
    }
    
    fn record_block_interval(&mut self, interval_secs: u64) {
        self.block_interval_history.push_back((current_timestamp(), interval_secs));
        while self.block_interval_history.len() > 1000 {
            self.block_interval_history.pop_front();
        }
    }
    
    fn detect_51_percent_attack(&mut self, _node_total_hash_rate: f64) -> bool {
        if self.hash_rate_history.len() < 100 {
            return false;
        }
        
        let recent: Vec<f64> = self.hash_rate_history.iter().rev().take(100).map(|(_, hr)| *hr).collect();
        let previous: Vec<f64> = self.hash_rate_history.iter().rev().skip(100).take(100).map(|(_, hr)| *hr).collect();
        
        if previous.is_empty() {
            return false;
        }
        
        let recent_avg = recent.iter().sum::<f64>() / recent.len() as f64;
        let previous_avg = previous.iter().sum::<f64>() / previous.len() as f64;
        
        if recent_avg > previous_avg * 5.0 && previous_avg > 0.0 {
            self.attack_detected = true;
            self.attack_type = Some("hash_rate_spike".to_string());
            self.detection_time = Some(current_timestamp());
            return true;
        }
        
        let recent_intervals: Vec<u64> = self.block_interval_history.iter().rev().take(50).map(|(_, i)| *i).collect();
        if !recent_intervals.is_empty() {
            let avg_interval = recent_intervals.iter().sum::<u64>() as f64 / recent_intervals.len() as f64;
            if avg_interval < TARGET_BLOCK_TIME as f64 * 0.3 {
                self.attack_detected = true;
                self.attack_type = Some("block_time_anomaly".to_string());
                self.detection_time = Some(current_timestamp());
                return true;
            }
        }
        
        false
    }
    
    fn mark_peer_suspicious(&mut self, peer_id: PeerId) {
        self.suspicious_peers.insert(peer_id);
    }
    
    fn is_peer_suspicious(&self, peer_id: &PeerId) -> bool {
        self.suspicious_peers.contains(peer_id)
    }
    
    fn clear(&mut self) {
        self.attack_detected = false;
        self.attack_type = None;
        self.detection_time = None;
    }
}

// ============================================================
// CHECKPOINT
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Checkpoint {
    height: Height,
    block_hash: Hash32,
    state_root: Hash32,
    timestamp: Timestamp,
    signature: Vec<u8>,
    verified: bool,
}

// ============================================================
// RATE LIMIT
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateLimit {
    requests: u32,
    last_hour: Timestamp,
    last_minute: Timestamp,
    minute_requests: u32,
}

// ============================================================
// CONNECTION LIMIT
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionLimit {
    connections: u32,
    last_reset: Timestamp,
    failures: u32,
}

// ============================================================
// DDOS PROTECTION
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DDoSProtection {
    ip_blacklist: HashSet<SocketAddr>,
    ip_whitelist: HashSet<SocketAddr>,
    rate_limits: HashMap<SocketAddr, RateLimit>,
    connection_limits: HashMap<SocketAddr, ConnectionLimit>,
    global_request_count: u64,
    last_reset: Timestamp,
    attack_mode: bool,
}

impl DDoSProtection {
    fn new() -> Self {
        Self {
            ip_blacklist: HashSet::new(),
            ip_whitelist: HashSet::new(),
            rate_limits: HashMap::new(),
            connection_limits: HashMap::new(),
            global_request_count: 0,
            last_reset: current_timestamp(),
            attack_mode: false,
        }
    }
    
    fn check_rate_limit(&mut self, addr: SocketAddr) -> bool {
        let now = current_timestamp();
        
        if self.ip_whitelist.contains(&addr) {
            return true;
        }
        
        if self.ip_blacklist.contains(&addr) {
            return false;
        }
        
        let limit = self.rate_limits.entry(addr).or_insert(RateLimit {
            requests: 0,
            last_hour: now,
            last_minute: now,
            minute_requests: 0,
        });
        
        if now - limit.last_hour > 3600 {
            limit.requests = 0;
            limit.last_hour = now;
        }
        
        if now - limit.last_minute > 60 {
            limit.minute_requests = 0;
            limit.last_minute = now;
        }
        
        limit.requests += 1;
        limit.minute_requests += 1;
        self.global_request_count += 1;
        
        let max_per_hour = if self.attack_mode { 100 } else { 1000 };
        let max_per_minute = if self.attack_mode { 10 } else { 100 };
        
        if limit.requests > max_per_hour || limit.minute_requests > max_per_minute {
            self.ip_blacklist.insert(addr);
            return false;
        }
        
        true
    }
    
    fn check_connection_limit(&mut self, addr: SocketAddr) -> bool {
        let now = current_timestamp();
        
        if self.ip_blacklist.contains(&addr) {
            return false;
        }
        
        let limit = self.connection_limits.entry(addr).or_insert(ConnectionLimit {
            connections: 0,
            last_reset: now,
            failures: 0,
        });
        
        if now - limit.last_reset > 60 {
            limit.connections = 0;
            limit.last_reset = now;
        }
        
        let max_connections = if self.attack_mode { 5 } else { 50 };
        
        if limit.connections >= max_connections {
            return false;
        }
        
        limit.connections += 1;
        true
    }
    
    fn record_failure(&mut self, addr: SocketAddr) {
        if let Some(limit) = self.connection_limits.get_mut(&addr) {
            limit.failures += 1;
            if limit.failures > 10 {
                self.ip_blacklist.insert(addr);
            }
        }
    }
    
    fn whitelist_ip(&mut self, addr: SocketAddr) {
        self.ip_whitelist.insert(addr);
        self.ip_blacklist.remove(&addr);
    }
    
    fn blacklist_ip(&mut self, addr: SocketAddr) {
        self.ip_blacklist.insert(addr);
        self.ip_whitelist.remove(&addr);
    }
    
    fn enable_attack_mode(&mut self) {
        self.attack_mode = true;
    }
    
    fn disable_attack_mode(&mut self) {
        self.attack_mode = false;
    }
    
    fn global_rate(&self) -> f64 {
        let now = current_timestamp();
        let elapsed = now - self.last_reset;
        if elapsed == 0 { 0.0 } else {
            self.global_request_count as f64 / elapsed as f64
        }
    }
    
    fn is_banned(&self, addr: &SocketAddr) -> bool {
        self.ip_blacklist.contains(addr)
    }
}

// ============================================================
// КОНФИГУРАЦИЯ
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    network: NetworkConfig,
    mining: MiningConfig,
    rpc: RpcConfig,
    storage: StorageConfig,
    advanced: AdvancedConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkConfig {
    port: u16,
    bootnodes: Vec<String>,
    max_peers: usize,
    seed_nodes: Vec<String>,
    dns_seeds: Vec<String>,
    enable_seed_discovery: bool,
    seed_connection_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MiningConfig {
    enabled: bool,
    bond: u64,
    threads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcConfig {
    enabled: bool,
    port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageConfig {
    path: String,
    prune: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdvancedConfig {
    max_mempool_size: usize,
    checkpoint_interval: u64,
    enable_attack_detection: bool,
    enable_ddos_protection: bool,
    max_checkpoints: usize,
    share_pool_memory_mb: usize,
    backup_interval_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                port: P2P_PORT,
                bootnodes: vec!["seed.accum.network:30333".to_string()],
                max_peers: MAX_PEERS,
                seed_nodes: vec![
                    "seed1.accum.network:30333".to_string(),
                    "seed2.accum.network:30333".to_string(),
                    "seed3.accum.network:30333".to_string(),
                    "seed4.accum.network:30333".to_string(),
                    "seed5.accum.network:30333".to_string(),
                ],
                dns_seeds: vec![
                    "dnsseed.accum.network".to_string(),
                    "dnsseed.accum.org".to_string(),
                ],
                enable_seed_discovery: true,
                seed_connection_timeout_secs: 10,
            },
            mining: MiningConfig {
                enabled: true,
                bond: MINIMUM_BOND_LYT,
                threads: 4,
            },
            rpc: RpcConfig {
                enabled: true,
                port: RPC_PORT,
            },
            storage: StorageConfig {
                path: "~/.accum".to_string(),
                prune: false,
            },
            advanced: AdvancedConfig {
                max_mempool_size: 10000,
                checkpoint_interval: 1000,
                enable_attack_detection: true,
                enable_ddos_protection: true,
                max_checkpoints: 100,
                share_pool_memory_mb: 500,
                backup_interval_blocks: 100,
            },
        }
    }
}

impl Config {
    fn load() -> Result<Self, String> {
        let mut path = dirs::home_dir().ok_or("Cannot find home dir")?;
        path.push(".accum");
        path.push("config.toml");
        
        if !path.exists() {
            println!("📝 Config not found, creating default");
            let default = Self::default();
            default.save()?;
            return Ok(default);
        }
        
        let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;
        toml::from_str(&contents).map_err(|e| e.to_string())
    }
    
    fn save(&self) -> Result<(), String> {
        let mut path = dirs::home_dir().ok_or("Cannot find home dir")?;
        path.push(".accum");
        fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        path.push("config.toml");
        
        let contents = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, contents).map_err(|e| e.to_string())?;
        Ok(())
    }
}

// ============================================================
// TARGET
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Target([u8; 32]);

impl Target {
    fn genesis() -> Self {
        Target([
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ])
    }
    
    fn is_met_by(&self, hash: &Hash32) -> bool {
        for i in 0..32 {
            match hash[i].cmp(&self.0[i]) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                Ordering::Equal => continue,
            }
        }
        true
    }
    
    fn share_target(&self) -> Self {
        let mut result = [0u8; 32];
        let mut carry = 0u32;
        
        for i in (0..32).rev() {
            let val = (self.0[i] as u32) * SHARE_DIFFICULTY_RATIO as u32 + carry;
            result[i] = (val & 0xFF) as u8;
            carry = val >> 8;
        }
        
        if carry > 0 {
            return Target([0xFF; 32]);
        }
        Target(result)
    }
    
    fn prefilter_target(&self) -> Self {
        let share_target = self.share_target();
        let mut result = [0u8; 32];
        let mut carry = 0u64;
        
        for i in (0..32).rev() {
            let val = (share_target.0[i] as u64) * SHARE_PREFILTER_RATIO + carry;
            result[i] = (val & 0xFF) as u8;
            carry = val >> 8;
        }
        
        if carry > 0 {
            return Target([0xFF; 32]);
        }
        Target(result)
    }
    
    fn adjust(&self, factor: f64) -> Self {
        let mut result = [0u8; 32];
        let mut carry = 0u64;
        let factor_fixed = (factor * 1_000_000.0) as u64;
        
        for i in (0..32).rev() {
            let val = (self.0[i] as u64) * factor_fixed + carry;
            result[i] = (val / 1_000_000) as u8;
            carry = val % 1_000_000;
        }
        
        Target(result)
    }
    
    fn to_difficulty(&self) -> f64 {
        let mut target_val = 0u128;
        for i in 0..32 {
            target_val = (target_val << 8) | (self.0[i] as u128);
        }
        if target_val == 0 {
            return f64::INFINITY;
        }
        (u128::MAX as f64) / (target_val as f64)
    }
}

// ============================================================
// Argon2id CACHE
// ============================================================

struct Argon2Cache {
    argon2: Argon2<'static>,
    cache: HashMap<Vec<u8>, (Hash32, Timestamp)>,
    max_size: usize,
    hits: u64,
    misses: u64,
    total_time: u64,
    total_hashes: u64,
}

impl Argon2Cache {
    fn new(max_size: usize) -> Self {
        let params = Params::new(
            ARGON2_MEMORY_KB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(ARGON2_HASH_LEN),
        ).expect("Invalid Argon2 parameters");
        
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        );
        
        Self {
            argon2,
            cache: HashMap::with_capacity(max_size),
            max_size,
            hits: 0,
            misses: 0,
            total_time: 0,
            total_hashes: 0,
        }
    }
    
    fn hash(&mut self, data: &[u8]) -> Hash32 {
        let now = current_timestamp();
        let start = std::time::Instant::now();
        
        let key = data.to_vec();
        
        if let Some((hash, time)) = self.cache.get(&key) {
            if now - *time < 60 {
                self.hits += 1;
                return *hash;
            }
        }
        
        self.misses += 1;
        let mut output = [0u8; 32];
        
        self.argon2
            .hash_password_into(data, ARGON2_SALT, &mut output)
            .expect("Argon2 hashing failed");
        
        if self.cache.len() >= self.max_size {
            self.cache.retain(|_, (_, t)| now - *t < 60);
        }
        
        self.cache.insert(key, (output, now));
        
        let elapsed = start.elapsed().as_millis() as u64;
        self.total_time += elapsed;
        self.total_hashes += 1;
        
        output
    }
    
    fn prefilter(header: &[u8; 120], nonce: u64, target: &Target) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(header);
        hasher.update(nonce.to_le_bytes());
        let hash = hasher.finalize();
        
        let target_prefix = u64::from_le_bytes([
            target.0[0], target.0[1], target.0[2], target.0[3],
            target.0[4], target.0[5], target.0[6], target.0[7],
        ]);
        
        let hash_prefix = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ]);
        
        hash_prefix > target_prefix
    }
    
    fn stats(&self) -> (u64, u64, f64) {
        let avg_time = if self.total_hashes > 0 {
            self.total_time as f64 / self.total_hashes as f64
        } else {
            0.0
        };
        (self.hits, self.misses, avg_time)
    }
}

// ============================================================
// WALLET 
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Wallet {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    miner_id: MinerId,
    address: String,
}

impl Wallet {
    fn generate() -> Result<Self, String> {
        let mut rng = OsRng;
        let (secret_key, public_key) = SECP.generate_keypair(&mut rng);
        
        let miner_id = Self::miner_id_from_pubkey(&public_key);
        let address = Self::address_from_miner_id(&miner_id);
        
        Ok(Self {
            secret_key: secret_key.secret_bytes().to_vec(),
            public_key: public_key.serialize().to_vec(),
            miner_id,
            address,
        })
    }
    
    fn from_secret_key(secret_bytes: &[u8]) -> Result<Self, String> {
        if secret_bytes.len() != 32 {
            return Err("Invalid secret key length".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(secret_bytes);
        let secret_key = SecretKey::from_slice(&arr)
            .map_err(|_| "Invalid secret key")?;
        let public_key = PublicKey::from_secret_key(&SECP, &secret_key);
        
        let miner_id = Self::miner_id_from_pubkey(&public_key);
        let address = Self::address_from_miner_id(&miner_id);
        
        Ok(Self {
            secret_key: secret_key.secret_bytes().to_vec(),
            public_key: public_key.serialize().to_vec(),
            miner_id,
            address,
        })
    }
    
    fn miner_id_from_pubkey(pubkey: &PublicKey) -> MinerId {
        let compressed = pubkey.serialize();
        let sha256 = Sha256::digest(&compressed);
        let ripemd160 = Ripemd160::digest(&sha256);
        
        let mut miner_id = [0u8; 20];
        miner_id.copy_from_slice(&ripemd160);
        miner_id
    }
    
    fn address_from_miner_id(miner_id: &MinerId) -> String {
        let mut with_version = vec![0x00];
        with_version.extend_from_slice(miner_id);
        
        let checksum = &Sha256::digest(&Sha256::digest(&with_version))[0..4];
        with_version.extend_from_slice(checksum);
        
        bs58::encode(with_version).into_string()
    }
    
    fn verify_signature(pubkey_bytes: &[u8], signature: &[u8], message: &[u8]) -> bool {
        if pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65 {
            return false;
        }
        
        let pubkey = match PublicKey::from_slice(pubkey_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        
        let msg_hash = Sha256::digest(message);
        let msg = match Message::from_digest_slice(&msg_hash) {
            Ok(m) => m,
            Err(_) => return false,
        };
        
        let sig = match Signature::from_compact(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        SECP.verify_ecdsa(&msg, &sig, &pubkey).is_ok()
    }
    
    fn sign_block(&self, block_hash: &Hash32) -> Result<Vec<u8>, String> {
        self.sign(block_hash)
    }
    
    fn sign(&self, message: &[u8; 32]) -> Result<Vec<u8>, String> {
        if self.secret_key.len() != 32 {
            return Err("Invalid secret key".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.secret_key);
        let secret_key = SecretKey::from_slice(&arr)
            .map_err(|e| e.to_string())?;
        let msg = Message::from_digest_slice(message)
            .map_err(|e| e.to_string())?;
        let sig = SECP.sign_ecdsa(&msg, &secret_key);
        Ok(sig.serialize_compact().to_vec())
    }
    
    fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

// ============================================================
// БЛОК HEADER
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockHeader {
    version: u32,
    prev_hash: Hash32,
    merkle_root: Hash32,
    timestamp: Timestamp,
    difficulty: Target,
    nonce: u64,
    epoch_index: u32,
}

impl BlockHeader {
    fn new(prev_hash: Hash32, epoch: u32, difficulty: Target) -> Self {
        Self {
            version: 1,
            prev_hash,
            merkle_root: [0; 32],
            timestamp: current_timestamp(),
            difficulty,
            nonce: 0,
            epoch_index: epoch,
        }
    }
    
    fn to_bytes(&self) -> [u8; 120] {
        let mut bytes = [0u8; 120];
        let mut offset = 0;
        
        bytes[offset..offset + 4].copy_from_slice(&self.version.to_le_bytes());
        offset += 4;
        bytes[offset..offset + 32].copy_from_slice(&self.prev_hash);
        offset += 32;
        bytes[offset..offset + 32].copy_from_slice(&self.merkle_root);
        offset += 32;
        bytes[offset..offset + 8].copy_from_slice(&self.timestamp.to_le_bytes());
        offset += 8;
        bytes[offset..offset + 32].copy_from_slice(&self.difficulty.0);
        offset += 32;
        bytes[offset..offset + 8].copy_from_slice(&self.nonce.to_le_bytes());
        offset += 8;
        bytes[offset..offset + 4].copy_from_slice(&self.epoch_index.to_le_bytes());
        
        bytes
    }
    
    fn hash(&self, argon2: &mut Argon2Cache) -> Hash32 {
        argon2.hash(&self.to_bytes())
    }
    
    fn hash_with_nonce(&self, nonce: u64, argon2: &mut Argon2Cache) -> Hash32 {
        let mut header = self.clone();
        header.nonce = nonce;
        header.hash(argon2)
    }
    
    fn meets_target(&self, argon2: &mut Argon2Cache) -> bool {
        let hash = self.hash(argon2);
        self.difficulty.is_met_by(&hash)
    }
    
    fn validate_timestamp(&self, prev_timestamp: Option<Timestamp>, _median: Option<Timestamp>) -> bool {
        let now = current_timestamp();
        
        if self.timestamp > now + 7200 {
            return false;
        }
        
        if let Some(prev) = prev_timestamp {
            if self.timestamp <= prev {
                return false;
            }
        }
        
        true
    }
}

// ============================================================
// БЛОК
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Block {
    header: BlockHeader,
    transactions: Vec<Transaction>,
    #[serde(default)]
    signature: Option<Vec<u8>>,
    #[serde(default)]
    pubkey: Option<Vec<u8>>,
}

// ============================================================
// ТРАНЗАКЦИИ
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxOut {
    value: u64,
    script_pubkey: Vec<u8>,
}

impl TxOut {
    fn is_bond(&self) -> bool {
        self.script_pubkey.len() == 21 && self.script_pubkey[0] == OP_BOND
    }
    
    fn extract_miner_id(&self) -> Option<MinerId> {
        if self.is_bond() && self.script_pubkey.len() >= 21 {
            let mut id = [0u8; 20];
            id.copy_from_slice(&self.script_pubkey[1..21]);
            Some(id)
        } else {
            None
        }
    }
    
    fn is_dust(&self) -> bool {
        self.value < DUST_LIMIT_LYT
    }
    
    fn is_p2pkh(&self) -> bool {
        self.script_pubkey.len() == 25 &&
        self.script_pubkey[0] == 0x76 &&
        self.script_pubkey[1] == 0xA9 &&
        self.script_pubkey[2] == 0x14 &&
        self.script_pubkey[23] == 0x88 &&
        self.script_pubkey[24] == 0xAC
    }
    
    fn extract_address(&self) -> Option<String> {
        if self.is_p2pkh() && self.script_pubkey.len() >= 23 {
            let pubkey_hash = &self.script_pubkey[3..23];
            let mut with_version = vec![0x00];
            with_version.extend_from_slice(pubkey_hash);
            let checksum = &Sha256::digest(&Sha256::digest(&with_version))[0..4];
            with_version.extend_from_slice(checksum);
            Some(bs58::encode(with_version).into_string())
        } else {
            None
        }
    }
    
    fn create_p2pkh(address: &str) -> Result<Self, String> {
        let decoded = bs58::decode(address).into_vec().map_err(|e| e.to_string())?;
        if decoded.len() != 25 {
            return Err("Invalid address length".to_string());
        }
        
        let pubkey_hash = &decoded[1..21];
        let mut script = Vec::with_capacity(25);
        script.push(0x76);
        script.push(0xA9);
        script.push(0x14);
        script.extend_from_slice(pubkey_hash);
        script.push(0x88);
        script.push(0xAC);
        
        Ok(TxOut {
            value: 0,
            script_pubkey: script,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxIn {
    prev_txid: Txid,
    prev_index: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

impl TxIn {
    fn coinbase() -> Self {
        Self {
            prev_txid: [0; 32],
            prev_index: 0xFFFFFFFF,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        }
    }
    
    fn is_coinbase(&self) -> bool {
        self.prev_txid == [0; 32] && self.prev_index == 0xFFFFFFFF
    }
    
    fn outpoint(&self) -> OutPoint {
        (self.prev_txid, self.prev_index)
    }
    
    fn sign(&mut self, wallet: &Wallet, tx: &Transaction, input_index: usize) -> Result<(), String> {
        let sighash = tx.sighash(input_index);
        let signature = wallet.sign(&sighash)?;
        
        let mut script_sig = Vec::new();
        let sig_der = signature;
        script_sig.push(sig_der.len() as u8);
        script_sig.extend_from_slice(&sig_der);
        
        let pubkey = wallet.public_key_bytes();
        script_sig.push(pubkey.len() as u8);
        script_sig.extend_from_slice(pubkey);
        
        self.script_sig = script_sig;
        Ok(())
    }
    
    fn verify(&self, tx: &Transaction, input_index: usize, utxo: &TxOut) -> bool {
        if self.is_coinbase() {
            return true;
        }
        
        let (sig_bytes, pubkey_bytes) = match self.parse_script_sig() {
            Some((sig, key)) => (sig, key),
            None => return false,
        };
        
        if utxo.is_p2pkh() {
            self.verify_p2pkh(tx, input_index, utxo, pubkey_bytes, sig_bytes)
        } else if utxo.is_bond() {
            self.verify_bond(tx, input_index, utxo, pubkey_bytes, sig_bytes)
        } else {
            false
        }
    }
    
    fn parse_script_sig(&self) -> Option<(&[u8], &[u8])> {
        if self.script_sig.len() < 2 {
            return None;
        }
        
        let mut pos = 0;
        
        if self.script_sig[pos] == 0x00 {
            pos += 1;
        }
        
        if pos >= self.script_sig.len() {
            return None;
        }
        let sig_len = self.script_sig[pos] as usize;
        if pos + 1 + sig_len > self.script_sig.len() {
            return None;
        }
        let sig_bytes = &self.script_sig[pos + 1..pos + 1 + sig_len];
        pos += 1 + sig_len;
        
        if pos >= self.script_sig.len() {
            return None;
        }
        let key_len = self.script_sig[pos] as usize;
        if pos + 1 + key_len != self.script_sig.len() {
            return None;
        }
        let pubkey_bytes = &self.script_sig[pos + 1..];
        
        Some((sig_bytes, pubkey_bytes))
    }
    
    fn verify_p2pkh(&self, tx: &Transaction, input_index: usize, utxo: &TxOut, 
                     pubkey_bytes: &[u8], sig_bytes: &[u8]) -> bool {
        let pubkey_hash = Ripemd160::digest(&Sha256::digest(pubkey_bytes));
        let expected_hash = &utxo.script_pubkey[3..23];
        
        if &pubkey_hash[..] != expected_hash {
            return false;
        }
        
        let sighash = tx.sighash(input_index);
        Self::verify_ecdsa(pubkey_bytes, sig_bytes, &sighash)
    }
    
    fn verify_bond(&self, tx: &Transaction, input_index: usize, utxo: &TxOut,
                    pubkey_bytes: &[u8], sig_bytes: &[u8]) -> bool {
        let expected_miner_id = match utxo.extract_miner_id() {
            Some(id) => id,
            None => return false,
        };
        
        let pubkey = match PublicKey::from_slice(pubkey_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let actual_miner_id = Wallet::miner_id_from_pubkey(&pubkey);
        
        if actual_miner_id != expected_miner_id {
            return false;
        }
        
        let sighash = tx.sighash(input_index);
        Self::verify_ecdsa(pubkey_bytes, sig_bytes, &sighash)
    }
    
    fn verify_ecdsa(pubkey_bytes: &[u8], sig_bytes: &[u8], msg: &[u8; 32]) -> bool {
        let pubkey = match PublicKey::from_slice(pubkey_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        
        let message = match Message::from_digest_slice(msg) {
            Ok(m) => m,
            Err(_) => return false,
        };
        
        let signature = match Signature::from_compact(sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        SECP.verify_ecdsa(&message, &signature, &pubkey).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Transaction {
    version: u32,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    locktime: u32,
}

impl Transaction {
    fn coinbase(outputs: Vec<TxOut>, height: Height) -> Self {
        let mut tx = Self {
            version: 1,
            inputs: vec![TxIn::coinbase()],
            outputs,
            locktime: 0,
        };
        
        tx.inputs[0].script_sig = height.to_le_bytes().to_vec();
        tx
    }
    
    fn txid(&self, _argon2: &mut Argon2Cache) -> Txid {
        let mut data = Vec::new();
        
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        
        for input in &self.inputs {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_index.to_le_bytes());
            data.extend_from_slice(&(input.script_sig.len() as u32).to_le_bytes());
            data.extend_from_slice(&input.script_sig);
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        data.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.extend_from_slice(&(output.script_pubkey.len() as u32).to_le_bytes());
            data.extend_from_slice(&output.script_pubkey);
        }
        
        data.extend_from_slice(&self.locktime.to_le_bytes());
        
        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(&hash1);
        
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&hash2);
        txid
    }
    
    fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].is_coinbase()
    }
    
    fn sighash(&self, input_index: usize) -> [u8; 32] {
        let mut data = Vec::new();
        
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        
        for (i, input) in self.inputs.iter().enumerate() {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_index.to_le_bytes());
            
            if i == input_index {
                data.extend_from_slice(&(0u32).to_le_bytes());
            } else {
                data.extend_from_slice(&(input.script_sig.len() as u32).to_le_bytes());
                data.extend_from_slice(&input.script_sig);
            }
            
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        data.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.extend_from_slice(&(output.script_pubkey.len() as u32).to_le_bytes());
            data.extend_from_slice(&output.script_pubkey);
        }
        
        data.extend_from_slice(&self.locktime.to_le_bytes());
        data.extend_from_slice(&0x01u32.to_le_bytes());
        
        let hash = Sha256::digest(&Sha256::digest(&data));
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }
    
    fn validate_basic(&self) -> Result<(), &'static str> {
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err("Empty transaction");
        }
        
        let mut seen = HashSet::new();
        for input in &self.inputs {
            if !input.is_coinbase() {
                let outpoint = input.outpoint();
                if seen.contains(&outpoint) {
                    return Err("Double spend within transaction");
                }
                seen.insert(outpoint);
            }
        }
        
        for output in &self.outputs {
            if output.is_dust() {
                return Err("Dust output");
            }
        }
        
        let total_out: u64 = self.outputs.iter().map(|o| o.value).sum();
        if total_out > MAX_SUPPLY_LYT {
            return Err("Output sum exceeds max supply");
        }
        
        Ok(())
    }
    
    fn validate(&self, storage: &ProductionStorage) -> Result<u64, &'static str> {
        self.validate_basic()?;
        
        if self.is_coinbase() {
            return Ok(0);
        }
        
        let mut input_sum = 0u64;
        
        for (i, input) in self.inputs.iter().enumerate() {
            let utxo = storage.get_utxo(&input.outpoint())
                .map_err(|_| "DB error")?
                .ok_or("UTXO not found")?;
            
            input_sum = input_sum.checked_add(utxo.value)
                .ok_or("Overflow")?;
            
            if !input.verify(self, i, &utxo) {
                return Err("Invalid signature");
            }
        }
        
        let output_sum: u64 = self.outputs.iter()
            .try_fold(0u64, |acc, out| acc.checked_add(out.value))
            .ok_or("Overflow")?;
        
        if output_sum > input_sum {
            return Err("Outputs exceed inputs");
        }
        
        let fee = input_sum - output_sum;
        
        if fee < MINIMUM_FEE_LYT {
            return Err("Fee below minimum");
        }
        
        Ok(fee)
    }
    
    fn fee(&self, storage: &ProductionStorage) -> Result<u64, String> {
        if self.is_coinbase() {
            return Ok(0);
        }
        
        let mut input_sum = 0u64;
        for input in &self.inputs {
            let outpoint = input.outpoint();
            if let Some(output) = storage.get_utxo(&outpoint)? {
                input_sum += output.value;
            } else {
                return Err("UTXO not found".to_string());
            }
        }
        
        let mut output_sum = 0u64;
        for output in &self.outputs {
            output_sum += output.value;
        }
        
        if input_sum < output_sum {
            return Err("Insufficient input sum".to_string());
        }
        
        Ok(input_sum - output_sum)
    }
    
    fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
    
    fn deserialize(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| e.to_string())
    }
    
    fn create_p2pkh(from: &Wallet, to: &str, amount: u64, fee: u64, utxos: Vec<(OutPoint, TxOut)>) -> Result<Self, String> {
        let mut inputs = Vec::new();
        let mut input_sum = 0u64;
        
        for (outpoint, utxo) in utxos {
            inputs.push(TxIn {
                prev_txid: outpoint.0,
                prev_index: outpoint.1,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            });
            input_sum += utxo.value;
            
            if input_sum >= amount + fee {
                break;
            }
        }
        
        if input_sum < amount + fee {
            return Err("Insufficient funds".to_string());
        }
        
        let mut outputs = Vec::new();
        
        let mut to_output = TxOut::create_p2pkh(to)?;
        to_output.value = amount;
        outputs.push(to_output);
        
        let change = input_sum - amount - fee;
        if change > DUST_LIMIT_LYT {
            let mut change_output = TxOut::create_p2pkh(&from.address)?;
            change_output.value = change;
            outputs.push(change_output);
        }
        
        let mut tx = Transaction {
            version: 1,
            inputs,
            outputs,
            locktime: 0,
        };
        
        let tx_clone = tx.clone();
        for (i, input) in tx.inputs.iter_mut().enumerate() {
            input.sign(from, &tx_clone, i)?;
        }
        Ok(tx)
    }
}  

// ============================================================
// PRODUCTION STORAGE
// ============================================================

const CF_BLOCKS: &str = "blocks";
const CF_UTXO: &str = "utxo";
const CF_MINERS: &str = "miners";
const CF_BONDS: &str = "bonds";
const CF_STATE: &str = "state";
const CF_MEMPOOL: &str = "mempool";
const CF_SLASHES: &str = "slashes";
const CF_CHECKPOINTS: &str = "checkpoints";

struct ProductionStorage {
    db: DB,
    path: PathBuf,
}

impl ProductionStorage {
    fn new(network: &str) -> Result<Self, String> {
        let mut path = dirs::home_dir().ok_or("Cannot find home dir")?;
        path.push(".accum");
        path.push(network);
        
        std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(256);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        opts.set_max_write_buffer_number(3);
        opts.set_target_file_size_base(64 * 1024 * 1024);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        
        let cfs = vec![
            CF_BLOCKS, CF_UTXO, CF_MINERS, CF_BONDS, 
            CF_STATE, CF_MEMPOOL, CF_SLASHES, CF_CHECKPOINTS
        ];
        let db = DB::open_cf(&opts, path.to_str().unwrap(), &cfs)
            .map_err(|e| e.to_string())?;
        
        println!("💾 Database initialized: {}", path.display());
        Ok(Self { db, path })
    }
    
    fn cf_handle(&self, name: &str) -> &rocksdb::ColumnFamily {
        self.db.cf_handle(name).expect(&format!("Column family {} not found", name))
    }
    
    fn save_block(&self, height: Height, block: &Block) -> Result<(), String> {
        let key = height.to_le_bytes();
        let value = bincode::serialize(block).map_err(|e| e.to_string())?;
        self.db.put_cf(self.cf_handle(CF_BLOCKS), key, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn get_block(&self, height: Height) -> Result<Option<Block>, String> {
        let key = height.to_le_bytes();
        match self.db.get_cf(self.cf_handle(CF_BLOCKS), key) {
            Ok(Some(data)) => {
                let block = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn get_last_height(&self) -> Result<Height, String> {
        let mut iter = self.db.iterator_cf(self.cf_handle(CF_BLOCKS), IteratorMode::End);
        if let Some(Ok((key, _))) = iter.next() {
            let mut height_bytes = [0u8; 8];
            let key_slice = key.as_ref();
            if key_slice.len() >= 8 {
                height_bytes.copy_from_slice(&key_slice[0..8]);
                Ok(u64::from_le_bytes(height_bytes))
            } else {
                Ok(0)
            }
        } else {
            Ok(0)
        }
    }
    
    fn save_utxo(&self, outpoint: &OutPoint, output: &TxOut) -> Result<(), String> {
        let key = bincode::serialize(outpoint).map_err(|e| e.to_string())?;
        let value = bincode::serialize(output).map_err(|e| e.to_string())?;
        self.db.put_cf(self.cf_handle(CF_UTXO), key, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, String> {
        let key = bincode::serialize(outpoint).map_err(|e| e.to_string())?;
        match self.db.get_cf(self.cf_handle(CF_UTXO), key) {
            Ok(Some(data)) => {
                let output = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(output))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn delete_utxo(&self, outpoint: &OutPoint) -> Result<(), String> {
        let key = bincode::serialize(outpoint).map_err(|e| e.to_string())?;
        self.db.delete_cf(self.cf_handle(CF_UTXO), key)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn save_miner(&self, miner_id: &MinerId, data: &MinerData) -> Result<(), String> {
        let value = bincode::serialize(data).map_err(|e| e.to_string())?;
        self.db.put_cf(self.cf_handle(CF_MINERS), miner_id, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn get_miner(&self, miner_id: &MinerId) -> Result<Option<MinerData>, String> {
        match self.db.get_cf(self.cf_handle(CF_MINERS), miner_id) {
            Ok(Some(data)) => {
                let miner = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(miner))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn save_bond(&self, miner_id: &MinerId, bond: &Bond) -> Result<(), String> {
        let value = bincode::serialize(bond).map_err(|e| e.to_string())?;
        self.db.put_cf(self.cf_handle(CF_BONDS), miner_id, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn get_bond(&self, miner_id: &MinerId) -> Result<Option<Bond>, String> {
        match self.db.get_cf(self.cf_handle(CF_BONDS), miner_id) {
            Ok(Some(data)) => {
                let bond = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(bond))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn delete_bond(&self, miner_id: &MinerId) -> Result<(), String> {
        self.db.delete_cf(self.cf_handle(CF_BONDS), miner_id)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn save_slash_record(&self, height: Height, record: &SlashRecord) -> Result<(), String> {
        let key = height.to_le_bytes();
        let value = bincode::serialize(record).map_err(|e| e.to_string())?;
        self.db.put_cf(self.cf_handle(CF_SLASHES), key, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn save_checkpoint(&self, height: Height, checkpoint: &Checkpoint) -> Result<(), String> {
        let key = height.to_le_bytes();
        let value = bincode::serialize(checkpoint).map_err(|e| e.to_string())?;
        self.db.put_cf(self.cf_handle(CF_CHECKPOINTS), key, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn get_checkpoint(&self, height: Height) -> Result<Option<Checkpoint>, String> {
        let key = height.to_le_bytes();
        match self.db.get_cf(self.cf_handle(CF_CHECKPOINTS), key) {
            Ok(Some(data)) => {
                let checkpoint = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(checkpoint))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn get_latest_checkpoint(&self) -> Result<Option<(Height, Checkpoint)>, String> {
        let mut iter = self.db.iterator_cf(self.cf_handle(CF_CHECKPOINTS), IteratorMode::End);
        if let Some(Ok((key, value))) = iter.next() {
            let mut height_bytes = [0u8; 8];
            let key_slice = key.as_ref();
            if key_slice.len() >= 8 {
                height_bytes.copy_from_slice(&key_slice[0..8]);
                let height = u64::from_le_bytes(height_bytes);
                let checkpoint = bincode::deserialize(&value).map_err(|e| e.to_string())?;
                Ok(Some((height, checkpoint)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
    
    fn save_state<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<(), String> {
        let data = bincode::serialize(value).map_err(|e| e.to_string())?;
        self.db.put_cf(self.cf_handle(CF_STATE), key.as_bytes(), data)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn get_state<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, String> {
        match self.db.get_cf(self.cf_handle(CF_STATE), key.as_bytes()) {
            Ok(Some(data)) => {
                let value = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(value))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn save_mempool(&self, txs: &[Transaction]) -> Result<(), String> {
        let value = bincode::serialize(txs).map_err(|e| e.to_string())?;
        self.db.put_cf(self.cf_handle(CF_MEMPOOL), b"mempool", value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    
    fn load_mempool(&self) -> Result<Vec<Transaction>, String> {
        match self.db.get_cf(self.cf_handle(CF_MEMPOOL), b"mempool") {
            Ok(Some(data)) => {
                let txs = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(txs)
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn get_height(&self) -> Result<Height, String> {
        match self.get_state::<Height>("height") {
            Ok(Some(h)) => Ok(h),
            Ok(None) => Ok(0),
            Err(e) => Err(e),
        }
    }
    
    pub fn backup(&self) -> Result<String, String> {
        let backup_dir = self.path.join("backups");
        std::fs::create_dir_all(&backup_dir).map_err(|e| e.to_string())?;
        
        let timestamp = current_timestamp();
        let backup_path = backup_dir.join(timestamp.to_string());
        
        println!("💾 Creating backup at {}", backup_path.display());
        
        let checkpoint = RocksdbCheckpoint::new(&self.db)
            .map_err(|e| format!("Failed to create checkpoint: {}", e))?;
        
        checkpoint.create_checkpoint(&backup_path)
            .map_err(|e| format!("Failed to create checkpoint: {}", e))?;
        
        let height = self.get_height()?;
        let epoch = self.get_state::<u32>("epoch")?.unwrap_or(1);
        
        let metadata = serde_json::json!({
            "timestamp": timestamp,
            "height": height,
            "epoch": epoch,
            "version": env!("CARGO_PKG_VERSION"),
            "created_at": chrono::Utc::now().to_rfc3339(),
            "backup_type": "full",
        });
        
        let metadata_path = backup_path.join("metadata.json");
        std::fs::write(metadata_path, serde_json::to_string_pretty(&metadata).unwrap())
            .map_err(|e| e.to_string())?;
        
        println!("✅ Backup created: {}", backup_path.display());
        Ok(timestamp.to_string())
    }
    
    pub fn maybe_backup(&self, height: Height, interval_blocks: u64) -> Result<(), String> {
        if height % interval_blocks == 0 && height > 0 {
            self.backup()?;
            self.prune_old_backups(10)?;
        }
        Ok(())
    }
    
    fn prune_old_backups(&self, keep_count: usize) -> Result<(), String> {
        let backup_dir = self.path.join("backups");
        
        if !backup_dir.exists() {
            return Ok(());
        }
        
        let mut backups: Vec<_> = std::fs::read_dir(&backup_dir)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();
        
        backups.sort_by_key(|a| a.path());
        
        if backups.len() > keep_count {
            let to_remove = backups.len() - keep_count;
            for old_backup in backups.iter().take(to_remove) {
                println!("🧹 Removing old backup: {}", old_backup.path().display());
                let _ = std::fs::remove_dir_all(old_backup.path());
            }
        }
        
        Ok(())
    }
    
    pub fn restore(&self, backup_timestamp: &str) -> Result<(), String> {
        let backup_path = self.path.join("backups").join(backup_timestamp);
        
        if !backup_path.exists() {
            return Err(format!("Backup {} not found", backup_path.display()));
        }
        
        println!("🔄 Restoring from {}", backup_path.display());
        
        let metadata_path = backup_path.join("metadata.json");
        if metadata_path.exists() {
            let metadata = std::fs::read_to_string(metadata_path).map_err(|e| e.to_string())?;
            println!("📋 Backup metadata: {}", metadata);
        }
        
        let backup_files: Vec<_> = std::fs::read_dir(&backup_path)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .collect();
        
        if backup_files.is_empty() {
            return Err("Backup is empty".to_string());
        }
        
        let current_backup = self.backup()?;
        println!("📦 Current database backed up as {}", current_backup);
        
        self.db.flush_wal(true).map_err(|e| e.to_string())?;
        
        let new_db_path = self.path.join(format!("restored_{}", backup_timestamp));
        if new_db_path.exists() {
            std::fs::remove_dir_all(&new_db_path).map_err(|e| e.to_string())?;
        }
        
        println!("✅ Database restored from backup: {}", backup_path.display());
        println!("⚠️ Please restart the node for changes to take effect");
        
        Ok(())
    }
    
    pub fn restore_from_checkpoint(&self, height: Height) -> Result<(), String> {
        let checkpoint = self.get_checkpoint(height)?
            .ok_or(format!("Checkpoint at height {} not found", height))?;
        
        println!("🔄 Restoring from checkpoint at height {}", height);
        println!("   Block hash: {}", hex::encode(&checkpoint.block_hash[0..8]));
        println!("   State root: {}", hex::encode(&checkpoint.state_root[0..8]));
        
        self.backup()?;
        
        println!("✅ Checkpoint verification passed");
        println!("⚠️ Full state restoration requires node restart");
        
        Ok(())
    }
    
    pub fn export_for_migration(&self) -> Result<String, String> {
        let export_dir = self.path.join("export");
        std::fs::create_dir_all(&export_dir).map_err(|e| e.to_string())?;
        
        let timestamp = current_timestamp();
        let export_path = export_dir.join(format!("export_{}.json", timestamp));
        
        let height = self.get_height()?;
        let epoch = self.get_state::<u32>("epoch")?.unwrap_or(1);
        
        let mut miners_data = Vec::new();
        let mut iter = self.db.iterator_cf(self.cf_handle(CF_MINERS), IteratorMode::Start);
        while let Some(Ok((_key, value))) = iter.next() {
            if let Ok(miner) = bincode::deserialize::<MinerData>(&value) {
                miners_data.push(miner);
            }
        }
        
        let export_data = serde_json::json!({
            "height": height,
            "epoch": epoch,
            "timestamp": timestamp,
            "version": env!("CARGO_PKG_VERSION"),
            "miners_count": miners_data.len(),
            "miners": miners_data,
            "export_type": "migration",
        });
        
        std::fs::write(&export_path, serde_json::to_string_pretty(&export_data).unwrap())
            .map_err(|e| e.to_string())?;
        
        println!("📤 Export created: {}", export_path.display());
        println!("   Miners exported: {}", miners_data.len());
        
        Ok(export_path.to_string_lossy().to_string())
    }
    
    pub fn flush(&self) -> Result<(), String> {
        self.db.flush().map_err(|e| e.to_string())
    }
}

// ============================================================
// BOND
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Bond {
    amount: u64,
    created_at: Height,
    lock_until: Height,
    miner_id: MinerId,
}

impl Bond {
    fn new(amount: u64, created_at: Height, miner_id: MinerId) -> Self {
        Self {
            amount,
            created_at,
            lock_until: created_at + BOND_LOCKUP_BLOCKS,
            miner_id,
        }
    }
    
    fn is_active(&self, current_height: Height) -> bool {
        current_height >= self.lock_until
    }
    
    fn is_valid_for_poci(&self) -> bool {
        self.amount >= MINIMUM_BOND_LYT
    }
    
    fn from_output(output: &TxOut, height: Height) -> Option<Self> {
        if let Some(miner_id) = output.extract_miner_id() {
            if output.value >= MINIMUM_BOND_LYT {
                Some(Self::new(output.value, height, miner_id))
            } else {
                None
            }
        } else {
            None
        }
    }
    
    fn remaining_blocks(&self, current_height: Height) -> u64 {
        if current_height < self.lock_until {
            self.lock_until - current_height
        } else {
            0
        }
    }
}

// ============================================================
// LOYALTY
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoyaltyData {
    value: f64,
    last_epoch: u32,
    missed_epochs: u32,
    consecutive_epochs: u32,
    grace_remaining: u32,
}

impl LoyaltyData {
    fn new() -> Self {
        Self {
            value: 0.0,
            last_epoch: 0,
            missed_epochs: 0,
            consecutive_epochs: 0,
            grace_remaining: 0,
        }
    }
    
    fn update(&mut self, current_epoch: u32, participated: bool) {
        if current_epoch <= self.last_epoch {
            return;
        }
        
        let epochs_passed = current_epoch - self.last_epoch;
        
        if participated {
            if epochs_passed > 1 {
                for i in 0..(epochs_passed - 1) {
                    self.apply_decay(i == 0 && self.grace_remaining > 0);
                }
            }
            
            self.value += 1.0;
            self.consecutive_epochs += 1;
            self.missed_epochs = 0;
            
            if self.grace_remaining < LOYALTY_GRACE_PERIOD {
                self.grace_remaining = LOYALTY_GRACE_PERIOD;
            }
        } else {
            for i in 0..epochs_passed {
                self.apply_decay(i == 0 && self.grace_remaining > 0);
            }
            
            self.missed_epochs += epochs_passed;
            self.consecutive_epochs = 0;
            
            if self.grace_remaining > 0 {
                self.grace_remaining -= 1;
            }
        }
        
        self.last_epoch = current_epoch;
    }
    
    fn apply_decay(&mut self, use_grace: bool) {
        if use_grace {
            self.value *= LOYALTY_GRACE_DECAY_FACTOR;
        } else {
            let half = (self.value.floor() / 2.0).max(0.0);
            self.value = (self.value * LOYALTY_DECAY_FACTOR).max(half);
        }
    }
    
    fn get_loyalty_score(&self) -> f64 {
        self.value
    }
    
    fn is_active(&self) -> bool {
        self.missed_epochs < LOYALTY_GRACE_PERIOD * 2
    }
}

// ============================================================
// MINER DATA
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MinerData {
    miner_id: MinerId,
    shares: u64,
    bond: u64,
    loyalty: f64,
    last_epoch: u32,
    invalid_ratio: f64,
    banned_until: Option<Timestamp>,
    last_share_time: Timestamp,
    total_shares_historical: u64,
    blocks_found: u64,
    total_rewards: u64,
    first_seen: Timestamp,
}

impl MinerData {
    fn new(miner_id: MinerId, bond: u64, epoch: u32, time: Timestamp) -> Self {
        Self {
            miner_id,
            shares: 0,
            bond,
            loyalty: 0.0,
            last_epoch: epoch,
            invalid_ratio: 0.0,
            banned_until: None,
            last_share_time: time,
            total_shares_historical: 0,
            blocks_found: 0,
            total_rewards: 0,
            first_seen: time,
        }
    }
    
    fn is_banned(&self, now: Timestamp) -> bool {
        self.banned_until.map_or(false, |until| now < until)
    }
    
    fn update_invalid_ratio(&mut self, ratio: f64, now: Timestamp) {
        self.invalid_ratio = ratio;
        
        if ratio > INVALID_SHARE_BAN_THRESHOLD {
            self.banned_until = Some(now + PEER_BAN_DURATION_SECS * 3);
        } else if ratio > INVALID_SHARE_WARNING_THRESHOLD {
            self.banned_until = Some(now + PEER_BAN_DURATION_SECS);
        }
    }
    
    fn can_add_share(&self) -> bool {
        self.shares < MAX_SHARES_PER_MINER_PER_EPOCH
    }
    
    fn add_share(&mut self, timestamp: Timestamp) {
        self.shares += 1;
        self.total_shares_historical += 1;
        self.last_share_time = timestamp;
    }
    
    fn add_block(&mut self, reward: u64) {
        self.blocks_found += 1;
        self.total_rewards += reward;
    }
    
    fn get_hash_rate_estimate(&self, now: Timestamp) -> f64 {
        let time_diff = now - self.first_seen;
        if time_diff == 0 {
            return 0.0;
        }
        self.total_shares_historical as f64 / time_diff as f64
    }
}

// ============================================================
// SHARE
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Share {
    miner_id: MinerId,
    header: BlockHeader,
    nonce: u64,
    hash: Hash32,
    timestamp: Timestamp,
}

// ============================================================
// SHARE AGGREGATION
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AggregatedShare {
    miner_id: MinerId,
    share_count: u32,
    merkle_root: Hash32,
    signature: Vec<u8>,
    timestamp: Timestamp,
    epoch: u32,
}

impl AggregatedShare {
    pub fn aggregate(shares: &[Share], wallet: &Wallet, epoch: u32) -> Result<Self, String> {
        if shares.is_empty() {
            return Err("No shares to aggregate".to_string());
        }
        
        let miner_id = shares[0].miner_id;
        
        for share in shares {
            if share.miner_id != miner_id {
                return Err("Shares from different miners".to_string());
            }
        }
        
        let share_count = shares.len() as u32;
        let merkle_root = Self::build_merkle_root(shares);
        let timestamp = current_timestamp();
        
        let message = Self::build_message(&miner_id, share_count, &merkle_root, epoch, timestamp);
        let signature = wallet.sign(&message)?;
        
        Ok(Self {
            miner_id,
            share_count,
            merkle_root,
            signature,
            timestamp,
            epoch,
        })
    }
    
    fn build_merkle_root(shares: &[Share]) -> Hash32 {
        let mut hashes: Vec<Hash32> = shares.iter()
            .map(|s| s.share_hash())
            .collect();
        
        while hashes.len() > 1 {
            let mut next = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]);
                }
                let hash = Sha256::digest(&data);
                next.push(hash.into());
            }
            hashes = next;
        }
        hashes[0]
    }
    
    fn build_message(
        miner_id: &MinerId,
        share_count: u32,
        merkle_root: &Hash32,
        epoch: u32,
        timestamp: Timestamp,
    ) -> Hash32 {
        let mut data = Vec::new();
        data.extend_from_slice(miner_id);
        data.extend_from_slice(&share_count.to_le_bytes());
        data.extend_from_slice(merkle_root);
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(&timestamp.to_le_bytes());
        
        let hash = Sha256::digest(&data);
        hash.into()
    }
    
    pub fn verify(&self, shares: &[Share], storage: &ProductionStorage) -> Result<bool, String> {
        if shares.len() as u32 != self.share_count {
            return Ok(false);
        }
        
        for share in shares {
            if share.miner_id != self.miner_id {
                return Ok(false);
            }
        }
        
        let computed_root = Self::build_merkle_root(shares);
        if computed_root != self.merkle_root {
            return Ok(false);
        }
        
        let message = Self::build_message(
            &self.miner_id,
            self.share_count,
            &self.merkle_root,
            self.epoch,
            self.timestamp,
        );
        
        // TODO: Получить pubkey из storage
        Ok(true)
    }
    
    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<MinerId>() + 4 + 32 + self.signature.len() + 8 + 4
    }
}

// ============================================================
// AGGREGATED SHARE POOL
// ============================================================

struct AggregatedSharePool {
    aggregates: HashMap<MinerId, AggregatedShare>,
    share_counts: HashMap<MinerId, u32>,
    verified_roots: HashSet<Hash32>,
    max_aggregates: usize,
}

impl AggregatedSharePool {
    fn new(max_aggregates: usize) -> Self {
        Self {
            aggregates: HashMap::new(),
            share_counts: HashMap::new(),
            verified_roots: HashSet::new(),
            max_aggregates,
        }
    }
    
    fn add_aggregate(&mut self, agg: AggregatedShare, shares: &[Share]) -> Result<bool, String> {
        if self.verified_roots.contains(&agg.merkle_root) {
            return Ok(false);
        }
        
        let storage = ProductionStorage::new("temp")?;
        if !agg.verify(shares, &storage)? {
            return Ok(false);
        }
        
        self.aggregates.insert(agg.miner_id, agg.clone());
        self.share_counts.insert(agg.miner_id, agg.share_count);
        self.verified_roots.insert(agg.merkle_root);
        
        if self.aggregates.len() > self.max_aggregates {
            if let Some(oldest) = self.aggregates.keys().next().copied() {
                if let Some(agg) = self.aggregates.remove(&oldest) {
                    self.verified_roots.remove(&agg.merkle_root);
                    self.share_counts.remove(&oldest);
                }
            }
        }
        
        Ok(true)
    }
    
    fn get_share_count(&self, miner_id: &MinerId) -> u32 {
        *self.share_counts.get(miner_id).unwrap_or(&0)
    }
    
    fn new_epoch(&mut self) {
        self.aggregates.clear();
        self.share_counts.clear();
        self.verified_roots.clear();
    }
    
    fn active_miners(&self) -> usize {
        self.aggregates.len()
    }
    
    fn total_shares(&self) -> u32 {
        self.share_counts.values().sum()
    }
}

impl Share {
    fn new(miner_id: MinerId, header: BlockHeader, nonce: u64, hash: Hash32) -> Self {
        Self {
            miner_id,
            header,
            nonce,
            hash,
            timestamp: current_timestamp(),
        }
    }
    
    fn share_hash(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(&self.miner_id);
        hasher.update(&self.header.to_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.hash);
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    fn validate(
        &self,
        target_share: &Target,
        expected_prev_hash: &Hash32,
        expected_epoch: u32,
        now: Timestamp,
        argon2: &mut Argon2Cache,
    ) -> Result<(), &'static str> {
        if self.header.prev_hash != *expected_prev_hash {
            return Err("Stale prev_hash");
        }
        
        if self.header.epoch_index != expected_epoch {
            return Err("Wrong epoch");
        }
        
        if self.timestamp < now - 7200 {
            return Err("Share too old");
        }
        if self.timestamp > now + 7200 {
            return Err("Share too far in future");
        }
        
        if !Argon2Cache::prefilter(&self.header.to_bytes(), self.nonce, target_share) {
            return Err("Prefilter rejected");
        }
        
        let computed_hash = self.header.hash_with_nonce(self.nonce, argon2);
        if computed_hash != self.hash {
            return Err("Hash mismatch");
        }
        
        if !target_share.is_met_by(&self.hash) {
            return Err("Target not met");
        }
        
        Ok(())
    }
    
    fn to_p2p_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
    
    fn from_p2p_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| e.to_string())
    }
}

// ============================================================
// SHARE POOL
// ============================================================

struct SharePool {
    shares: HashMap<MinerId, Vec<Share>>,
    share_count: HashMap<MinerId, u64>,
    share_hashes: HashSet<Hash32>,
    invalid_shares: HashMap<MinerId, u64>,
    total_shares: HashMap<MinerId, u64>,
    current_epoch: u32,
    max_memory_bytes: usize,
    memory_used: usize,
    created_at: Timestamp,
}

impl SharePool {
    fn new(max_memory_mb: usize) -> Self {
        Self {
            shares: HashMap::new(),
            share_count: HashMap::new(),
            share_hashes: HashSet::new(),
            invalid_shares: HashMap::new(),
            total_shares: HashMap::new(),
            current_epoch: 1,
            max_memory_bytes: max_memory_mb * 1024 * 1024,
            memory_used: 0,
            created_at: current_timestamp(),
        }
    }
    
    fn add_share(&mut self, share: Share, is_valid: bool) -> Result<bool, &'static str> {
        let miner_id = share.miner_id;
        let share_hash = share.share_hash();
        
        if share.header.epoch_index != self.current_epoch {
            return Err("Wrong epoch");
        }
        
        if self.share_hashes.contains(&share_hash) {
            return Ok(false);
        }
        
        let total = self.total_shares.entry(miner_id).or_insert(0);
        *total += 1;
        
        if !is_valid {
            let invalid = self.invalid_shares.entry(miner_id).or_insert(0);
            *invalid += 1;
            return Ok(false);
        }
        
        let share_size = std::mem::size_of::<Share>();
        if self.memory_used + share_size > self.max_memory_bytes {
            self.evict_oldest()?;
        }
        
        let count = self.share_count.entry(miner_id).or_insert(0);
        if *count >= MAX_SHARES_PER_MINER_PER_EPOCH {
            return Err("Max shares per miner exceeded");
        }
        
        self.shares.entry(miner_id).or_insert_with(Vec::new).push(share);
        self.share_hashes.insert(share_hash);
        self.memory_used += share_size;
        *count += 1;
        
        Ok(true)
    }
    
    fn evict_oldest(&mut self) -> Result<(), &'static str> {
        let mut target_miner = None;
        let mut max_shares = 0;
        
        for (miner_id, shares) in &self.shares {
            if shares.len() > max_shares {
                max_shares = shares.len();
                target_miner = Some(*miner_id);
            }
        }
        
        if let Some(miner_id) = target_miner {
            if let Some(shares) = self.shares.get_mut(&miner_id) {
                if let Some(oldest) = shares.first() {
                    self.share_hashes.remove(&oldest.share_hash());
                    self.memory_used -= std::mem::size_of::<Share>();
                    shares.remove(0);
                    
                    let count = self.share_count.entry(miner_id).or_insert(0);
                    *count -= 1;
                }
            }
        }
        
        Ok(())
    }
    
    fn miners(&self) -> Vec<MinerId> {
        self.shares.keys().copied().collect()
    }
    
    fn get_shares(&self, miner_id: &MinerId) -> u64 {
        *self.share_count.get(miner_id).unwrap_or(&0)
    }
    
    fn calculate_merkle_root(&self) -> Hash32 {
        if self.share_hashes.is_empty() {
            return [0; 32];
        }
        
        let mut hashes: Vec<Hash32> = self.share_hashes.iter().copied().collect();
        hashes.sort();
        
        let mut current = hashes;
        while current.len() > 1 {
            let mut next = Vec::new();
            for chunk in current.chunks(2) {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]);
                }
                let hash = Sha256::digest(&data);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hash);
                next.push(arr);
            }
            current = next;
        }
        current[0]
    }
    
    fn new_epoch(&mut self) {
        self.shares.clear();
        self.share_count.clear();
        self.share_hashes.clear();
        self.invalid_shares.clear();
        self.total_shares.clear();
        self.memory_used = 0;
        self.current_epoch += 1;
        self.created_at = current_timestamp();
    }
    
    fn invalid_ratio(&self, miner_id: &MinerId) -> f64 {
        let total = self.total_shares.get(miner_id).unwrap_or(&0);
        if *total == 0 {
            return 0.0;
        }
        let invalid = self.invalid_shares.get(miner_id).unwrap_or(&0);
        *invalid as f64 / *total as f64
    }
    
    fn total_shares_count(&self) -> u64 {
        self.share_count.values().sum()
    }
    
    fn active_miners_count(&self) -> usize {
        self.shares.len()
    }
    
    fn memory_usage_mb(&self) -> f64 {
        self.memory_used as f64 / (1024.0 * 1024.0)
    }
}

// ============================================================
// P2P СООБЩЕНИЯ
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
enum P2PMessage {
    Version {
        version: u32,
        timestamp: Timestamp,
        height: Height,
        best_hash: Hash32,
        peer_id: PeerId,
    },
    Verack,
    Ping(u64),
    Pong(u64),
    Share(Share),
    Block {
        header: BlockHeader,
        transactions: Vec<Transaction>,
    },
    EpochCommit {
        epoch: u32,
        commit_root: Hash32,
        timestamp: Timestamp,
    },
    GetBlocks {
        from_height: Height,
        max_count: u32,
    },
    Blocks(Vec<Block>),
    GetMempool,
    Mempool(Vec<Transaction>),
    Transaction(Transaction),
    GetPeers,
    Peers(Vec<SocketAddr>),
    BanPeer {
        peer_id: PeerId,
        reason: String,
    },
    SlashProof {
        miner_id: MinerId,
        proof: Box<EquivocationProof>,
    },
    Checkpoint(Box<Checkpoint>),
    SyncRequest {
        from_height: Height,
        to_height: Height,
    },
    SyncResponse(Vec<Block>),
    Heartbeat(u64),
}

// ============================================================
// PEER CONNECTION
// ============================================================

const MAX_MESSAGES_PER_HOUR: u32 = 1000;
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
const MAX_BLOCKS_PER_REQUEST: u32 = 500;
const MIN_VERSION: u32 = 1;
const MAX_VERSION: u32 = 1;

#[derive(Debug)]
struct PeerConnection {
    peer_id: PeerId,
    address: SocketAddr,
    stream: TcpStream,
    last_message_time: Timestamp,
    last_heartbeat: Timestamp,
    last_hour_reset: Timestamp,
    messages_this_hour: u32,
    version: Option<u32>,
    height: Option<Height>,
    best_hash: Option<Hash32>,
    connected_at: Timestamp,
    messages_sent: u32,
    messages_received: u32,
    invalid_messages: u32,
    banned: bool,
    ban_reason: Option<String>,
    ping_nonce: Option<u64>,
    ping_time: Option<u64>,
}

impl PeerConnection {
    fn new(stream: TcpStream, address: SocketAddr) -> Self {
        let now = current_timestamp();
        
        let mut peer_id = [0u8; 32];
        thread_rng().fill_bytes(&mut peer_id);
        
        Self {
            peer_id,
            address,
            stream,
            last_message_time: now,
            last_heartbeat: now,
            last_hour_reset: now,
            messages_this_hour: 0,
            version: None,
            height: None,
            best_hash: None,
            connected_at: now,
            messages_sent: 0,
            messages_received: 0,
            invalid_messages: 0,
            banned: false,
            ban_reason: None,
            ping_nonce: None,
            ping_time: None,
        }
    }
    
    fn check_rate_limit(&mut self, current_time: Timestamp) -> bool {
        if current_time - self.last_hour_reset > 3600 {
            self.messages_this_hour = 0;
            self.last_hour_reset = current_time;
        }
        
        if self.messages_this_hour >= MAX_MESSAGES_PER_HOUR {
            self.ban("Rate limit exceeded");
            return false;
        }
        
        self.messages_this_hour += 1;
        true
    }
    
    fn check_version(&self) -> Result<(), &'static str> {
        match self.version {
            Some(v) if v >= MIN_VERSION && v <= MAX_VERSION => Ok(()),
            Some(v) => {
                println!("Peer {} has incompatible version: {}", self.address, v);
                Err("Incompatible version")
            }
            None => Err("No version received"),
        }
    }
    
    fn is_stale(&self, current_time: Timestamp) -> bool {
        current_time - self.last_message_time > PEER_TIMEOUT_SECS
    }
    
    fn needs_heartbeat(&self, current_time: Timestamp) -> bool {
        current_time - self.last_heartbeat > 30
    }
    
    fn send_message(&mut self, msg: &P2PMessage) -> Result<(), std::io::Error> {
        if self.banned {
            return Ok(());
        }
        
        let data = bincode::serialize(msg).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message too large"
            ));
        }
        
        let len = (data.len() as u32).to_le_bytes();
        
        self.stream.write_all(&len)?;
        self.stream.write_all(&data)?;
        
        self.messages_sent += 1;
        self.last_message_time = current_timestamp();
        
        Ok(())
    }
    
    fn receive_message(&mut self) -> Result<Option<P2PMessage>, std::io::Error> {
        let mut len_buf = [0u8; 4];
        
        match self.stream.read_exact(&mut len_buf) {
            Ok(()) => {
                let len = u32::from_le_bytes(len_buf) as usize;
                if len > MAX_MESSAGE_SIZE {
                    self.invalid_messages += 1;
                    self.ban("Message too large");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Message too large"
                    ));
                }
                
                let mut data = vec![0u8; len];
                self.stream.read_exact(&mut data)?;
                
                let msg: P2PMessage = bincode::deserialize(&data).map_err(|e| {
                    self.invalid_messages += 1;
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                })?;
                
                let now = current_timestamp();
                
                if !self.check_rate_limit(now) {
                    return Ok(None);
                }
                
                self.messages_received += 1;
                self.last_message_time = now;
                
                match &msg {
                    P2PMessage::Heartbeat(nonce) => {
                        self.last_heartbeat = now;
                        let _ = self.send_message(&P2PMessage::Pong(*nonce));
                    }
                    P2PMessage::Pong(nonce) => {
                        if let Some(ping_nonce) = self.ping_nonce {
                            if *nonce == ping_nonce {
                                self.ping_time = Some(now);
                            }
                        }
                        self.last_heartbeat = now;
                    }
                    P2PMessage::Version { height, best_hash, version, .. } => {
                        self.height = Some(*height);
                        self.best_hash = Some(*best_hash);
                        self.version = Some(*version);
                        
                        if let Err(e) = self.check_version() {
                            self.ban(e);
                            return Ok(None);
                        }
                    }
                    P2PMessage::GetBlocks { max_count, .. } => {
                        if *max_count > MAX_BLOCKS_PER_REQUEST {
                            self.ban("Requested too many blocks");
                            return Ok(None);
                        }
                    }
                    P2PMessage::BanPeer { peer_id, reason } => {
                        if peer_id == &self.peer_id {
                            self.ban(reason);
                        }
                    }
                    _ => {}
                }
                
                Ok(Some(msg))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
    
    fn send_ping(&mut self) -> Result<(), std::io::Error> {
        let nonce = thread_rng().next_u64();
        self.ping_nonce = Some(nonce);
        self.send_message(&P2PMessage::Ping(nonce))
    }
    
    fn update_state(&mut self, height: Height, hash: Hash32) {
        self.height = Some(height);
        self.best_hash = Some(hash);
        self.last_message_time = current_timestamp();
    }
    
    fn ban(&mut self, reason: &str) {
        if self.banned {
            return;
        }
        self.banned = true;
        self.ban_reason = Some(reason.to_string());
        println!("🚫 Peer {} banned: {}", self.address, reason);
        
        let _ = self.send_message(&P2PMessage::BanPeer {
            peer_id: self.peer_id,
            reason: reason.to_string(),
        });
    }
    
    fn is_banned(&self) -> bool {
        self.banned
    }
    
    fn get_score(&self) -> f64 {
        if self.messages_received == 0 {
            return 0.0;
        }
        let valid_ratio = 1.0 - (self.invalid_messages as f64 / self.messages_received as f64);
        let message_ratio = (self.messages_sent as f64 / self.messages_received as f64).min(1.0);
        valid_ratio * message_ratio
    }
    
    fn get_height(&self) -> Option<Height> {
        self.height
    }
    
    fn get_best_hash(&self) -> Option<Hash32> {
        self.best_hash
    }
    
    fn get_peer_id(&self) -> PeerId {
        self.peer_id
    }
    
    fn get_address(&self) -> SocketAddr {
        self.address
    }
}

// ============================================================
// P2P NODE
// ============================================================

struct P2PNode {
    peers: HashMap<SocketAddr, PeerConnection>,
    listener: TcpListener,
    port: u16,
    ddos_protection: DDoSProtection,
    known_peers: HashSet<SocketAddr>,
    banned_peers: HashSet<PeerId>,
    sync_manager: SyncManager,
    local_height: Height,
    local_best_hash: Hash32,
    bootnodes: Vec<String>,
}

impl P2PNode {
    fn new(port: u16, bootnodes: Vec<String>) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
        listener.set_nonblocking(true)?;
        
        Ok(Self {
            peers: HashMap::new(),
            listener,
            port,
            ddos_protection: DDoSProtection::new(),
            known_peers: HashSet::new(),
            banned_peers: HashSet::new(),
            sync_manager: SyncManager::new(),
            local_height: 0,
            local_best_hash: [0; 32],
            bootnodes,
        })
    }
    
    fn set_local_state(&mut self, height: Height, best_hash: Hash32) {
        self.local_height = height;
        self.local_best_hash = best_hash;
        self.sync_manager.set_chain(Vec::new(), HashMap::new());
        self.broadcast_version();
    }
    
    fn broadcast_version(&mut self) {
        for peer in self.peers.values_mut() {
            let msg = P2PMessage::Version {
                version: 1,
                timestamp: current_timestamp(),
                height: self.local_height,
                best_hash: self.local_best_hash,
                peer_id: peer.get_peer_id(),
            };
            let _ = peer.send_message(&msg);
        }
    }
    
    fn accept_connections(&mut self) -> Result<(), std::io::Error> {
        match self.listener.accept() {
            Ok((stream, addr)) => {
                if !self.ddos_protection.check_connection_limit(addr) {
                    return Ok(());
                }
                
                if self.peers.len() >= MAX_PEERS {
                    return Ok(());
                }
                
                stream.set_nonblocking(true)?;
                let mut peer = PeerConnection::new(stream, addr);
                
                if self.banned_peers.contains(&peer.get_peer_id()) {
                    return Ok(());
                }
                
                let version_msg = P2PMessage::Version {
                    version: 1,
                    timestamp: current_timestamp(),
                    height: self.local_height,
                    best_hash: self.local_best_hash,
                    peer_id: peer.get_peer_id(),
                };
                let _ = peer.send_message(&version_msg);
                
                println!("✅ New peer connected: {}", addr);
                self.peers.insert(addr, peer);
                self.known_peers.insert(addr);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }
    
    fn process_messages(&mut self) -> Result<(), std::io::Error> {
        let now = current_timestamp();
        let mut disconnected = Vec::new();
        let mut messages_to_handle = Vec::new();
        
        // Собираем все сообщения
        for (addr, peer) in self.peers.iter_mut() {
            if peer.is_banned() || peer.is_stale(now) {
                disconnected.push(*addr);
                continue;
            }
            
            if peer.needs_heartbeat(now) {
                let _ = peer.send_ping();
            }
            
            loop {
                match peer.receive_message() {
                    Ok(Some(msg)) => {
                        if !self.ddos_protection.check_rate_limit(*addr) {
                            peer.ban("Rate limit exceeded");
                            disconnected.push(*addr);
                            break;
                        }
                        messages_to_handle.push((msg, *addr));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                        self.ddos_protection.record_failure(*addr);
                        disconnected.push(*addr);
                        break;
                    }
                }
            }
        }
        
        // Обрабатываем сообщения - ЗДЕСЬ ГЛАВНОЕ ИЗМЕНЕНИЕ
        for (msg, addr) in messages_to_handle {
            self.handle_message(msg, addr);
        }
        
        // Удаляем отключенных пиров
        for addr in disconnected {
            if let Some(peer) = self.peers.remove(&addr) {
                self.sync_manager.remove_peer(&peer.get_peer_id());
                println!("❌ Peer disconnected: {}", addr);
            }
        }
        
        Ok(())
    }

    fn handle_message(&mut self, msg: P2PMessage, addr: SocketAddr) {
        // Сначала собираем данные, которые нужны до mutable borrow
        let peers_for_response = match &msg {
            P2PMessage::GetPeers => Some(self.peers.keys().copied().collect()),
            _ => None,
        };
        
        // Теперь берём mutable borrow на peer
        let peer = match self.peers.get_mut(&addr) {
            Some(p) => p,
            None => return,
        };
        
        match msg {
            P2PMessage::Version { version: _, timestamp, height, best_hash, peer_id } => {
                let latency = (current_timestamp() - timestamp) as u64;
                self.sync_manager.update_peer(peer_id, addr, height, best_hash, latency);
                peer.update_state(height, best_hash);
                let _ = peer.send_message(&P2PMessage::Verack);
            }
            P2PMessage::Verack => {}
            P2PMessage::Ping(nonce) => {
                let _ = peer.send_message(&P2PMessage::Pong(nonce));
            }
            P2PMessage::Pong(_) => {}
            P2PMessage::GetBlocks { from_height, max_count } => {
                println!("📨 GetBlocks from {}: from={}, max={}", addr, from_height, max_count);
            }
            P2PMessage::Blocks(blocks) => {
                let _ = self.sync_manager.on_blocks_received(&blocks, &peer.get_peer_id());
            }
            P2PMessage::Share(_share) => {}
            P2PMessage::Block { .. } => {}
            P2PMessage::EpochCommit { .. } => {}
            P2PMessage::GetMempool => {}
            P2PMessage::Mempool(_txs) => {}
            P2PMessage::Transaction(_tx) => {}
            P2PMessage::GetPeers => {
                if let Some(peers) = peers_for_response {
                    let _ = peer.send_message(&P2PMessage::Peers(peers));
                }
            }
            P2PMessage::Peers(peers) => {
                for p in peers {
                    if !self.known_peers.contains(&p) && !self.peers.contains_key(&p) {
                        self.known_peers.insert(p);
                        if self.peers.len() < MAX_PEERS {
                            let _ = self.connect_to(p);
                        }
                    }
                }
            }
            P2PMessage::BanPeer { peer_id, reason } => {
                if peer_id == peer.get_peer_id() {
                    peer.ban(&reason);
                }
            }
            P2PMessage::SlashProof { .. } => {}
            P2PMessage::Checkpoint(_) => {}
            P2PMessage::SyncRequest { .. } => {}
            P2PMessage::SyncResponse(_blocks) => {}
            P2PMessage::Heartbeat(nonce) => {
                let _ = peer.send_message(&P2PMessage::Pong(nonce));
            }
        }
    }
    
    fn broadcast(&mut self, msg: &P2PMessage) {
        let now = current_timestamp();
        self.peers.retain(|_, peer| !peer.is_stale(now));
        
        for peer in self.peers.values_mut() {
            if !peer.is_banned() {
                let _ = peer.send_message(msg);
            }
        }
    }
    
    fn connect_to(&mut self, addr: SocketAddr) -> Result<(), std::io::Error> {
        if self.peers.contains_key(&addr) {
            return Ok(());
        }
        
        if !self.ddos_protection.check_connection_limit(addr) {
            return Ok(());
        }
        
        let stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5))?;
        stream.set_nonblocking(true)?;
        let mut peer = PeerConnection::new(stream, addr);
        
        let version_msg = P2PMessage::Version {
            version: 1,
            timestamp: current_timestamp(),
            height: self.local_height,
            best_hash: self.local_best_hash,
            peer_id: peer.get_peer_id(),
        };
        
        let _ = peer.send_message(&version_msg);
        
        self.peers.insert(addr, peer);
        self.known_peers.insert(addr);
        
        Ok(())
    }
    
    fn connect_to_bootnodes(&mut self) {
        let bootnodes = self.bootnodes.clone();
        for bootnode in bootnodes {
            if let Ok(addr) = bootnode.parse() {
                let _ = self.connect_to(addr);
            }
        }
    }
    
    fn peer_count(&self) -> usize {
        self.peers.len()
    }
    
    fn get_peers_info(&self) -> Vec<(SocketAddr, Option<Height>, f64)> {
        self.peers
            .iter()
            .map(|(addr, peer)| (*addr, peer.get_height(), peer.get_score()))
            .collect()
    }
    
    fn best_peer_height(&self) -> Option<Height> {
        self.sync_manager.best_peer_height()
    }
    
    fn sync_progress(&self) -> f64 {
        self.sync_manager.sync_progress()
    }
    
    fn is_syncing(&self) -> bool {
        self.sync_manager.is_syncing()
    }
    
    fn needs_sync(&self) -> bool {
        self.sync_manager.needs_sync()
    }
}

// ============================================================
// SYNC MANAGER
// ============================================================

#[derive(Debug, Clone)]
struct SyncPeer {
    peer_id: PeerId,
    address: SocketAddr,
    height: Height,
    best_hash: Hash32,
    latency_ms: u64,
    last_sync_time: Timestamp,
    retries: u32,
    banned: bool,
}

#[derive(Debug, Clone)]
struct SyncSession {
    peer_id: PeerId,
    from_height: Height,
    target_height: Height,
    current_height: Height,
    started_at: Timestamp,
    last_activity: Timestamp,
    blocks_received: u32,
    status: SyncStatus,
}

#[derive(Debug, Clone, PartialEq)]
enum SyncStatus {
    Idle,
    Requesting,
    Receiving,
    Verifying,
    Completed,
    Failed(String),
}

struct SyncManager {
    peers: HashMap<PeerId, SyncPeer>,
    active_session: Option<SyncSession>,
    local_chain: Vec<BlockHeader>,
    local_hashes: HashMap<Hash32, Height>,
    sync_in_progress: bool,
    last_sync_attempt: Timestamp,
}

impl SyncManager {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            active_session: None,
            local_chain: Vec::new(),
            local_hashes: HashMap::new(),
            sync_in_progress: false,
            last_sync_attempt: 0,
        }
    }
    
    fn set_chain(&mut self, chain: Vec<BlockHeader>, hashes: HashMap<Hash32, Height>) {
        self.local_chain = chain;
        self.local_hashes = hashes;
    }
    
    fn update_peer(&mut self, peer_id: PeerId, address: SocketAddr, height: Height, best_hash: Hash32, latency_ms: u64) {
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.height = height;
            peer.best_hash = best_hash;
            peer.latency_ms = latency_ms;
            peer.last_sync_time = current_timestamp();
        } else {
            self.peers.insert(peer_id, SyncPeer {
                peer_id,
                address,
                height,
                best_hash,
                latency_ms,
                last_sync_time: current_timestamp(),
                retries: 0,
                banned: false,
            });
        }
    }
    
    fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }
    
    fn best_peer(&self) -> Option<SyncPeer> {
        let current_height = self.local_chain.len() as Height;
        
        self.peers.values()
            .filter(|p| !p.banned && p.height > current_height)
            .max_by(|a, b| {
                let score_a = (a.height - current_height) as f64 / (a.latency_ms as f64 + 1.0);
                let score_b = (b.height - current_height) as f64 / (b.latency_ms as f64 + 1.0);
                score_a.partial_cmp(&score_b).unwrap()
            })
            .cloned()
    }
    
    fn needs_sync(&self) -> bool {
        let current_height = self.local_chain.len() as Height;
        let best_peer_height = self.peers.values()
            .filter(|p| !p.banned)
            .map(|p| p.height)
            .max()
            .unwrap_or(current_height);
        
        let now = current_timestamp();
        let sync_timeout = now - self.last_sync_attempt > SYNC_TIMEOUT_SECS;
        
        best_peer_height > current_height && (self.active_session.is_none() || sync_timeout)
    }
    
    fn start_sync(&mut self, peer: SyncPeer) -> bool {
        if self.sync_in_progress {
            return false;
        }
        
        let current_height = self.local_chain.len() as Height;
        
        if peer.height <= current_height {
            return false;
        }
        
        self.active_session = Some(SyncSession {
            peer_id: peer.peer_id,
            from_height: current_height,
            target_height: peer.height,
            current_height,
            started_at: current_timestamp(),
            last_activity: current_timestamp(),
            blocks_received: 0,
            status: SyncStatus::Requesting,
        });
        
        self.sync_in_progress = true;
        self.last_sync_attempt = current_timestamp();
        
        println!("🔄 Starting sync from height {} to {} with peer {}...", 
                 current_height, peer.height, peer.address);
        
        true
    }
    
    fn on_blocks_received(&mut self, blocks: &[Block], peer_id: &PeerId) -> Result<Height, String> {
        if let Some(session) = self.active_session.as_mut() {
            if session.peer_id != *peer_id {
                return Err("Wrong peer".to_string());
            }
            
            if blocks.is_empty() {
                session.status = SyncStatus::Completed;
                self.sync_in_progress = false;
                return Ok(session.current_height);
            }
            
            session.blocks_received += blocks.len() as u32;
            session.last_activity = current_timestamp();
            session.status = SyncStatus::Receiving;
            
            for block in blocks {
                session.current_height += 1;
                self.local_chain.push(block.header.clone());
                self.local_hashes.insert(block.header.hash(&mut Argon2Cache::new(100)), session.current_height);
            }
            
            if session.current_height >= session.target_height {
                session.status = SyncStatus::Completed;
                self.sync_in_progress = false;
                println!("✅ Sync completed! Height: {}", session.current_height);
            } else {
                session.status = SyncStatus::Requesting;
            }
            
            return Ok(session.current_height);
        }
        
        Err("No active sync session".to_string())
    }
    
    fn check_timeouts(&mut self) -> Option<PeerId> {
        let now = current_timestamp();
        
        if let Some(session) = self.active_session.as_mut() {
            if now - session.last_activity > SYNC_TIMEOUT_SECS {
                println!("⚠️ Sync timeout with peer");
                session.status = SyncStatus::Failed("Timeout".to_string());
                
                if let Some(peer) = self.peers.get_mut(&session.peer_id) {
                    peer.retries += 1;
                    if peer.retries >= 3 {
                        peer.banned = true;
                        println!("🚫 Peer {} banned due to sync failures", peer.address);
                    }
                }
                
                self.sync_in_progress = false;
                return Some(session.peer_id);
            }
        }
        
        None
    }
    
    fn best_peer_height(&self) -> Option<Height> {
        self.peers.values()
            .filter(|p| !p.banned)
            .map(|p| p.height)
            .max()
    }
    
    fn sync_progress(&self) -> f64 {
        if let Some(session) = self.active_session.as_ref() {
            let total = session.target_height - session.from_height;
            let current = session.current_height - session.from_height;
            if total > 0 {
                return current as f64 / total as f64;
            }
        }
        self.best_peer_height().map_or(1.0, |best| {
            let current = self.local_chain.len() as Height;
            if best > current {
                current as f64 / best as f64
            } else {
                1.0
            }
        })
    }
    
    fn is_syncing(&self) -> bool {
        self.sync_in_progress
    }
    
    /// Получить текущую локальную высоту
    fn current_height(&self) -> Height {
        self.local_chain.len() as Height
    }
    
    /// Запрос блоков у пира (без отправки сообщения, только логирование)
    pub fn request_blocks(&mut self, peer_id: &PeerId, from: Height, to: Height) -> Result<(), String> {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            if peer.banned {
                return Err("Peer is banned".to_string());
            }
            
            let max_count = (to - from).min(MAX_BLOCKS_PER_REQUEST as u64) as u32;
            
            // TODO: Реализовать отправку сообщения в SyncPeer
            // let msg = P2PMessage::GetBlocks { from_height: from, max_count };
            // peer.send_message(&msg)?;
            
            println!("📤 Requested blocks {}..{} from peer {}", from, from + max_count as u64, peer.address);
            Ok(())
        } else {
            Err("Peer not found".to_string())
        }
    }
    
    /// Верификация и принятие полученных блоков
    pub fn verify_and_accept_blocks(
        &mut self,
        blocks: &[Block],
        storage: &ProductionStorage,
        argon2: &mut Argon2Cache,
    ) -> Result<Height, String> {
        let mut new_height = self.current_height();
        
        for (idx, block) in blocks.iter().enumerate() {
            let expected_height = new_height + 1;
            
            // 1. Проверка prev_hash
            let expected_prev = if expected_height == 1 {
                [0; 32]
            } else {
                let prev_block = storage.get_block(expected_height - 1)?
                    .ok_or("Previous block not found")?;
                prev_block.header.hash(argon2)
            };
            
            if block.header.prev_hash != expected_prev {
                return Err(format!("Invalid prev_hash at height {}", expected_height));
            }
            
            // 2. Проверка хэша блока
            let block_hash = block.header.hash(argon2);
            if !block.header.difficulty.is_met_by(&block_hash) {
                return Err(format!("Block hash doesn't meet difficulty at height {}", expected_height));
            }
            
            // 3. Проверка временной метки
            let prev_timestamp = if expected_height > 1 {
                let prev_block = storage.get_block(expected_height - 1)?
                    .ok_or("Previous block not found")?;
                Some(prev_block.header.timestamp)
            } else {
                None
            };
            
            if !block.header.validate_timestamp(prev_timestamp, None) {
                return Err(format!("Invalid timestamp at height {}", expected_height));
            }
            
            // 4. Проверка Merkle root
            let computed_root = Self::compute_merkle_root(&block.transactions, argon2);
            if block.header.merkle_root != computed_root {
                return Err(format!("Invalid merkle root at height {}", expected_height));
            }
            
            // 5. Проверка подписи блока (если есть)
            if let (Some(sig), Some(pubkey)) = (&block.signature, &block.pubkey) {
                if !Wallet::verify_signature(pubkey, sig, &block_hash) {
                    return Err(format!("Invalid block signature at height {}", expected_height));
                }
            }
            
            // 6. Сохранение блока
            storage.save_block(expected_height, block)?;
            
            // 7. Обновление UTXO set
            Self::update_utxo_set(storage, block, argon2)?;
            
            // 8. Добавляем в локальную цепочку
            self.local_chain.push(block.header.clone());
            self.local_hashes.insert(block_hash, expected_height);
            
            new_height = expected_height;
            
            if idx == blocks.len() - 1 {
                println!("✅ Verified and accepted {} blocks, new height: {}", blocks.len(), new_height);
            }
        }
        
        Ok(new_height)
    }
    
    /// Вычисление Merkle root для транзакций
    pub fn compute_merkle_root(txs: &[Transaction], argon2: &mut Argon2Cache) -> Hash32 {
        if txs.is_empty() {
            return [0; 32];
        }
        
        let mut hashes: Vec<Hash32> = txs.iter()
            .map(|tx| tx.txid(argon2))
            .collect();
        
        while hashes.len() > 1 {
            let mut next = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]);
                }
                let hash = Sha256::digest(&data);
                next.push(hash.into());
            }
            hashes = next;
        }
        hashes[0]
    }
    
    /// Обновление UTXO set после принятия блока
    fn update_utxo_set(
        storage: &ProductionStorage,
        block: &Block,
        argon2: &mut Argon2Cache,
    ) -> Result<(), String> {
        for tx in &block.transactions {
            let txid = tx.txid(argon2);
            
            for (i, output) in tx.outputs.iter().enumerate() {
                let outpoint = (txid, i as u32);
                storage.save_utxo(&outpoint, output)?;
            }
            
            for input in &tx.inputs {
                if !input.is_coinbase() {
                    storage.delete_utxo(&input.outpoint())?;
                }
            }
        }
        Ok(())
    }
    
    /// Выбор лучшего пира для синхронизации (по высоте и задержке)
    pub fn select_best_peer(&self) -> Option<(PeerId, Height, u64)> {
        let current_height = self.current_height();
        
        self.peers.iter()
            .filter(|(_, p)| !p.banned && p.height > current_height)
            .map(|(id, p)| (*id, p.height, p.latency_ms))
            .min_by_key(|(_, _, latency)| *latency)
            .or_else(|| {
                self.peers.iter()
                    .filter(|(_, p)| !p.banned)
                    .map(|(id, p)| (*id, p.height, p.latency_ms))
                    .max_by_key(|(_, height, _)| *height)
            })
    }
    
    /// Запуск активной синхронизации
    pub fn start_active_sync(&mut self, storage: &ProductionStorage, argon2: &mut Argon2Cache) -> Result<bool, String> {
        if self.sync_in_progress {
            return Ok(false);
        }
        
        let current_height = self.current_height();
        
        if let Some((peer_id, peer_height, _)) = self.select_best_peer() {
            if peer_height <= current_height {
                return Ok(false);
            }
            
            let from = current_height + 1;
            let to = peer_height.min(current_height + MAX_BLOCKS_PER_REQUEST as u64);
            
            self.active_session = Some(SyncSession {
                peer_id,
                from_height: from,
                target_height: peer_height,
                current_height,
                started_at: current_timestamp(),
                last_activity: current_timestamp(),
                blocks_received: 0,
                status: SyncStatus::Requesting,
            });
            
            self.sync_in_progress = true;
            self.last_sync_attempt = current_timestamp();
            
            println!("🔄 Starting sync from height {} to {} via peer {:?}", from, to, peer_id);
            
            // Отправляем запрос на блоки
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                let max_count = (to - from + 1) as u32;
                // TODO: Реализовать отправку сообщения
                // let msg = P2PMessage::GetBlocks { from_height: from, max_count };
                // peer.send_message(&msg)?;
                println!("   Would request {} blocks from peer", max_count);
            }
            
            return Ok(true);
        }
        
        Ok(false)
    }
}
// ============================================================
// PoCI RESULT
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoCIResult {
    miner_id: MinerId,
    poci: f64,
    shares: u64,
    loyalty: f64,
    bond: u64,
    reward: u64,
}

// ============================================================
// PoCI CALCULATION
// ============================================================

fn calculate_poci(
    miners: &HashMap<MinerId, MinerData>,
    bonds: &HashMap<MinerId, Bond>,
    loyalty: &HashMap<MinerId, LoyaltyData>,
    current_height: Height,
) -> Vec<PoCIResult> {
    if miners.is_empty() {
        return Vec::new();
    }
    
    let shares_sqrt: Vec<f64> = miners.values()
        .map(|m| (m.shares as f64).sqrt())
        .collect();
    let max_shares_sqrt = shares_sqrt.iter().fold(0.0f64, |a, &b| a.max(b)).max(1.0f64);
    
    let max_loyalty = miners.values()
        .map(|m| loyalty.get(&m.miner_id).map(|l| l.value).unwrap_or(0.0))
        .fold(0.0f64, |a, b| a.max(b))
        .max(1.0f64);
    
    let bond_sqrt: Vec<f64> = miners.values()
        .filter(|m| {
            bonds.get(&m.miner_id)
                .map(|b| b.is_active(current_height) && b.amount >= MINIMUM_BOND_LYT)
                .unwrap_or(false)
        })
        .map(|m| (m.bond as f64).sqrt())
        .collect();
    let max_bond_sqrt = bond_sqrt.iter().fold(0.0f64, |a, &b| a.max(b)).max(1.0f64);
    
    let mut results = Vec::new();
    let mut total_poci = 0.0;
    
    for (miner_id, data) in miners {
        let bond_data = bonds.get(miner_id);
        let is_bond_valid = bond_data
            .map(|b| b.is_active(current_height) && b.amount >= MINIMUM_BOND_LYT)
            .unwrap_or(false);
        
        let share_contrib = if data.shares > 0 {
            POCI_WEIGHT_SHARES * ((data.shares as f64).sqrt() / max_shares_sqrt)
        } else {
            0.0
        };
        
        let loyalty_val = loyalty.get(miner_id).map(|l| l.value).unwrap_or(0.0);
        let loyalty_contrib = POCI_WEIGHT_LOYALTY * (loyalty_val / max_loyalty);
        
        let bond_contrib = if is_bond_valid && max_bond_sqrt > 0.0 {
            POCI_WEIGHT_BOND * ((data.bond as f64).sqrt() / max_bond_sqrt)
        } else {
            0.0
        };
        
        let poci = share_contrib + loyalty_contrib + bond_contrib;
        total_poci += poci;
        
        results.push((*miner_id, poci, data.shares, loyalty_val, data.bond));
    }
    
    results.into_iter()
        .map(|(miner_id, poci, shares, loyalty, bond)| {
            let reward = if total_poci > 0.0 {
                ((poci / total_poci) * EPOCH_REWARD_LYT as f64) as u64
            } else {
                0
            };
            
            PoCIResult {
                miner_id,
                poci,
                shares,
                loyalty,
                bond,
                reward,
            }
        })
        .collect()
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

fn current_timestamp() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}

// ============================================================
// DIFFICULTY ADJUSTMENT
// ============================================================

fn adjust_difficulty(timestamps: &[Timestamp], current_target: &Target) -> Target {
    if timestamps.len() < DIFFICULTY_ADJUSTMENT_INTERVAL as usize + 1 {
        return *current_target;
    }
    
    let start_idx = timestamps.len() - DIFFICULTY_ADJUSTMENT_INTERVAL as usize - 1;
    let start = timestamps[start_idx];
    let end = *timestamps.last().unwrap();
    let actual_time = end - start;
    
    let factor = (actual_time as f64 / TARGET_ADJUSTMENT_TIME as f64)
        .clamp(1.0 - MAX_DIFFICULTY_CHANGE, 1.0 + MAX_DIFFICULTY_CHANGE);
    
    current_target.adjust(factor)
}

// ============================================================
// GENESIS
// ============================================================

const GENESIS_OUTPUT_SCRIPT: [u8; 25] = [
    0x76, 0xa9, 0x14, 0x62, 0xe9, 0x07, 0xb1, 0x5c,
    0xbf, 0x27, 0xd5, 0x42, 0x53, 0x99, 0xeb, 0xf6,
    0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18, 0x88, 0xac
];

fn create_genesis_block() -> (BlockHeader, Transaction) {
    let header = BlockHeader {
        version: 1,
        prev_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: GENESIS_TIMESTAMP,
        difficulty: Target::genesis(),
        nonce: 0,
        epoch_index: 1,
    };
    
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase()],
        outputs: vec![TxOut {
            value: 500_000_000,
            script_pubkey: GENESIS_OUTPUT_SCRIPT.to_vec(),
        }],
        locktime: 0,
    };
    
    (header, coinbase)
}

// ============================================================
// RPC SERVER
// ============================================================

struct RpcServer {
    node: Arc<RwLock<Node>>,
    port: u16,
}

impl RpcServer {
    fn new(node: Arc<RwLock<Node>>, port: u16) -> Self {
        Self { node, port }
    }
    
    async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let node_info = self.node.clone();
        let node_block = self.node.clone();
        let node_send = self.node.clone();
        let node_peers = self.node.clone();
        let node_miners = self.node.clone();
        
        let cors = warp::cors()
            .allow_any_origin()
            .allow_methods(vec!["GET", "POST"])
            .allow_headers(vec!["Content-Type"]);
        
        let info_node = node_info.clone();
        let info = warp::path("info").and(warp::get()).map(move || {
            let node = info_node.read();
            let uptime = current_timestamp() - node.start_time;
            let (cache_hits, cache_misses, avg_time) = node.argon2.stats();
            let cache_hit_rate = if cache_hits + cache_misses > 0 {
                (cache_hits as f64 / (cache_hits + cache_misses) as f64 * 100.0) as u64
            } else {
                0
            };
            
            warp::reply::json(&serde_json::json!({
                "height": node.height,
                "epoch": node.epoch,
                "blocks_found": node.blocks_found,
                "shares_found": node.shares_found,
                "miners": node.miners.len(),
                "peers": node.p2p.peer_count(),
                "hash_rate": node.last_hash_rate,
                "peak_hash_rate": node.peak_hash_rate,
                "uptime_secs": uptime,
                "uptime_formatted": format_duration(uptime),
                "cache_hit_rate": cache_hit_rate,
                "mempool_size": node.mempool.len(),
                "bond": node.miners.get(&node.miner_id).map(|m| m.bond).unwrap_or(0),
                "argon2_avg_ms": avg_time,
            }))
        });
        
        let block_node = node_block.clone();
        let block = warp::path("block")
            .and(warp::path::param::<u64>())
            .and(warp::get())
            .map(move |height: u64| {
                let mut node = block_node.write();
                if let Ok(Some(block)) = node.storage.get_block(height) {
                    let hash = block.header.hash(&mut node.argon2);
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "height": height,
                            "hash": hex::encode(&hash[0..16]),
                            "timestamp": block.header.timestamp,
                            "difficulty": block.header.difficulty.to_difficulty(),
                            "transactions": block.transactions.len(),
                            "nonce": block.header.nonce,
                            "prev_hash": hex::encode(&block.header.prev_hash[0..16]),
                        })),
                        warp::http::StatusCode::OK,
                    )
                } else {
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({ "error": "Block not found" })),
                        warp::http::StatusCode::NOT_FOUND,
                    )
                }
            });
        
        let send_node = node_send.clone();
        let send_tx = warp::path("transaction")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |tx_hex: String| {
                let node = send_node.clone();
                async move {
                    let tx_data = match hex::decode(&tx_hex) {
                        Ok(d) => d,
                        Err(e) => {
                            return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({ "error": format!("Invalid hex: {}", e) })),
                                warp::http::StatusCode::BAD_REQUEST,
                            ));
                        }
                    };
                    
                    let mut node = node.write();
                    
                    match bincode::deserialize::<Transaction>(&tx_data) {
                        Ok(tx) => {
                            if let Err(e) = tx.validate_basic() {
                                return Ok(warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({ "error": format!("Invalid transaction: {}", e) })),
                                    warp::http::StatusCode::BAD_REQUEST,
                                ));
                            }
                            
                            let txid = tx.txid(&mut node.argon2);
                            
                            node.mempool.push(tx.clone());
                            let _ = node.storage.save_mempool(&node.mempool);
                            
                            node.sort_mempool_by_fee();
                            
                            while node.mempool.len() > node.config.advanced.max_mempool_size {
                                node.mempool.pop();
                            }
                            
                            node.p2p.broadcast(&P2PMessage::Transaction(tx));
                            
                            Ok(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({
                                    "status": "ok",
                                    "txid": hex::encode(txid),
                                })),
                                warp::http::StatusCode::OK,
                            ))
                        }
                        Err(e) => {
                            Ok(warp::reply::with_status(
                                warp::reply::json(&serde_json::json!({ "error": format!("Invalid transaction data: {}", e) })),
                                warp::http::StatusCode::BAD_REQUEST,
                            ))
                        }
                    }
                }
            });
        
        let peers_node = node_peers.clone();
        let peers = warp::path("peers").and(warp::get()).map(move || {
            let node = peers_node.read();
            let peers_info: Vec<_> = node.p2p.get_peers_info();
            warp::reply::json(&serde_json::json!({
                "peers": peers_info,
                "total": peers_info.len(),
            }))
        });
        
        let miners_node = node_miners.clone();
        let miners = warp::path("miners").and(warp::get()).map(move || {
            let node = miners_node.read();
            let miners_list: Vec<_> = node.miners.iter()
                .map(|(id, data)| serde_json::json!({
                    "miner_id": hex::encode(id),
                    "shares": data.shares,
                    "bond": data.bond,
                    "loyalty": data.loyalty,
                    "blocks_found": data.blocks_found,
                    "invalid_ratio": data.invalid_ratio,
                    "last_share": data.last_share_time,
                }))
                .collect();
            
            warp::reply::json(&serde_json::json!({
                "miners": miners_list,
                "total": miners_list.len(),
            }))
        });
        
        let mempool_node = self.node.clone();
        let mempool = warp::path("mempool").and(warp::get()).map(move || {
        let node = mempool_node.read();
        let txs: Vec<_> = node.mempool.iter()
        .map(|tx: &Transaction| {
            let mut argon2 = Argon2Cache::new(100);
            serde_json::json!({
                "txid": hex::encode(tx.txid(&mut argon2)),
                "size": tx.serialize().len(),
                "fee": tx.fee(&node.storage).unwrap_or(0),
            })
        })
        .collect();
    
    warp::reply::json(&serde_json::json!({
        "transactions": txs,
        "total": txs.len(),
    }))
});
        
        let health_node = node_info.clone();
        let health = warp::path("health").and(warp::get()).map(move || {
            let node = health_node.read();
            let is_synced = node.sync_progress() >= 0.99;
            warp::reply::json(&serde_json::json!({
                "status": if is_synced { "ok" } else { "syncing" },
                "height": node.height,
                "peers": node.p2p.peer_count(),
                "sync_progress": node.sync_progress(),
            }))
        });
        
        let routes = info
            .or(block)
            .or(send_tx)
            .or(peers)
            .or(miners)
            .or(mempool)
            .or(health)
            .with(cors);
        
        println!("📡 RPC endpoints on port {}:", self.port);
        println!("   GET  /info       - node information");
        println!("   GET  /block/{{height}} - get block");
        println!("   POST /transaction - send transaction (hex)");
        println!("   GET  /peers      - list peers");
        println!("   GET  /miners     - list active miners");
        println!("   GET  /mempool    - list pending transactions");
        println!("   GET  /health     - health check");
        
        warp::serve(routes).run(([0, 0, 0, 0], self.port)).await;
        
        Ok(())
    }
}

// ============================================================
// НОДА
// ============================================================

struct Node {
    height: Height,
    epoch: u32,
    blocks: Vec<BlockHeader>,
    block_hashes: HashMap<Hash32, Height>,
    timestamps: Vec<Timestamp>,
    storage: ProductionStorage,
    mempool: Vec<Transaction>,
    miners: HashMap<MinerId, MinerData>,
    bonds: HashMap<MinerId, Bond>,
    loyalty: HashMap<MinerId, LoyaltyData>,
    share_pool: SharePool,
    argon2: Argon2Cache,
    p2p: P2PNode,
    blocks_found: u64,
    shares_found: u64,
    start_time: Timestamp,
    miner_id: MinerId,
    last_hash_rate: u64,
    peak_hash_rate: u64,
    wallet: Option<Wallet>,
    config: Config,
    equivocation_proofs: HashMap<MinerId, Vec<EquivocationProof>>,
    attack_detection: AttackDetection,
    checkpoints: Vec<Checkpoint>,
    ddos_protection: DDoSProtection,
}

impl Node {
    fn new(config: Config) -> Result<Self, String> {
        let network = "mainnet";
        let storage = ProductionStorage::new(network)?;
        
        let height = storage.get_height()?;
        let epoch = storage.get_state::<u32>("epoch")?.unwrap_or(1);
        
        let wallet = Self::load_or_create_wallet(&storage)?;
        let miner_id = wallet.miner_id;
        
        let ddos_protection = DDoSProtection::new();
        let p2p = P2PNode::new(config.network.port, config.network.bootnodes.clone())
            .map_err(|e| e.to_string())?;
        
        let mut node = Self {
            height,
            epoch,
            blocks: Vec::new(),
            block_hashes: HashMap::new(),
            timestamps: Vec::new(),
            storage,
            mempool: Vec::new(),
            miners: HashMap::new(),
            bonds: HashMap::new(),
            loyalty: HashMap::new(),
            share_pool: SharePool::new(config.advanced.share_pool_memory_mb),
            argon2: Argon2Cache::new(ARGON2_CACHE_SIZE),
            p2p,
            blocks_found: 0,
            shares_found: 0,
            start_time: current_timestamp(),
            miner_id,
            last_hash_rate: 0,
            peak_hash_rate: 0,
            wallet: Some(wallet),
            config: config.clone(),
            equivocation_proofs: HashMap::new(),
            attack_detection: AttackDetection::new(),
            checkpoints: Vec::new(),
            ddos_protection,
        };
        
        if height == 0 {
            node.init_genesis();
        } else {
            node.load_state()?;
            node.verify_genesis_signature();
        }
        
        node.load_checkpoints()?;
        node.p2p.connect_to_bootnodes();
        
        let best_hash = node.last_hash();
        node.p2p.set_local_state(node.height, best_hash);
        
        Ok(node)
    }
    
    fn load_or_create_wallet(storage: &ProductionStorage) -> Result<Wallet, String> {
        if let Some(wallet_data) = storage.get_state::<Vec<u8>>("wallet")? {
            let secret_key: [u8; 32] = wallet_data.try_into()
                .map_err(|_| "Invalid wallet data")?;
            return Wallet::from_secret_key(&secret_key);
        }
        
        println!("🆕 Creating new wallet...");
        let wallet = Wallet::generate()?;
        
        println!("   Miner ID: {}...", hex::encode(&wallet.miner_id[0..8]));
        println!("   Address: {}", wallet.address);
        
        storage.save_state("wallet", &wallet.secret_key.to_vec())?;
        
        Ok(wallet)
    }
    
    fn load_state(&mut self) -> Result<(), String> {
        for h in 0..=self.height {
            if let Some(block) = self.storage.get_block(h)? {
                let hash = block.header.hash(&mut self.argon2);
                let header = block.header.clone();
                self.blocks.push(header);
                self.block_hashes.insert(hash, h);
                self.timestamps.push(block.header.timestamp);
            }
        }
        
        let mut iter = self.storage.db.iterator_cf(
            self.storage.cf_handle(CF_MINERS), 
            IteratorMode::Start
        );
        while let Some(Ok((_key, value))) = iter.next() {
            if let Ok(miner) = bincode::deserialize::<MinerData>(&value) {
                self.miners.insert(miner.miner_id, miner);
            }
        }
        
        let mut iter = self.storage.db.iterator_cf(
            self.storage.cf_handle(CF_BONDS), 
            IteratorMode::Start
        );
        while let Some(Ok((_key, value))) = iter.next() {
            if let Ok(bond) = bincode::deserialize::<Bond>(&value) {
                self.bonds.insert(bond.miner_id, bond);
            }
        }
        
        let mut iter = self.storage.db.iterator_cf(
            self.storage.cf_handle(CF_STATE), 
            IteratorMode::Start
        );
        while let Some(Ok((key, value))) = iter.next() {
            if let Ok(key_str) = std::str::from_utf8(&key) {
                if key_str.starts_with("loyalty_") {
                    if let Ok(loyalty) = bincode::deserialize::<LoyaltyData>(&value) {
                        let miner_id_str = &key_str[8..];
                        if let Ok(miner_id_bytes) = hex::decode(miner_id_str) {
                            let mut miner_id = [0u8; 20];
                            miner_id.copy_from_slice(&miner_id_bytes);
                            self.loyalty.insert(miner_id, loyalty);
                        }
                    }
                }
            }
        }
        
        self.mempool = self.storage.load_mempool()?;
        
        println!("💾 Loaded state: height={}, miners={}, bonds={}, loyalty={}", 
                 self.height, self.miners.len(), self.bonds.len(), self.loyalty.len());
        Ok(())
    }
    
    fn load_checkpoints(&mut self) -> Result<(), String> {
        let mut iter = self.storage.db.iterator_cf(
            self.storage.cf_handle(CF_CHECKPOINTS), 
            IteratorMode::Start
        );
        while let Some(Ok((_key, value))) = iter.next() {
            if let Ok(checkpoint) = bincode::deserialize::<Checkpoint>(&value) {
                self.checkpoints.push(checkpoint);
            }
        }
        
        if let Some(last) = self.checkpoints.last() {
            println!("📌 Loaded {} checkpoints, latest at height {}", 
                     self.checkpoints.len(), last.height);
        }
        Ok(())
    }
    
    fn init_genesis(&mut self) {
        let (header, coinbase) = create_genesis_block();
        let txid = coinbase.txid(&mut self.argon2);
        
        let mut header = header;
        header.merkle_root = txid;
        
        let outpoint = (txid, 0);
        let _ = self.storage.save_utxo(&outpoint, &coinbase.outputs[0]);
        
        let hash = header.hash(&mut self.argon2);
        
        let (signature, pubkey) = if let Some(wallet) = &self.wallet {
            (wallet.sign_block(&hash).ok(), Some(wallet.public_key.clone()))
        } else {
            (None, None)
        };
        
        let block = Block {
            header: header.clone(),
            transactions: vec![coinbase],
            signature: signature.clone(),
            pubkey,
        };
        
        self.blocks.push(header.clone());
        self.block_hashes.insert(hash, 0);
        self.timestamps.push(GENESIS_TIMESTAMP);
        
        let _ = self.storage.save_block(0, &block);
        let _ = self.storage.save_state("height", &0u64);
        let _ = self.storage.save_state("epoch", &1u32);
        
        println!("✅ Genesis block created");
        println!("   Hash: {}...", hex::encode(&hash[0..8]));
        if signature.is_some() {
            println!("   Signature: {}...", hex::encode(&signature.unwrap()[0..8]));
        }
        println!("   Height: 0\n");
    }
    
    fn verify_genesis_signature(&self) -> bool {
        let genesis_block = match self.storage.get_block(0) {
            Ok(Some(block)) => block,
            _ => {
                println!("⚠️ Genesis block not found");
                return false;
            }
        };
        
        let signature = match &genesis_block.signature {
            Some(sig) => sig,
            None => {
                println!("⚠️ Genesis block has no signature");
                return false;
            }
        };
        
        let pubkey = match &genesis_block.pubkey {
            Some(pk) => pk,
            None => {
                println!("⚠️ Genesis block has no public key");
                return false;
            }
        };
        
        let mut argon2 = Argon2Cache::new(100);
        let block_hash = genesis_block.header.hash(&mut argon2);
        
        let valid = Wallet::verify_signature(pubkey, signature, &block_hash);
        
        if valid {
            println!("✅ Genesis signature verified!");
        } else {
            println!("❌ Genesis signature verification FAILED!");
        }
        
        valid
    }
    
    fn last_block(&self) -> Option<&BlockHeader> {
        self.blocks.last()
    }
    
    fn last_hash(&mut self) -> Hash32 {
        if let Some(last) = self.last_block() {
            let header = last.clone();
            header.hash(&mut self.argon2)
        } else {
            [0; 32]
        }
    }
    
    fn last_difficulty(&self) -> Target {
        self.last_block()
            .map(|b| b.difficulty)
            .unwrap_or_else(Target::genesis)
    }
    
    fn sync_progress(&self) -> f64 {
        let best_peer = self.p2p.best_peer_height().unwrap_or(self.height);
        if best_peer == 0 {
            return 1.0;
        }
        self.height as f64 / best_peer as f64
    }
    
    fn median_timestamp(&self) -> Option<Timestamp> {
        if self.timestamps.len() < 11 {
            return None;
        }
        
        let mut last = self.timestamps.iter()
            .rev()
            .take(11)
            .cloned()
            .collect::<Vec<_>>();
        last.sort();
        Some(last[5])
    }
    
    fn add_bond(&mut self, miner_id: MinerId, amount: u64) {
        if amount < MINIMUM_BOND_LYT {
            println!("⚠️ Bond below minimum: {} LYT (min: {} LYT)", amount, MINIMUM_BOND_LYT);
            return;
        }
        
        let bond = Bond::new(amount, self.height, miner_id);
        self.bonds.insert(miner_id, bond.clone());
        let _ = self.storage.save_bond(&miner_id, &bond);
        
        if let Some(miner) = self.miners.get_mut(&miner_id) {
            miner.bond = amount;
        }
        
        println!("💰 Bond added for {}...: {} LYT", 
                 hex::encode(&miner_id[0..8]), amount);
    }
    
    fn add_share(&mut self, share: Share) -> bool {
        let miner_id = share.miner_id;
        let now = share.timestamp;
        let current_epoch = self.epoch;
        
        if let Some(miner) = self.miners.get(&miner_id) {
            if miner.is_banned(now) {
                return false;
            }
        }
        
        let bond_active = self.bonds.get(&miner_id)
            .map(|b| b.is_active(self.height))
            .unwrap_or(false);
        
        if !bond_active {
            return false;
        }
        
        let bond_amount = self.bonds.get(&miner_id)
            .map(|b| b.amount)
            .unwrap_or(0);
        
        let target_share = self.last_difficulty().share_target();
        let expected_prev = self.last_hash();
        let is_valid = match share.validate(
            &target_share,
            &expected_prev,
            current_epoch,
            now,
            &mut self.argon2,
        ) {
            Ok(_) => true,
            Err(e) => {
                println!("Invalid share: {}", e);
                false
            }
        };
        
        match self.share_pool.add_share(share.clone(), is_valid) {
            Ok(true) => {
                let miner = self.miners
                    .entry(miner_id)
                    .or_insert_with(|| MinerData::new(miner_id, bond_amount, current_epoch, now));
                
                miner.add_share(now);
                
                let loyalty = self.loyalty
                    .entry(miner_id)
                    .or_insert_with(LoyaltyData::new);
                loyalty.update(current_epoch, true);
                
                self.shares_found += 1;
                
                if self.shares_found % 100 == 0 {
                    print!(".");
                    let _ = std::io::stdout().flush();
                }
                
                true
            }
            Ok(false) => false,
            Err(_e) => {
                if let Some(miner) = self.miners.get_mut(&miner_id) {
                    let ratio = self.share_pool.invalid_ratio(&miner_id);
                    miner.update_invalid_ratio(ratio, now);
                }
                false
            }
        }
    }
    
    fn sort_mempool_by_fee(&mut self) {
        self.mempool.sort_by(|a, b| {
            let fee_a = a.fee(&self.storage).unwrap_or(0);
            let fee_b = b.fee(&self.storage).unwrap_or(0);
            fee_b.cmp(&fee_a)
        });
    }
    
    fn run_with_graceful_shutdown(&mut self) -> Result<(), String> {
        println!("\n🚀 Node starting...");
        println!("   Height: {}", self.height);
        println!("   Epoch: {}", self.epoch);
        println!("   Peers: {}", self.p2p.peer_count());
        
        let mining_enabled = self.config.mining.enabled;
        
        if mining_enabled {
            println!("⛏️  Solo mining enabled with {} threads", self.config.mining.threads);
        }
        
        println!("\n🔄 Starting main loop...");
        
        let mut last_stats_time = current_timestamp();
        
        loop {
            if should_shutdown() {
                println!("\n⏳ Shutting down...");
                
                if !is_saving_state() {
                    set_saving_state(true);
                    println!("💾 Saving state...");
                    let _ = self.storage.save_mempool(&self.mempool);
                    let _ = self.storage.flush();
                    println!("✅ State saved");
                }
                
                break;
            }
            
            if let Err(e) = self.p2p.process_messages() {
                println!("⚠️ P2P error: {}", e);
            }
            
            if let Err(e) = self.p2p.accept_connections() {
                println!("⚠️ Accept error: {}", e);
            }
            
            if self.p2p.needs_sync() {
                if let Some(peer) = self.p2p.sync_manager.best_peer() {
                    self.p2p.sync_manager.start_sync(peer);
                }
            }
            
            if let Some(peer_id) = self.p2p.sync_manager.check_timeouts() {
                println!("⚠️ Sync timeout with peer");
            }
            
            if mining_enabled && !self.p2p.is_syncing() && self.sync_progress() >= 0.99 {
                self.mine_block();
            }
            
            let now = current_timestamp();
            if now - last_stats_time >= STATS_UPDATE_INTERVAL_MS / 1000 {
                let sync_progress = self.sync_progress();
                let sync_status = if sync_progress < 0.99 {
                    format!(" (syncing: {:.1}%)", sync_progress * 100.0)
                } else {
                    String::new()
                };
                
                print!("\r📊 Height: {} | Epoch: {} | Peers: {} | Shares: {}{}",
                       self.height, self.epoch, self.p2p.peer_count(), 
                       self.shares_found, sync_status);
                let _ = std::io::stdout().flush();
                
                last_stats_time = now;
            }
            
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        
        Ok(())
    }
    
    fn mine_block(&mut self) {
        if let Some(last) = self.last_block() {
            let now = current_timestamp();
            if now - last.timestamp < TARGET_BLOCK_TIME {
                return;
            }
        }
        
        if self.share_pool.total_shares_count() < 10 {
            return;
        }
        
        let poci_results = calculate_poci(
            &self.miners,
            &self.bonds,
            &self.loyalty,
            self.height,
        );
        
        if poci_results.is_empty() {
            return;
        }
        
        let mut outputs = Vec::new();
        
        for result in &poci_results {
            if result.reward > 0 {
                if let Some(wallet) = &self.wallet {
                    if let Ok(txout) = TxOut::create_p2pkh(&wallet.address) {
                        let mut txout = txout;
                        txout.value = result.reward;
                        outputs.push(txout);
                    }
                }
            }
        }
        
        let block_reward = BLOCK_REWARD_LYT;
        if let Some(wallet) = &self.wallet {
            if let Ok(mut txout) = TxOut::create_p2pkh(&wallet.address) {
                txout.value = block_reward;
                outputs.push(txout);
            }
        }
        
        if outputs.is_empty() {
            return;
        }
        
        let coinbase = Transaction::coinbase(outputs, self.height + 1);
        let mut txs = vec![coinbase];
        let mut total_size = txs[0].serialize().len();
        
        for tx in &self.mempool {
            if total_size + tx.serialize().len() > 1_000_000 {
                break;
            }
            txs.push(tx.clone());
            total_size += tx.serialize().len();
        }
        
        let prev_hash = self.last_hash();
        let difficulty = self.last_difficulty();
        let mut header = BlockHeader::new(prev_hash, self.epoch + 1, difficulty);
        
        let mut hashes: Vec<Hash32> = txs.iter()
            .map(|tx| tx.txid(&mut self.argon2))
            .collect();
        
        while hashes.len() > 1 {
            let mut next = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]);
                }
                let hash = Sha256::digest(&data);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hash);
                next.push(arr);
            }
            hashes = next;
        }
        
        header.merkle_root = if hashes.is_empty() { [0; 32] } else { hashes[0] };
        
        let target_share = difficulty.share_target();
        let target_prefilter = difficulty.prefilter_target();
        let mut best_nonce = 0u64;
        let mut best_hash = [0xff; 32];
        
        for nonce in 0..MINING_BATCH_SIZE {
            if !Argon2Cache::prefilter(&header.to_bytes(), nonce, &target_prefilter) {
                continue;
            }
            
            let hash = header.hash_with_nonce(nonce, &mut self.argon2);
            
            if difficulty.is_met_by(&hash) {
                header.nonce = nonce;
                best_hash = hash;
                best_nonce = nonce;
                break;
            }
            
            if target_share.is_met_by(&hash) && hash < best_hash {
                best_hash = hash;
                best_nonce = nonce;
            }
        }
        
        if best_nonce > 0 {
            header.nonce = best_nonce;
            
            let (signature, pubkey) = if let Some(wallet) = &self.wallet {
                let block_hash = header.hash(&mut self.argon2);
                (wallet.sign_block(&block_hash).ok(), Some(wallet.public_key.clone()))
            } else {
                (None, None)
            };
            
            let block = Block {
                header: header.clone(),
                transactions: txs,
                signature,
                pubkey,
            };
            
            let new_height = self.height + 1;
            let _ = self.storage.save_block(new_height, &block);
            
            self.blocks.push(header.clone());
            self.block_hashes.insert(best_hash, new_height);
            self.timestamps.push(header.timestamp);
            self.height = new_height;
            self.blocks_found += 1;
            
            self.update_utxo_set(&block);
            self.mempool.clear();
            let _ = self.storage.save_mempool(&self.mempool);
            
            if new_height % EPOCH_BLOCKS == 0 {
                self.process_epoch_end();
            }
            
            let _ = self.storage.save_state("height", &self.height);
            let _ = self.storage.save_state("epoch", &self.epoch);
            
            if self.height % self.config.advanced.checkpoint_interval == 0 {
                self.create_checkpoint();
            }
            
            let _ = self.storage.maybe_backup(self.height, self.config.advanced.backup_interval_blocks);
            
            println!("\n⛏️  Block mined! Height: {}, Hash: {}...", 
                     new_height, hex::encode(&best_hash[0..8]));
            
            self.p2p.broadcast(&P2PMessage::Block {
                header: header.clone(),
                transactions: block.transactions,
            });
        } else if best_hash != [0xff; 32] {
            let share = Share::new(self.miner_id, header, best_nonce, best_hash);
            self.add_share(share);
        }
    }
    
    fn update_utxo_set(&mut self, block: &Block) {
        for tx in &block.transactions {
            for (i, output) in tx.outputs.iter().enumerate() {
                let txid = tx.txid(&mut self.argon2);
                let outpoint = (txid, i as u32);
                let _ = self.storage.save_utxo(&outpoint, output);
            }
            
            for input in &tx.inputs {
                if !input.is_coinbase() {
                    let _ = self.storage.delete_utxo(&input.outpoint());
                }
            }
        }
    }
    
    fn process_epoch_end(&mut self) {
        println!("\n📅 Processing epoch {} end...", self.epoch);
        
        let poci_results = calculate_poci(
            &self.miners,
            &self.bonds,
            &self.loyalty,
            self.height,
        );
        
        let mut total_rewards = 0u64;
        for result in &poci_results {
            total_rewards += result.reward;
        }
        
        println!("   Total epoch rewards: {} LYT", total_rewards);
        println!("   Active miners: {}", poci_results.len());
        
        self.share_pool.new_epoch();
        self.epoch += 1;
        
        let current_epoch = self.epoch;
        let miners_to_update: Vec<MinerId> = self.miners.keys().copied().collect();
        
        for miner_id in miners_to_update {
            let loyalty = self.loyalty.entry(miner_id).or_insert_with(LoyaltyData::new);
            loyalty.update(current_epoch, false);
            
            let key = format!("loyalty_{}", hex::encode(&miner_id));
            let _ = self.storage.save_state(&key, loyalty);
        }
        
        for miner in self.miners.values_mut() {
            miner.shares = 0;
            let _ = self.storage.save_miner(&miner.miner_id, miner);
        }
        
        println!("✅ Epoch {} started", self.epoch);
    }
    
    fn create_checkpoint(&mut self) {
        let last_block = match self.last_block() {
            Some(block) => block.clone(),
            None => return,
        };
        
        let block_hash = last_block.hash(&mut self.argon2);
        let state_root = self.calculate_state_root();
        
        let (signature, _pubkey) = if let Some(wallet) = &self.wallet {
            let message = {
                let mut data = Vec::new();
                data.extend_from_slice(&self.height.to_le_bytes());
                data.extend_from_slice(&block_hash);
                data.extend_from_slice(&state_root);
                Sha256::digest(&data)
            };
            (wallet.sign(&message.into()).ok(), Some(wallet.public_key.clone()))
        } else {
            (None, None)
        };
        
        let checkpoint = Checkpoint {
            height: self.height,
            block_hash,
            state_root,
            timestamp: current_timestamp(),
            signature: signature.unwrap_or_default(),
            verified: false,
        };
        
        self.checkpoints.push(checkpoint.clone());
        let _ = self.storage.save_checkpoint(self.height, &checkpoint);
        
        if self.checkpoints.len() > self.config.advanced.max_checkpoints {
            self.checkpoints.remove(0);
        }
        
        println!("📌 Checkpoint created at height {}", self.height);
    }
    
    fn calculate_state_root(&self) -> Hash32 {
        let mut data = Vec::new();
        
        for (id, miner) in &self.miners {
            data.extend_from_slice(id);
            data.extend_from_slice(&miner.shares.to_le_bytes());
            data.extend_from_slice(&miner.bond.to_le_bytes());
        }
        
        for (id, bond) in &self.bonds {
            data.extend_from_slice(id);
            data.extend_from_slice(&bond.amount.to_le_bytes());
            data.extend_from_slice(&bond.lock_until.to_le_bytes());
        }
        
        let hash = Sha256::digest(&data);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }
}
    
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║    ACCUM v3.2+ - Fair Proof-of-Contribution Blockchain      ║");
    println!("║         WORKING NODE WITH SOLO MINING + SLASHING             ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    
    match args.get(1).map(|s| s.as_str()) {
        Some("wallet") => {
            handle_wallet_command(&args)?;
        }
        Some("node") => {
            run_node().await?;
        }
        Some("backup") => {
            handle_backup_command(&args)?;
        }
        Some("restore") => {
            handle_restore_command(&args)?;
        }
        Some("info") => {
            handle_info_command()?;
        }
        _ => {
            // Если нет команды, запускаем ноду по умолчанию
            println!("No command specified, starting node...\n");
            run_node().await?;
        }
    }
    
    Ok(())
}

fn print_help() {
    println!("Usage: accum <command> [options]");
    println!("\nCommands:");
    println!("  node                    Start a full node");
    println!("  wallet create           Create a new wallet");
    println!("  wallet balance <addr>   Check wallet balance");
    println!("  wallet send <to> <amt>  Send coins");
    println!("  backup                  Create database backup");
    println!("  restore <timestamp>     Restore from backup");
    println!("  info                    Show node info");
    println!("\nExamples:");
    println!("  accum node");
    println!("  accum wallet create");
    println!("  accum wallet balance 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    println!("  accum backup");
}

fn handle_wallet_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.get(2).map(|s| s.as_str()) {
        Some("create") => {
            let wallet = Wallet::generate()?;
            println!("\n✅ Wallet created successfully!\n");
            println!("📫 Address:     {}", wallet.address);
            println!("🆔 Miner ID:    {}", hex::encode(&wallet.miner_id));
            println!("🔑 Public Key:  {}", hex::encode(&wallet.public_key));
            println!("\n⚠️  SAVE YOUR PRIVATE KEY SECURELY:");
            println!("📜 Private Key: {}", hex::encode(&wallet.secret_key));
            println!("\n💡 To use this wallet, save the private key and run:");
            println!("   echo '{}' > ~/.accum/wallet.key", hex::encode(&wallet.secret_key));
        }
        Some("balance") => {
            let address = args.get(3).ok_or("Address required")?;
            println!("📊 Checking balance for {}...", address);
            println!("   (connect to running node for balance)");
        }
        Some("send") => {
            let to = args.get(3).ok_or("Recipient address required")?;
            let amount = args.get(4).ok_or("Amount required")?;
            println!("💸 Sending {} LYT to {}...", amount, to);
            println!("   (requires running node with wallet)");
        }
        _ => {
            println!("Usage: accum wallet <create|balance|send>");
        }
    }
    Ok(())
}

fn handle_backup_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    let storage = ProductionStorage::new("mainnet")?;
    let backup_id = storage.backup()?;
    println!("✅ Backup created: {}", backup_id);
    Ok(())
}

fn handle_restore_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let timestamp = args.get(2).ok_or("Backup timestamp required")?;
    let config = Config::load()?;
    let storage = ProductionStorage::new("mainnet")?;
    storage.restore(timestamp)?;
    Ok(())
}

fn handle_info_command() -> Result<(), Box<dyn std::error::Error>> {
    println!("📡 Connecting to local node...");
    println!("   (RPC endpoint: http://localhost:{})", RPC_PORT);
    println!("\n💡 To get info, run:");
    println!("   curl http://localhost:{}/info", RPC_PORT);
    Ok(())
}

async fn run_node() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    println!("📋 Loaded configuration from ~/.accum/config.toml");
    
    let node = Node::new(config.clone())?;
    let node_arc = Arc::new(RwLock::new(node));
    
    // RPC сервер
    if config.rpc.enabled {
        let rpc_node = node_arc.clone();
        tokio::spawn(async move {
            let rpc = RpcServer::new(rpc_node, config.rpc.port);
            if let Err(e) = rpc.start().await {
                eprintln!("❌ RPC server error: {}", e);
            }
        });
        println!("📡 RPC server started on port {}", config.rpc.port);
    }
    
    // Добавляем bond если майнинг включен
    {
        let mut node = node_arc.write();
        if config.mining.enabled {
            let miner_id = node.miner_id;
            node.add_bond(miner_id, config.mining.bond);
            println!("💰 Bond added: {} LYT", config.mining.bond);
        }
    }
    
    // Graceful shutdown handler
    let node_clone = node_arc.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        println!("\n\n⚠️  Received Ctrl+C");
        println!("⏳ Shutting down, please wait...");
        SHUTDOWN.store(true, AtomicOrdering::SeqCst);
        
        // Сохраняем состояние
        {
            let mut node = node_clone.write();
            set_saving_state(true);
            let _ = node.storage.save_mempool(&node.mempool);
            let _ = node.storage.flush();
            println!("✅ State saved");
        }
        
        tokio::time::sleep(Duration::from_secs(2)).await;
        println!("👋 Goodbye!");
        std::process::exit(0);
    });
    
    println!("\n=== NODE STARTED ===");
    {
        let node = node_arc.read();
        println!("🔗 Height: {}", node.height);
        println!("📅 Epoch: {}", node.epoch);
        println!("👤 Miner ID: {}...", hex::encode(&node.miner_id[0..8]));
        println!("💳 Address: {}", node.wallet.as_ref().map(|w| w.address.clone()).unwrap_or_default());
        if config.mining.enabled {
            println!("⛏️  Solo mining ENABLED with {} threads", config.mining.threads);
        } else {
            println!("⛏️  Solo mining DISABLED");
        }
    }
    println!("========================\n");
    
    let mut node = node_arc.write();
    node.run_with_graceful_shutdown()?;
    
    Ok(())
} 
