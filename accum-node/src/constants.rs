//! Protocol constants for ACCUM v3.2+

// Monetary
pub const LYATORS_PER_ACM: u64 = 10_000_000;
pub const MAX_SUPPLY_ACM: u64 = 150_000_000;
pub const MAX_SUPPLY_LYT: u64 = 1_500_000_000_000_000;
pub const BLOCK_REWARD_LYT: u64 = 500_000;
pub const EPOCH_REWARD_LYT: u64 = 720_000_000;

// Time
pub const TARGET_BLOCK_TIME: u64 = 60;
pub const EPOCH_BLOCKS: u64 = 1_440;
pub const EPOCH_DURATION: u64 = 86_400;
pub const GENESIS_TIMESTAMP: u64 = 1741353600; // 2026-03-09 00:00:00 UTC

// Fees & Dust
pub const MINIMUM_FEE_LYT: u64 = 50;
pub const DUST_LIMIT_LYT: u64 = 100;

// Bond
pub const MINIMUM_BOND_LYT: u64 = 10_000_000;
pub const BOND_LOCKUP_BLOCKS: u64 = 20_160;

// Proof-of-Work
pub const ARGON2_MEMORY: u32 = 268_435_456;  // 256 MiB
pub const ARGON2_ITERATIONS: u32 = 2;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const ARGON2_VERSION: u32 = 0x13;
pub const ARGON2_HASH_LEN: usize = 32;

// PoCI Weights
pub const POCI_WEIGHT_SHARES: f64 = 0.6;
pub const POCI_WEIGHT_LOYALTY: f64 = 0.2;
pub const POCI_WEIGHT_BOND: f64 = 0.2;

// Share Limits
pub const MAX_SHARES_PER_MINER_PER_EPOCH: u32 = 5000;
pub const MAX_SHARES_PER_PEER_PER_MINUTE: u32 = 100;
pub const INVALID_SHARE_BAN_THRESHOLD: f64 = 0.3;
pub const INVALID_SHARE_WARN_THRESHOLD: f64 = 0.1;

// Difficulty
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 120;
pub const TARGET_ADJUSTMENT_TIME: u64 = 7_200; // 120 blocks * 60 seconds
pub const MAX_DIFFICULTY_CHANGE: f64 = 0.25; // ±25%

// Governance
pub const PHASE_1_BLOCKS: u64 = 100_000;
pub const PHASE_2_BLOCKS: u64 = 400_000;
pub const PHASE_3_BLOCKS: u64 = 500_001;
pub const VALIDATOR_COUNCIL_SIZE: usize = 7;
pub const SECURITY_COUNCIL_SIZE: usize = 9;
pub const SECURITY_COUNCIL_QUORUM: usize = 6;