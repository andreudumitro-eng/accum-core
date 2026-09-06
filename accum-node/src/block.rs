//! Block structures and validation for ACCUM protocol
//! Strictly following ACCUM v3.2+ specification

use crate::constants::*;
use crate::crypto::argon2id_hash;
use crate::error::Error;
use crate::types::{Hash32, Target};
use crate::transaction::{Transaction, TxIn, TxOut}; // ИМПОРТ из transaction.rs
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Block header (120 bytes, little-endian) as per specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_hash: Hash32,
    pub merkle_root: Hash32,
    pub timestamp: u64,
    pub difficulty: Target,
    pub nonce: u64,
    pub epoch_index: u32,
}

impl BlockHeader {
    /// Convert header to bytes (exactly 120 bytes, little-endian)
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(120);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.prev_hash);
        bytes.extend_from_slice(&self.merkle_root);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.difficulty.0);
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.epoch_index.to_le_bytes());
        
        debug_assert_eq!(bytes.len(), 120, "Header must be exactly 120 bytes");
        bytes
    }

    /// Alias for as_bytes() - used by share.rs
    pub fn serialize(&self) -> Vec<u8> {
        self.as_bytes()
    }

    /// Deserialize from bytes (must be exactly 120 bytes)
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 120 {
            return Err(Error::InvalidHeaderLength);
        }

        let mut offset = 0;

        let version = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let timestamp = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let mut difficulty = [0u8; 32];
        difficulty.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let nonce = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let epoch_index = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());

        Ok(Self {
            version,
            prev_hash,
            merkle_root,
            timestamp,
            difficulty: Target(difficulty),
            nonce,
            epoch_index,
        })
    }

    /// Compute block hash using Argon2id
    pub fn hash(&self) -> Hash32 {
        argon2id_hash(&self.as_bytes())
    }

    /// Compute hash with specific nonce (for shares)
    pub fn hash_with_nonce(&self, nonce: u64) -> Hash32 {
        let mut header = self.clone();
        header.nonce = nonce;
        header.hash()
    }

    /// Check if hash meets target (PoW valid)
    pub fn meets_target(&self, target: &Target) -> bool {
        let hash = self.hash();
        for i in 0..32 {
            if hash[i] < target.0[i] {
                return true;
            }
            if hash[i] > target.0[i] {
                return false;
            }
        }
        true // equal is also valid
    }

    /// Basic timestamp validation per spec
    pub fn validate_timestamp(&self, prev_timestamp: Option<u64>) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Not too far in future (max 2 hours)
        if self.timestamp > now + 7200 {
            return Err(Error::InvalidTimestamp);
        }

        // Must be after previous block timestamp
        if let Some(prev) = prev_timestamp {
            if self.timestamp <= prev {
                return Err(Error::InvalidTimestamp);
            }
        }

        Ok(())
    }

    /// Validate against chain tip (for shares)
    pub fn is_current(&self, tip_prev_hash: &Hash32) -> bool {
        self.prev_hash == *tip_prev_hash
    }
}

/// Full block with transactions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>, // ТЕПЕРЬ ИСПОЛЬЗУЕТ Transaction из transaction.rs
}

impl Block {
    /// Calculate block hash
    pub fn hash(&self) -> Hash32 {
        self.header.hash()
    }

    /// Calculate merkle root from transactions
    pub fn calculate_merkle_root(&self) -> Hash32 {
        if self.transactions.is_empty() {
            return [0u8; 32];
        }
        
        let mut hashes: Vec<Hash32> = self.transactions.iter()
            .map(|tx| tx.txid())
            .collect();
        
        // Build merkle tree (simplified - just double SHA256 for now)
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut data = Vec::new();
                data.extend_from_slice(&chunk[0]);
                if chunk.len() == 2 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]); // Duplicate if odd
                }
                
                use sha2::{Sha256, Digest};
                let hash = Sha256::digest(&data);
                let mut result = [0u8; 32];
                result.copy_from_slice(&hash);
                next_level.push(result);
            }
            hashes = next_level;
        }
        
        hashes[0]
    }

    /// Validate block
    pub fn validate(&self, prev_block: Option<&Block>) -> Result<(), Error> {
        // Check height
        if let Some(prev) = prev_block {
            if self.header.prev_hash != prev.hash() {
                return Err(Error::InvalidPrevHash);
            }
        }

        // Check PoW
        if !self.header.meets_target(&self.header.difficulty) {
            return Err(Error::InvalidPoW);
        }

        // Check timestamp
        let prev_time = prev_block.map(|b| b.header.timestamp);
        self.header.validate_timestamp(prev_time)?;

        // Check merkle root
        let calculated_root = self.calculate_merkle_root();
        if calculated_root != self.header.merkle_root {
            return Err(Error::InvalidMerkleRoot);
        }

        // Check coinbase transaction (first transaction must be coinbase)
        if self.transactions.is_empty() || !self.transactions[0].is_coinbase() {
            return Err(Error::InvalidCoinbase);
        }

        // Check no other coinbase transactions
        for tx in self.transactions.iter().skip(1) {
            if tx.is_coinbase() {
                return Err(Error::InvalidCoinbase);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialization() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1741353600,
            difficulty: Target([0xFF; 32]),
            nonce: 12345,
            epoch_index: 1,
        };

        let bytes = header.serialize();
        assert_eq!(bytes.len(), 120);

        let deserialized = BlockHeader::deserialize(&bytes).unwrap();
        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_hash_with_nonce() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1741353600,
            difficulty: Target([0xFF; 32]),
            nonce: 0,
            epoch_index: 1,
        };

        let hash1 = header.hash_with_nonce(100);
        let hash2 = header.hash_with_nonce(200);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_meets_target() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1741353600,
            difficulty: Target([0xFF; 32]), // Max difficulty
            nonce: 0,
            epoch_index: 1,
        };

        // With max difficulty, hash should be less than or equal
        assert!(header.meets_target(&header.difficulty));
    }

    #[test]
    fn test_merkle_root() {
        // Создадим простую тестовую транзакцию
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            locktime: 0,
        };
        
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 1741353600,
                difficulty: Target([0xFF; 32]),
                nonce: 0,
                epoch_index: 1,
            },
            transactions: vec![tx],
        };
        
        let root = block.calculate_merkle_root();
        assert_ne!(root, [0u8; 32]);
    }
}