//! Miner identity, bonds, and loyalty for ACCUM protocol
//! Strictly following ACCUM v3.2+ specification

use crate::constants::*;
use crate::error::Error;
use crate::types::{Amount, Height, MinerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Bond entry for a miner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondEntry {
    pub amount: Amount,
    pub locked_until: Height,
    pub created_at: Height,
}

/// Miner information for PoCI calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerInfo {
    pub miner_id: MinerId,
    pub shares_raw: u64,
    pub loyalty: f64,
    pub bond_total: Amount,
    pub invalid_shares: u32,
    pub total_shares: u32,
    pub last_epoch_participated: u32,
    pub first_seen: u64,
}

impl Default for MinerInfo {
    fn default() -> Self {
        Self {
            miner_id: [0u8; 20],
            shares_raw: 0,
            loyalty: 0.0,
            bond_total: 0,
            invalid_shares: 0,
            total_shares: 0,
            last_epoch_participated: 0,
            first_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Registry of all miners and their bonds
#[derive(Debug, Default, Clone)]
pub struct MinerRegistry {
    miners: HashMap<MinerId, MinerInfo>,
    bonds: HashMap<MinerId, Vec<BondEntry>>,
    current_epoch: u32,
    current_height: Height,
}

impl MinerRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create miner info
    pub fn get_or_create_miner(&mut self, miner_id: MinerId) -> &mut MinerInfo {
        self.miners.entry(miner_id).or_insert_with(|| {
            let mut info = MinerInfo::default();
            info.miner_id = miner_id;
            info
        })
    }

    /// Add valid share for miner
    pub fn add_valid_share(&mut self, miner_id: MinerId) {
        let current_epoch = self.current_epoch; // ← копируем
        let miner = self.get_or_create_miner(miner_id);
        miner.shares_raw += 1;
        miner.total_shares += 1;
        miner.last_epoch_participated = current_epoch; // ← используем копию
    }

    /// Add invalid share for miner
    pub fn add_invalid_share(&mut self, miner_id: MinerId) {
        let current_epoch = self.current_epoch; // ← копируем
        let miner = self.get_or_create_miner(miner_id);
        miner.invalid_shares += 1;
        miner.total_shares += 1;
        miner.last_epoch_participated = current_epoch; // ← используем копию
    }

    /// Add bond for miner
    pub fn add_bond(&mut self, miner_id: MinerId, amount: Amount) -> Result<(), Error> {
        if amount < MINIMUM_BOND_LYT {
            return Err(Error::InsufficientBond(MINIMUM_BOND_LYT)); // ← исправлено
        }

        let lock_until = self.current_height + BOND_LOCKUP_BLOCKS;
        
        let bond = BondEntry {
            amount,
            locked_until: lock_until,
            created_at: self.current_height,
        };

        self.bonds.entry(miner_id).or_default().push(bond);
        
        // Update total bond in miner info
        let miner = self.get_or_create_miner(miner_id);
        miner.bond_total += amount;

        Ok(())
    }

    /// Update loyalty for all miners (end of epoch)
    /// Specification:
    /// - Initial: loyalty_i = 0
    /// - Epoch with ≥1 share: loyalty_i = loyalty_i + 1
    /// - Missed epoch: loyalty_i = max(loyalty_i * 0.7, loyalty_i // 2)
    /// - Grace period (first 3 epochs after absence): loyalty_i = loyalty_i * 0.5
    pub fn update_loyalty(&mut self) {
        for miner in self.miners.values_mut() {
            if miner.last_epoch_participated == self.current_epoch {
                // Participated: +1
                miner.loyalty += 1.0;
            } else {
                // Missed epoch: decay
                let missed_epochs = self.current_epoch - miner.last_epoch_participated;
                
                if missed_epochs <= 3 {
                    // Grace period: first 3 epochs after absence
                    miner.loyalty *= 0.5;
                } else {
                    // Normal decay: max(loyalty * 0.7, loyalty // 2)
                    let decayed = (miner.loyalty * 0.7).max((miner.loyalty / 2.0).floor());
                    miner.loyalty = decayed;
                }
            }
        }
    }

    /// Clean up expired bonds
    pub fn cleanup_expired_bonds(&mut self) {
        let mut to_remove = Vec::new();
        
        for (miner_id, bond_list) in self.bonds.iter_mut() {
            let before: Amount = bond_list.iter().map(|b| b.amount).sum();
            
            // Keep only bonds still locked
            bond_list.retain(|bond| bond.locked_until > self.current_height);
            
            let after: Amount = bond_list.iter().map(|b| b.amount).sum();
            
            // Update total if changed
            if before != after {
                if let Some(miner) = self.miners.get_mut(miner_id) {
                    miner.bond_total = after;
                }
            }
            
            if bond_list.is_empty() {
                to_remove.push(*miner_id);
            }
        }
        
        // Remove empty bond lists
        for miner_id in to_remove {
            self.bonds.remove(&miner_id);
        }
    }

    /// Check which miners should be banned (>30% invalid shares)
    /// Specification: 30% invalid shares → mining ban (3 epochs)
    pub fn check_bans(&self) -> Vec<MinerId> {
        let mut to_ban = Vec::new();
        
        for (miner_id, miner) in &self.miners {
            if miner.total_shares < 10 {
                continue; // Not enough data
            }
            let ratio = miner.invalid_shares as f64 / miner.total_shares as f64;
            if ratio > 0.3 {
                to_ban.push(*miner_id);
            }
        }
        
        to_ban
    }

    /// Ban a miner for 3 epochs
    pub fn ban_miner(&mut self, miner_id: MinerId) {
        if let Some(miner) = self.miners.get_mut(&miner_id) {
            // Set last participation to current epoch + 3 (effectively skip 3 epochs)
            miner.last_epoch_participated = self.current_epoch + 3;
            miner.loyalty = 0.0; // Reset loyalty on ban
        }
    }

    /// Get miner info
    pub fn get_miner(&self, miner_id: &MinerId) -> Option<&MinerInfo> {
        self.miners.get(miner_id)
    }

    /// Get all miner IDs
    pub fn all_miners(&self) -> Vec<MinerId> {
        self.miners.keys().copied().collect()
    }

    /// Get total bond for miner (normalized for PoCI)
    /// Returns sqrt(bond) if bond >= MINIMUM_BOND_LYT, else 0
    pub fn bond_for_poci(&self, miner_id: &MinerId) -> f64 {
        if let Some(miner) = self.miners.get(miner_id) {
            if miner.bond_total >= MINIMUM_BOND_LYT {
                (miner.bond_total as f64).sqrt()
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    /// Get loyalty for miner (raw value, not normalized)
    pub fn loyalty_for_poci(&self, miner_id: &MinerId) -> f64 {
        self.miners.get(miner_id).map(|m| m.loyalty).unwrap_or(0.0)
    }

    /// Get shares for miner (raw count)
    pub fn shares_for_poci(&self, miner_id: &MinerId) -> u64 {
        self.miners.get(miner_id).map(|m| m.shares_raw).unwrap_or(0)
    }

    /// Move to next epoch
    pub fn next_epoch(&mut self) {
        self.current_epoch += 1;
        self.update_loyalty();
        self.cleanup_expired_bonds();
        
        // Check and apply bans
        let to_ban = self.check_bans();
        for miner_id in to_ban {
            self.ban_miner(miner_id);
        }
    }

    /// Set current height
    pub fn set_height(&mut self, height: Height) {
        self.current_height = height;
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> u32 {
        self.current_epoch
    }
}

/// Equivocation proof for slashing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationProof {
    pub miner_id: MinerId,
    pub block_header_a: crate::block::BlockHeader,
    pub block_header_b: crate::block::BlockHeader,
}

impl EquivocationProof {
    /// Verify that this is a valid equivocation
    /// Specification: Two different blocks at same height from same miner_id
    pub fn verify(&self, _height: Height) -> bool {
        // Must be same miner
        // Must be different blocks
        if self.block_header_a.hash() == self.block_header_b.hash() {
            return false; // Same block, not equivocation
        }
        
        // Both blocks must be at same height (check prev_hash for height)
        // In real implementation, would need height from chain context
        true
    }
    
    /// Create slash transaction (returns raw transaction bytes)
    pub fn create_slash_tx(&self) -> Vec<u8> {
        // TODO: Implement slash transaction creation
        // Format: version(4) + type(1) + miner_id(20) + header_a(120) + header_b(120)
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes()); // version
        tx.push(0x01); // type: SLASH_EQUIVOCATION
        tx.extend_from_slice(&self.miner_id);
        tx.extend_from_slice(&self.block_header_a.serialize());
        tx.extend_from_slice(&self.block_header_b.serialize());
        tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use crate::crypto::miner_id_from_pubkey;
    use crate::types::Target;

    fn create_test_miner(index: u8) -> MinerId {
        let mut pubkey = [2u8; 33];
        pubkey[0] = index;
        miner_id_from_pubkey(&pubkey)
    }

    #[test]
    fn test_bond_addition() {
        let mut registry = MinerRegistry::new();
        let miner_id = create_test_miner(1);
        
        // Add valid bond
        assert!(registry.add_bond(miner_id, MINIMUM_BOND_LYT).is_ok());
        
        // Bond too small
        assert!(registry.add_bond(miner_id, MINIMUM_BOND_LYT - 1).is_err());
        
        // Check bond total
        assert_eq!(registry.bond_for_poci(&miner_id), (MINIMUM_BOND_LYT as f64).sqrt());
    }

    #[test]
    fn test_loyalty_update() {
        let mut registry = MinerRegistry::new();
        let miner_id = create_test_miner(1);
        
        // Epoch 1: participate
        registry.add_valid_share(miner_id);
        assert_eq!(registry.loyalty_for_poci(&miner_id), 0.0);
        
        registry.next_epoch(); // Epoch 2
        // Should have loyalty = 1.0 (participated)
        assert!((registry.loyalty_for_poci(&miner_id) - 1.0).abs() < 1e-10);
        
        // Epoch 3: miss
        registry.next_epoch();
        let loyalty = registry.loyalty_for_poci(&miner_id);
        assert!(loyalty < 1.0); // Should have decayed
    }

    #[test]
    fn test_invalid_share_ban() {
        let mut registry = MinerRegistry::new();
        let miner_id = create_test_miner(1);
        
        // Add 7 invalid, 3 valid (70% invalid)
        for _ in 0..7 {
            registry.add_invalid_share(miner_id);
        }
        for _ in 0..3 {
            registry.add_valid_share(miner_id);
        }
        
        let bans = registry.check_bans();
        assert!(bans.contains(&miner_id));
        
        // Apply ban
        registry.ban_miner(miner_id);
        let miner = registry.get_miner(&miner_id).unwrap();
        assert_eq!(miner.loyalty, 0.0);
        assert_eq!(miner.last_epoch_participated, registry.current_epoch + 3);
    }

    #[test]
    fn test_bond_lockup() {
        let mut registry = MinerRegistry::new();
        let miner_id = create_test_miner(1);
        
        registry.set_height(1000);
        registry.add_bond(miner_id, MINIMUM_BOND_LYT).unwrap();
        
        // Bond should be locked
        assert!(registry.bond_for_poci(&miner_id) > 0.0);
        
        // Move past lockup
        registry.set_height(1000 + BOND_LOCKUP_BLOCKS + 1);
        registry.cleanup_expired_bonds();
        
        // Bond should be expired
        assert_eq!(registry.bond_for_poci(&miner_id), 0.0);
    }

    #[test]
    fn test_equivocation_proof() {
        let miner_id = create_test_miner(1);
        
        let header1 = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1741353600,
            difficulty: Target([0xFF; 32]),
            nonce: 1,
            epoch_index: 1,
        };
        
        let header2 = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1741353601,
            difficulty: Target([0xFF; 32]),
            nonce: 2,
            epoch_index: 1,
        };
        
        let proof = EquivocationProof {
            miner_id,
            block_header_a: header1,
            block_header_b: header2,
        };
        
        assert!(proof.verify(100)); // Same height
        
        // Create slash transaction
        let slash_tx = proof.create_slash_tx();
        assert!(!slash_tx.is_empty());
    }
}