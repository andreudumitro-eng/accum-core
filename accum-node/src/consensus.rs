//! Proof-of-Contribution Index (PoCI) and reward distribution
//! Strictly following ACCUM v3.2+ specification

use crate::constants::*;
use crate::miner::MinerRegistry;
use crate::share::EpochShares;  // ← ИСПРАВЛЕНО
use crate::types::{Amount, MinerId};
use std::collections::HashMap;

/// PoCI calculator for an epoch
pub struct PoCICalculator<'a> {
    epoch_shares: &'a EpochShares,
    miner_registry: &'a MinerRegistry,
}

impl<'a> PoCICalculator<'a> {
    /// Create new PoCI calculator for an epoch
    pub fn new(epoch_shares: &'a EpochShares, miner_registry: &'a MinerRegistry) -> Self {
        Self {
            epoch_shares,
            miner_registry,
        }
    }

    /// Get all active miners in this epoch
    pub fn active_miners(&self) -> Vec<MinerId> {
        self.epoch_shares.miners()
    }

    /// Calculate normalized shares: norm_shares_i = sqrt(shares_raw) / max_sqrt_in_epoch
    pub fn normalized_shares(&self) -> HashMap<MinerId, f64> {
        let mut result = HashMap::new();
        let miners = self.active_miners();
        
        if miners.is_empty() {
            return result;
        }

        // Calculate sqrt for each miner
        let mut sqrt_values = Vec::new();
        for miner_id in &miners {
            let shares = self.epoch_shares.miner_share_count(miner_id) as f64;
            sqrt_values.push(shares.sqrt());
        }

        // Find max sqrt
        let max_sqrt = sqrt_values.iter().fold(0.0_f64, |a, &b| a.max(b));
        
        if max_sqrt == 0.0 {
            return result;
        }

        // Normalize
        for (i, miner_id) in miners.iter().enumerate() {
            result.insert(*miner_id, sqrt_values[i] / max_sqrt);
        }

        result
    }

    /// Calculate normalized loyalty: norm_loyalty_i = loyalty_i / max_loyalty_in_epoch
    pub fn normalized_loyalty(&self) -> HashMap<MinerId, f64> {
        let mut result = HashMap::new();
        let miners = self.active_miners();
        
        if miners.is_empty() {
            return result;
        }

        // Get loyalty values
        let mut loyalty_values = Vec::new();
        for miner_id in &miners {
            let loyalty = self.miner_registry.loyalty_for_poci(miner_id);
            loyalty_values.push(loyalty);
        }

        // Find max loyalty
        let max_loyalty = loyalty_values.iter().fold(0.0_f64, |a, &b| a.max(b));
        
        if max_loyalty == 0.0 {
            return result;
        }

        // Normalize
        for (i, miner_id) in miners.iter().enumerate() {
            result.insert(*miner_id, loyalty_values[i] / max_loyalty);
        }

        result
    }

    /// Calculate normalized bond: 
    /// if bond >= MINIMUM_BOND_LYT: sqrt(bond) / max_sqrt_bond
    /// else: 0
    pub fn normalized_bond(&self) -> HashMap<MinerId, f64> {
        let mut result = HashMap::new();
        let miners = self.active_miners();
        
        if miners.is_empty() {
            return result;
        }

        // Calculate sqrt bond for each miner (only if >= MINIMUM_BOND_LYT)
        let mut sqrt_values = Vec::new();
        for miner_id in &miners {
            let bond = self.miner_registry.bond_for_poci(miner_id);
            if bond >= MINIMUM_BOND_LYT as f64 {
                sqrt_values.push(bond.sqrt());
            } else {
                sqrt_values.push(0.0);
            }
        }

        // Find max sqrt bond
        let max_sqrt = sqrt_values.iter().fold(0.0_f64, |a, &b| a.max(b));
        
        if max_sqrt == 0.0 {
            return result;
        }

        // Normalize
        for (i, miner_id) in miners.iter().enumerate() {
            result.insert(*miner_id, sqrt_values[i] / max_sqrt);
        }

        result
    }

    /// Calculate PoCI for all miners
    /// PoCI_i = 0.6 × norm_shares_i + 0.2 × norm_loyalty_i + 0.2 × norm_bond_i
    pub fn calculate_poci(&self) -> HashMap<MinerId, f64> {
        let norm_shares = self.normalized_shares();
        let norm_loyalty = self.normalized_loyalty();
        let norm_bond = self.normalized_bond();

        let mut poci = HashMap::new();
        let miners = self.active_miners();

        for miner_id in miners {
            let shares = norm_shares.get(&miner_id).unwrap_or(&0.0);
            let loyalty = norm_loyalty.get(&miner_id).unwrap_or(&0.0);
            let bond = norm_bond.get(&miner_id).unwrap_or(&0.0);

            // PoCI = 0.6*shares + 0.2*loyalty + 0.2*bond
            let value = POCI_WEIGHT_SHARES * shares
                + POCI_WEIGHT_LOYALTY * loyalty
                + POCI_WEIGHT_BOND * bond;

            poci.insert(miner_id, value);
        }

        poci
    }

    /// Calculate rewards based on PoCI
    /// reward_i = (PoCI_i / sum_PoCI) × (EPOCH_REWARD_LYT + tx_fees)
    pub fn calculate_rewards(&self, poci: &HashMap<MinerId, f64>, tx_fees: Amount) -> HashMap<MinerId, Amount> {
        let mut rewards = HashMap::new();
        
        // Sum all PoCI values
        let sum_poci: f64 = poci.values().sum();
        
        if sum_poci == 0.0 {
            return rewards;
        }

        let total_reward = (EPOCH_REWARD_LYT as f64) + (tx_fees as f64);

        // Calculate rewards
        for (miner_id, &value) in poci {
            let reward = ((value / sum_poci) * total_reward) as Amount;
            rewards.insert(*miner_id, reward);
        }

        rewards
    }

    /// Full epoch reward calculation
    pub fn calculate_epoch_rewards(&self, tx_fees: Amount) -> HashMap<MinerId, Amount> {
        let poci = self.calculate_poci();
        self.calculate_rewards(&poci, tx_fees)
    }
}