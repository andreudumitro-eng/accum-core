//! RocksDB storage for ACCUM blockchain

use crate::block::Block;
use crate::error::Error;
use crate::miner::{BondEntry, MinerInfo};
use crate::pool::EpochCommit;
use crate::share::SharePacket;
use crate::types::{Hash32, Height, MinerId};
use rocksdb::{DB, Options, IteratorMode, ColumnFamily}; // <-- добавили ColumnFamily
use serde::{Serialize, Deserialize};
use std::path::Path;

/// Storage column families (separate data spaces)
pub enum Column {
    Blocks,      // blocks by height
    Shares,      // archived shares
    Miners,      // miner info
    Bonds,       // bond entries
    Peers,       // peer info
    Epochs,      // epoch commits
    State,       // current state
}

impl Column {
    /// Get column family name
    pub fn name(&self) -> &'static str {
        match self {
            Column::Blocks => "blocks",
            Column::Shares => "shares",
            Column::Miners => "miners",
            Column::Bonds => "bonds",
            Column::Peers => "peers",
            Column::Epochs => "epochs",
            Column::State => "state",
        }
    }
}

/// Main storage manager for ACCUM
pub struct Storage {
    db: DB,
}

impl Storage {
    /// Open or create database at specified path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        
        // Define column families
        let cf_names = vec![
            Column::Blocks.name(),
            Column::Shares.name(),
            Column::Miners.name(),
            Column::Bonds.name(),
            Column::Peers.name(),
            Column::Epochs.name(),
            Column::State.name(),
        ];
        
        // Open DB with column families
        let db = DB::open_cf(&opts, path, cf_names)
            .map_err(|e| {
                eprintln!("Failed to open database: {}", e);
                Error::Storage
            })?;
        
        Ok(Self { db })
    }
        /// Alias for open() for convenience
        pub fn new(path: &str) -> Result<Self, Error> {
            Self::open(path)
        }
    
    /// Get column family handle
    fn cf(&self, column: Column) -> &ColumnFamily {  // <-- ИЗМЕНЕНО
        self.db.cf_handle(column.name())
            .expect("Column family should exist")
    }
    
    /// Save block to storage
    pub fn save_block(&self, height: Height, block: &Block) -> Result<(), Error> {
        let key = format!("b:{}", height).into_bytes();
        let value = bincode::serialize(block)
            .map_err(|_| Error::Storage)?;
        
        self.db.put_cf(self.cf(Column::Blocks), key, value)
            .map_err(|_| Error::Storage)?;
        
        Ok(())
    }
    
    /// Get block by height
    pub fn get_block(&self, height: Height) -> Result<Option<Block>, Error> {
        let key = format!("b:{}", height).into_bytes();
        
        match self.db.get_cf(self.cf(Column::Blocks), &key) {
            Ok(Some(data)) => {
                let block = bincode::deserialize(&data)
                    .map_err(|_| Error::Storage)?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(Error::Storage),
        }
    }
    
    /// Save share to archive
    pub fn save_share(&self, epoch: u32, miner_id: MinerId, share: &SharePacket) -> Result<(), Error> {
        let key = format!("s:{}:{:?}:{}", epoch, miner_id, hex::encode(share.hash)).into_bytes();
        let value = bincode::serialize(share)
            .map_err(|_| Error::Storage)?;
        
        self.db.put_cf(self.cf(Column::Shares), key, value)
            .map_err(|_| Error::Storage)?;
        
        Ok(())
    }
    
    /// Save miner info
    pub fn save_miner(&self, miner_id: MinerId, info: &MinerInfo) -> Result<(), Error> {
        let key = format!("m:{:?}", miner_id).into_bytes();
        let value = bincode::serialize(info)
            .map_err(|_| Error::Storage)?;
        
        self.db.put_cf(self.cf(Column::Miners), key, value)
            .map_err(|_| Error::Storage)?;
        
        Ok(())
    }
    
    /// Get miner info
    pub fn get_miner(&self, miner_id: MinerId) -> Result<Option<MinerInfo>, Error> {
        let key = format!("m:{:?}", miner_id).into_bytes();
        
        match self.db.get_cf(self.cf(Column::Miners), &key) {
            Ok(Some(data)) => {
                let info = bincode::deserialize(&data)
                    .map_err(|_| Error::Storage)?;
                Ok(Some(info))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(Error::Storage),
        }
    }
    
    /// Save bond entry
    pub fn save_bond(&self, miner_id: MinerId, txid: Hash32, bond: &BondEntry) -> Result<(), Error> {
        let key = format!("bond:{:?}:{:?}", miner_id, txid).into_bytes();
        let value = bincode::serialize(bond)
            .map_err(|_| Error::Storage)?;
        
        self.db.put_cf(self.cf(Column::Bonds), key, value)
            .map_err(|_| Error::Storage)?;
        
        Ok(())
    }
    
    /// Save epoch commit
    pub fn save_epoch_commit(&self, epoch: u32, commit: &EpochCommit) -> Result<(), Error> {
        let key = format!("e:{}", epoch).into_bytes();
        let value = bincode::serialize(commit)
            .map_err(|_| Error::Storage)?;
        
        self.db.put_cf(self.cf(Column::Epochs), key, value)
            .map_err(|_| Error::Storage)?;
        
        Ok(())
    }
    
    /// Get epoch commit
    pub fn get_epoch_commit(&self, epoch: u32) -> Result<Option<EpochCommit>, Error> {
        let key = format!("e:{}", epoch).into_bytes();
        
        match self.db.get_cf(self.cf(Column::Epochs), &key) {
            Ok(Some(data)) => {
                let commit = bincode::deserialize(&data)
                    .map_err(|_| Error::Storage)?;
                Ok(Some(commit))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(Error::Storage),
        }
    }
    
    /// Save current state value
    pub fn save_state(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        self.db.put_cf(self.cf(Column::State), key.as_bytes(), value)
            .map_err(|_| Error::Storage)?;
        Ok(())
    }
    
    /// Get current state value
    pub fn get_state(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        self.db.get_cf(self.cf(Column::State), key.as_bytes())
            .map_err(|_| Error::Storage)
    }
    
    /// Get all miners from storage
    pub fn get_all_miners(&self) -> Result<Vec<(MinerId, MinerInfo)>, Error> {
        let cf = self.cf(Column::Miners);
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        let mut miners = Vec::new();
        
        for item in iter {
            let (key, value) = item.map_err(|_| Error::Storage)?;
            
            // Parse key to get miner_id (skip 'm:' prefix)
            if key.starts_with(b"m:") {
                if let Ok(info) = bincode::deserialize::<MinerInfo>(&value) {
                    miners.push((info.miner_id, info));
                }
            }
        }
        
        Ok(miners)
    }
    
    /// Flush all writes to disk
    pub fn flush(&self) -> Result<(), Error> {
        self.db.flush().map_err(|_| Error::Storage)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::open(temp_dir.path()).unwrap();
        
        // Just verify it opens
        assert!(true);
    }
    
    #[test]
    fn test_save_get_block() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::open(temp_dir.path()).unwrap();
        
        // Create dummy block
        use crate::block::BlockHeader;
        use crate::types::Target;
        
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1741353600,
            difficulty: Target([0xFF; 32]),
            nonce: 0,
            epoch_index: 1,
        };
        
        let block = Block {
            header,
            transactions: vec![],
        };
        
        storage.save_block(0, &block).unwrap();
        let retrieved = storage.get_block(0).unwrap().unwrap();
        
        assert_eq!(retrieved.header.version, block.header.version);
    }
}