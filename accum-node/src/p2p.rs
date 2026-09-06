//! P2P protocol messages and handling for ACCUM protocol
//! Strictly following ACCUM v3.2+ specification

use crate::block::Block;
use crate::error::Error;
use crate::share::SharePacket;
use crate::types::{Hash32, MinerId};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Version handshake message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMessage {
    pub version: u32,
    pub capabilities: u64,
    pub timestamp: u64,
    pub user_agent: String,
    pub start_height: u64,
    pub nonce: u64,
}

/// Inventory type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InvType {
    Block = 0,
    Transaction = 1,
    Share = 2,
}

/// Inventory item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvItem {
    pub inv_type: InvType,
    pub hash: Hash32,
}

/// Inventory message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvMessage {
    pub items: Vec<InvItem>,
}

/// GetData message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDataMessage {
    pub items: Vec<InvItem>,
}

/// Block message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMessage {
    pub block: Block,
}

/// Transaction message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxMessage {
    pub tx: Vec<u8>,
}

/// Share message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareMessage {
    pub share: SharePacket,
}

/// Epoch commit message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCommitMessage {
    pub epoch_index: u32,
    pub root: Hash32,
    pub timestamp: u64,
}

/// GetShares request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSharesMessage {
    pub epoch_index: u32,
    pub miner_id_list: Vec<MinerId>,
    pub offset: u32,
}

/// Shares reply
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharesReplyMessage {
    pub shares_batch: Vec<SharePacket>,
}

/// Compact block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactBlockMessage {
    pub header_hash: Hash32,
    pub nonce: u64,
    pub short_ids: Vec<u64>,
    pub prefilled_txs: Vec<usize>,
}

/// Ping message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingMessage {
    pub nonce: u64,
}

/// Pong message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongMessage {
    pub nonce: u64,
}

/// All possible P2P messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    Version(VersionMessage),
    Verack,
    Inv(InvMessage),
    GetData(GetDataMessage),
    Block(BlockMessage),
    Tx(TxMessage),
    Share(ShareMessage),
    EpochCommit(EpochCommitMessage),
    GetShares(GetSharesMessage),
    SharesReply(SharesReplyMessage),
    CompactBlock(CompactBlockMessage),
    Ping(PingMessage),
    Pong(PongMessage),
}

/// Peer connection state
#[derive(Debug, Clone)]
pub struct Peer {
    pub peer_id: PeerId,
    pub address: String,
    pub version: Option<VersionMessage>,
    pub connected_at: u64,
    pub last_seen: u64,
    pub share_count: u32,
    pub last_share_time: u64,
    pub ban_until: u64,
    pub misbehavior_count: u32,
}

impl Peer {
    /// Create new peer
    pub fn new(peer_id: PeerId, address: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            peer_id,
            address,
            version: None,
            connected_at: now,
            last_seen: now,
            share_count: 0,
            last_share_time: 0,
            ban_until: 0,
            misbehavior_count: 0,
        }
    }

    /// Check if peer is banned
    pub fn is_banned(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.ban_until > now
    }

    /// Ban peer for minutes
    pub fn ban(&mut self, minutes: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.ban_until = now + minutes * 60;
    }

    /// Record share reception
    pub fn record_share(&mut self) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if now - self.last_share_time >= 60 {
            self.share_count = 0;
        }
        
        if self.share_count >= 100 {
            self.ban(5);
            return Err(Error::P2p);
        }
        
        self.share_count += 1;
        self.last_share_time = now;
        self.last_seen = now;
        
        Ok(())
    }

    /// Update last seen
    pub fn seen(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_seen = now;
    }
}

/// P2P network manager
#[derive(Debug)]
pub struct P2PManager {
    pub peers: HashMap<PeerId, Peer>,
    max_peers: usize,
    message_history: Vec<(u64, PeerId, P2PMessage)>,
    max_history: usize,
    known_addresses: Vec<String>,
}

impl P2PManager {
    /// Create new P2P manager
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
            message_history: Vec::new(),
            max_history: 1000,
            known_addresses: Vec::new(),
        }
    }

    /// Add or update peer
    pub fn add_peer(&mut self, peer_id: PeerId, address: String) {
        if self.peers.len() >= self.max_peers {
            if let Some(oldest) = self.find_oldest_peer() {
                self.peers.remove(&oldest);
            }
        }
        
        let address_for_peer = address.clone();
        let address_for_list = address;
        
        self.peers.entry(peer_id)
            .or_insert_with(|| Peer::new(peer_id, address_for_peer));
        
        if !self.known_addresses.contains(&address_for_list) {
            self.known_addresses.push(address_for_list);
        }
    }

    /// Find oldest peer by last_seen
    fn find_oldest_peer(&self) -> Option<PeerId> {
        let mut oldest = None;
        let mut oldest_time = u64::MAX;
        
        for (id, peer) in &self.peers {
            if peer.last_seen < oldest_time {
                oldest_time = peer.last_seen;
                oldest = Some(*id);
            }
        }
        
        oldest
    }

    /// Process incoming message
    pub fn process_message(&mut self, from: PeerId, msg: P2PMessage) -> Result<Option<P2PMessage>, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if let Some(peer) = self.peers.get_mut(&from) {
            if peer.is_banned() {
                return Err(Error::P2p);
            }
            peer.seen();
        } else {
            return Err(Error::P2p);
        }
        
        self.message_history.push((now, from, msg.clone()));
        if self.message_history.len() > self.max_history {
            self.message_history.remove(0);
        }
        
        match msg {
            P2PMessage::Version(version) => {
                self.handle_version(from, version)
            }
            P2PMessage::Verack => Ok(None),
            P2PMessage::Inv(inv) => self.handle_inv(from, inv),
            P2PMessage::GetData(getdata) => self.handle_getdata(from, getdata),
            P2PMessage::Share(share) => self.handle_share(from, share),
            P2PMessage::Ping(ping) => {
                Ok(Some(P2PMessage::Pong(PongMessage { nonce: ping.nonce })))
            }
            P2PMessage::Pong(_) => Ok(None),
            P2PMessage::GetShares(gets) => self.handle_getshares(from, gets),
            P2PMessage::SharesReply(reply) => self.handle_sharesreply(from, reply),
            P2PMessage::EpochCommit(commit) => self.handle_epochcommit(from, commit),
            _ => Ok(None),
        }
    }

    fn handle_version(&mut self, from: PeerId, version: VersionMessage) -> Result<Option<P2PMessage>, Error> {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.version = Some(version);
            peer.seen();
        }
        Ok(Some(P2PMessage::Verack))
    }

    fn handle_inv(&mut self, _from: PeerId, inv: InvMessage) -> Result<Option<P2PMessage>, Error> {
        let mut to_request = Vec::new();
        for item in inv.items {
            to_request.push(item);
        }
        
        if !to_request.is_empty() {
            Ok(Some(P2PMessage::GetData(GetDataMessage { items: to_request })))
        } else {
            Ok(None)
        }
    }

    fn handle_getdata(&mut self, _from: PeerId, _getdata: GetDataMessage) -> Result<Option<P2PMessage>, Error> {
        Ok(None)
    }

    fn handle_share(&mut self, from: PeerId, _share: ShareMessage) -> Result<Option<P2PMessage>, Error> {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.record_share()?;
        }
        Ok(None)
    }

    fn handle_getshares(&mut self, _from: PeerId, _gets: GetSharesMessage) -> Result<Option<P2PMessage>, Error> {
        Ok(None)
    }

    fn handle_sharesreply(&mut self, _from: PeerId, _reply: SharesReplyMessage) -> Result<Option<P2PMessage>, Error> {
        Ok(None)
    }

    fn handle_epochcommit(&mut self, _from: PeerId, _commit: EpochCommitMessage) -> Result<Option<P2PMessage>, Error> {
        Ok(None)
    }

    /// Broadcast message to all peers
    pub fn broadcast(&self, msg: P2PMessage) -> Vec<(PeerId, P2PMessage)> {
        let mut broadcasts = Vec::new();
        
        for (id, peer) in &self.peers {
            if !peer.is_banned() {
                broadcasts.push((*id, msg.clone()));
            }
        }
        
        broadcasts
    }

    /// Send message to specific peer
    pub fn send_to(&self, peer_id: PeerId, msg: P2PMessage) -> Option<(PeerId, P2PMessage)> {
        if let Some(peer) = self.peers.get(&peer_id) {
            if !peer.is_banned() {
                return Some((peer_id, msg));
            }
        }
        None
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get banned peers
    pub fn banned_peers(&self) -> Vec<PeerId> {
        self.peers.iter()
            .filter(|(_, p)| p.is_banned())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get known addresses
    pub fn known_addresses(&self) -> &Vec<String> {
        &self.known_addresses
    }

    /// Clean up old peers
    pub fn cleanup(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.peers.retain(|_, peer| now - peer.last_seen < 3600);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_peer_id() -> PeerId {
        PeerId::random()
    }
    
    #[test]
    fn test_peer_rate_limit() {
        let peer_id = create_test_peer_id();
        let mut peer = Peer::new(peer_id, "127.0.0.1:8333".to_string());
        
        for _ in 0..100 {
            assert!(peer.record_share().is_ok());
        }
        
        assert!(peer.record_share().is_err());
        assert!(peer.is_banned());
    }
    
    #[test]
    fn test_p2p_manager() {
        let mut manager = P2PManager::new(10);
        let peer_id = create_test_peer_id();
        
        manager.add_peer(peer_id, "127.0.0.1:8333".to_string());
        assert_eq!(manager.peer_count(), 1);
        
        let version = VersionMessage {
            version: 1,
            capabilities: 0,
            timestamp: 1741353600,
            user_agent: "ACCUM node".to_string(),
            start_height: 0,
            nonce: 12345,
        };
        
        let response = manager.process_message(
            peer_id,
            P2PMessage::Version(version)
        ).unwrap();
        
        assert!(matches!(response, Some(P2PMessage::Verack)));
    }
}