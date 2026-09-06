//! Реальный P2P сетевой слой на libp2p с интеграцией P2PManager

use crate::block::Block;
use crate::p2p::{self, P2PManager, P2PMessage, VersionMessage};
use crate::storage::Storage;
use crate::error::Error;
use futures::StreamExt;
use libp2p::{
    core::upgrade,
    gossipsub,
    identity,
    kad,
    noise,
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp, Multiaddr, PeerId, Transport,
};
use std::error::Error as StdError;
use std::sync::Arc;
use tokio::sync::mpsc;

const NETWORK_NAME: &[u8] = b"accum-network-v1";

/// События сети, которые обрабатывает нода
#[derive(Debug)]
pub enum NetworkEvent {
    NewBlock(Block),
    NewPeer(PeerId),
    PeerDisconnected(PeerId),
}

/// Поведение нашей сети (комбинация протоколов)
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "AccumBehaviourEvent")]
pub struct AccumBehaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
}

/// События от поведения
#[derive(Debug)]
pub enum AccumBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Kad(kad::Event),
}

impl From<gossipsub::Event> for AccumBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        AccumBehaviourEvent::Gossipsub(event)
    }
}

impl From<kad::Event> for AccumBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        AccumBehaviourEvent::Kad(event)
    }
}

impl AccumBehaviour {
    pub fn new(local_peer_id: PeerId) -> Result<Self, Box<dyn StdError + Send + Sync>> {
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| format!("Gossipsub config error: {}", e))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(identity::Keypair::generate_ed25519()),
            gossipsub_config,
        ).map_err(|e| format!("Gossipsub error: {}", e))?;

        let kad = kad::Behaviour::new(
            local_peer_id,
            kad::store::MemoryStore::new(local_peer_id),
        );

        Ok(Self { gossipsub, kad })
    }
}

/// Наша P2P нода
pub struct P2PNode {
    swarm: Swarm<AccumBehaviour>,
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    event_receiver: mpsc::UnboundedReceiver<NetworkEvent>,
    peer_manager: P2PManager,
    storage: Arc<Storage>,
}

impl P2PNode {
    /// Создать новую P2P ноду
    pub async fn new(storage: Arc<Storage>) -> Result<Self, Box<dyn StdError + Send + Sync>> {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        println!("Local peer id: {}", local_peer_id);

        let transport = tcp::tokio::Transport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&local_key)?)
            .multiplex(libp2p::yamux::Config::default())
            .boxed();

        let behaviour = AccumBehaviour::new(local_peer_id)?;

        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor()
        );

        Ok(Self {
            swarm,
            event_sender,
            event_receiver,
            peer_manager: P2PManager::new(50),
            storage,
        })
    }

    /// Запустить ноду и слушать на указанном адресе
    pub async fn start(&mut self, listen_addr: &str) -> Result<(), Box<dyn StdError + Send + Sync>> {
        let addr: Multiaddr = listen_addr.parse()?;
        self.swarm.listen_on(addr)?;
        println!("Listening on: {}", listen_addr);
        Ok(())
    }

    /// Подключиться к другой ноде
    pub async fn dial(&mut self, addr: Multiaddr) -> Result<(), Box<dyn StdError + Send + Sync>> {
        self.swarm.dial(addr)?;
        Ok(())
    }

    /// Отправить сообщение конкретному пиру
    fn send_to_peer(&mut self, peer_id: PeerId, message: P2PMessage) {
        if let Some((_target_id, msg_data)) = self.peer_manager.send_to(peer_id, message) {
            let topic = gossipsub::IdentTopic::new("p2p".to_string());
            let data = bincode::serialize(&msg_data).unwrap_or_default();
            let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, data);
        }
    }

    /// Опубликовать блок в сеть (Gossipsub)
    pub async fn publish_block(&mut self, block: &Block) -> Result<(), Box<dyn StdError + Send + Sync>> {
        let topic = gossipsub::IdentTopic::new("blocks".to_string());
        let data = bincode::serialize(block)?;
        self.swarm.behaviour_mut().gossipsub.publish(topic, data)?;
        
        // Также рассылаем инвентарь через P2PManager
        let inv_item = p2p::InvItem {
            inv_type: p2p::InvType::Block,
            hash: block.header.hash(),
        };
        let inv_msg = P2PMessage::Inv(p2p::InvMessage {
            items: vec![inv_item],
        });
        
        for (peer_id, _) in self.peer_manager.broadcast(inv_msg.clone()) {
            self.send_to_peer(peer_id, inv_msg.clone());
        }
        
        Ok(())
    }
    
        /// Подключиться к bootnodes
        pub async fn connect_to_bootnodes(&mut self, bootnodes: Vec<String>) {
            for addr_str in bootnodes {
                if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                    println!("🔄 Подключаюсь к bootnode: {}", addr_str);
                    let _ = self.dial(addr).await;
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                } else {
                    eprintln!("❌ Неверный адрес bootnode: {}", addr_str);
                }
            }
        }

    /// Получить receiver для событий сети
    pub fn event_receiver(&mut self) -> &mut mpsc::UnboundedReceiver<NetworkEvent> {
        &mut self.event_receiver
    }

    /// Запустить главный цикл обработки событий сети
    pub async fn run(&mut self) -> Result<(), Box<dyn StdError + Send + Sync>> {
        let blocks_topic = gossipsub::IdentTopic::new("blocks".to_string());
        let p2p_topic = gossipsub::IdentTopic::new("p2p".to_string());

        self.swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic)?;
        self.swarm.behaviour_mut().gossipsub.subscribe(&p2p_topic)?;

        println!("P2P node is running...");
        println!("🔥 P2P DEBUG: Starting run loop");
        println!("📡 Subscribed to topics: blocks and p2p");
        println!("🔍 Local peer ID: {}", self.swarm.local_peer_id());

        loop {
            tokio::select! {
                Some(event) = self.swarm.next() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Listening on {}", address);
                        }
                        SwarmEvent::Behaviour(AccumBehaviourEvent::Gossipsub(gossipsub::Event::Message { 
                            propagation_source: source,
                            message_id: _,
                            message,
                        })) => {
                            // Проверяем, не забанен ли отправитель
                            if let Some(peer) = self.peer_manager.peers.get(&source) {
                                if peer.is_banned() {
                                    continue;
                                }
                            }

                            // Определяем топик сообщения
                            if message.topic == blocks_topic.hash() {
                                // Получили новый блок
                                if let Ok(block) = bincode::deserialize::<Block>(&message.data) {
                                    println!("Received new block from {}: {}...", source, &hex::encode(&block.header.hash()[0..4]));
                                    
                                    if let Err(e) = self.storage.save_block(block.header.nonce as u64, &block) {
                                        eprintln!("Failed to save block: {}", e);
                                    } else {
                                        let _ = self.event_sender.send(NetworkEvent::NewBlock(block));
                                    }
                                }
                            } else if message.topic == p2p_topic.hash() {
                                // Получили P2P сообщение
                                if let Ok(p2p_msg) = bincode::deserialize::<P2PMessage>(&message.data) {
                                    // Обрабатываем через P2PManager
                                    match self.peer_manager.process_message(source, p2p_msg) {
                                        Ok(Some(response)) => {
                                            // Отправляем ответ
                                            self.send_to_peer(source, response);
                                        }
                                        Ok(None) => {}
                                        Err(e) => {
                                            eprintln!("Error processing P2P message: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(AccumBehaviourEvent::Kad(kad_event)) => {
                            // Здесь можно обрабатывать Kademlia события для discovery
                            match kad_event {
                                kad::Event::RoutingUpdated { peer, .. } => {
                                    println!("Kademlia: discovered peer {}", peer);
                                    let addr = format!("{}", peer);
                                    self.peer_manager.add_peer(peer, addr);
                                }
                                _ => {}
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            println!("✅🔥 P2P CONNECTION ESTABLISHED with peer: {}", peer_id);
                            println!("Connected to peer: {}", peer_id);
                            
                            // Добавляем пира в менеджер
                            let addr = format!("{}", peer_id);
                            self.peer_manager.add_peer(peer_id, addr);
                            
                            // Отправляем Version сообщение
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            
                            let version = VersionMessage {
                                version: 1,
                                capabilities: 0,
                                timestamp: now,
                                user_agent: "ACCUM node".to_string(),
                                start_height: 0, // TODO: получить из storage
                                nonce: rand::random::<u64>(),
                            };
                            
                            self.send_to_peer(peer_id, P2PMessage::Version(version));
                            
                            let _ = self.event_sender.send(NetworkEvent::NewPeer(peer_id));
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            println!("Disconnected from peer: {}", peer_id);
                            let _ = self.event_sender.send(NetworkEvent::PeerDisconnected(peer_id));
                        }
                        _ => {}
                    }
                }
                else => break,
            }
            
            // Периодическая очистка старых пиров
            self.peer_manager.cleanup();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_p2p_node_creation() {
        let dir = tempdir().unwrap();
        let storage = Arc::new(Storage::new(dir.path().to_str().unwrap()).unwrap());
        
        let node = P2PNode::new(storage).await;
        assert!(node.is_ok());
    }
}