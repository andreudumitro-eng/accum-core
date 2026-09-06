//! JSON-RPC API для ACCUM ноды

use crate::block::Block;
use crate::transaction::Transaction;
use crate::types::{Hash32, Height};
use crate::Node;
use axum::{
    extract::State,
    routing::post,
    Json,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Vec<serde_json::Value>,
    pub id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<RpcError>,
    pub id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

pub struct RpcServer {
    node: Arc<Mutex<Node>>,
    port: u16,
}

impl RpcServer {
    pub fn new(node: Arc<Mutex<Node>>, port: u16) -> Self {
        Self { node, port }
    }
    
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            .route("/", post(handle_rpc))
            .with_state(self.node.clone());
        
        let addr = format!("0.0.0.0:{}", self.port);
        println!("📡 RPC API слушает на {}", addr);
        
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        
        Ok(())
    }
}

async fn handle_rpc(
    State(node): State<Arc<Mutex<Node>>>,
    Json(req): Json<RpcRequest>,
) -> Json<RpcResponse> {
    match req.method.as_str() {
        "getblock" => {
            let params = req.params;
            if params.is_empty() {
                return error_response(-32602, "Missing height", req.id);
            }
            
            let height: Height = match params[0].as_u64() {
                Some(h) => h,
                None => return error_response(-32602, "Invalid height", req.id),
            };
            
            let response = serde_json::json!({
                "height": height,
                "hash": "0x...",
            });
            
            Json(RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(response),
                error: None,
                id: req.id,
            })
        }
        
        "getbalance" => {
            Json(RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(serde_json::json!({"balance": 0})),
                error: None,
                id: req.id,
            })
        }
        
        "sendtransaction" => {
            Json(RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(serde_json::json!({"txid": "0x..."})),
                error: None,
                id: req.id,
            })
        }
        
        _ => {
            error_response(-32601, "Method not found", req.id)
        }
    }
}

fn error_response(code: i32, message: &str, id: u64) -> Json<RpcResponse> {
    Json(RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(RpcError {
            code,
            message: message.to_string(),
        }),
        id,
    })
}