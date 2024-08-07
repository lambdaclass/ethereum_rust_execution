use std::{future::IntoFuture, net::SocketAddr};

use handler::{handle_authrpc_request, handle_http_request};
use router::rpc_router;
use tokio::net::TcpListener;
use tracing::info;
use utils::RpcErr;

mod admin;
mod engine;
mod eth;
mod handler;
mod router;
mod utils;

use ethereum_rust_storage::Store;

pub async fn start_api(http_addr: SocketAddr, authrpc_addr: SocketAddr, storage: Store) {
    let http_router = rpc_router(handle_http_request, storage.clone());
    let http_listener = TcpListener::bind(http_addr).await.unwrap();

    let authrpc_router = rpc_router(handle_authrpc_request, storage.clone());
    let authrpc_listener = TcpListener::bind(authrpc_addr).await.unwrap();

    let authrpc_server = axum::serve(authrpc_listener, authrpc_router)
        .with_graceful_shutdown(shutdown_signal())
        .into_future();
    let http_server = axum::serve(http_listener, http_router)
        .with_graceful_shutdown(shutdown_signal())
        .into_future();

    info!("Starting HTTP server at {http_addr}");
    info!("Starting Auth-RPC server at {}", authrpc_addr);

    let _ = tokio::try_join!(authrpc_server, http_server)
        .inspect_err(|e| info!("Error shutting down servers: {:?}", e));
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
}
