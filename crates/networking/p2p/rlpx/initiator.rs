use crate::discovery::{LOOKUP_INTERVAL_MS, lookup_interval_function};
use crate::peer_table::PeerTableServerProtocol as _;
use crate::types::Node;
use crate::{metrics::METRICS, network::P2PContext, rlpx::connection::server::PeerConnection};
use spawned_concurrency::{
    actor,
    error::ActorError,
    protocol,
    tasks::{
        Actor, ActorRef, ActorStart as _, Backend, Context, Handler, send_after, send_message_on,
    },
};
use std::time::Duration;
use tracing::{debug, error};

#[derive(Debug, thiserror::Error)]
pub enum RLPxInitiatorError {
    #[error(transparent)]
    ActorError(#[from] ActorError),
}

#[protocol]
pub trait RlpxInitiatorProtocol: Send + Sync {
    fn look_for_peer(&self) -> Result<(), ActorError>;
    fn initiate(&self, node: Node) -> Result<(), ActorError>;
    fn shutdown(&self) -> Result<(), ActorError>;
}

#[derive(Debug, Clone)]
pub struct RLPxInitiator {
    context: P2PContext,
}

#[actor(protocol = RlpxInitiatorProtocol)]
impl RLPxInitiator {
    pub fn new(context: P2PContext) -> Self {
        Self { context }
    }

    pub fn spawn(context: P2PContext) -> ActorRef<RLPxInitiator> {
        Self::spawn_with_backend(context, None)
    }

    pub fn spawn_on_thread(context: P2PContext) -> ActorRef<RLPxInitiator> {
        Self::spawn_with_backend(context, Some(Backend::Thread))
    }

    fn spawn_with_backend(
        context: P2PContext,
        backend: Option<Backend>,
    ) -> ActorRef<RLPxInitiator> {
        debug!("Starting RLPx initiator");
        let state = RLPxInitiator::new(context);
        let actor_ref = match backend {
            Some(b) => state.start_with_backend(b),
            None => state.start(),
        };
        let _ = actor_ref.send(rlpx_initiator_protocol::LookForPeer);
        actor_ref
    }

    #[started]
    async fn started(&mut self, ctx: &Context<Self>) {
        send_message_on(
            ctx.clone(),
            tokio::signal::ctrl_c(),
            rlpx_initiator_protocol::Shutdown,
        );
    }

    #[send_handler]
    async fn handle_look_for_peer(
        &mut self,
        _msg: rlpx_initiator_protocol::LookForPeer,
        ctx: &Context<Self>,
    ) {
        let _ = self
            .do_look_for_peer()
            .await
            .inspect_err(|e| error!(err=?e, "Error looking for peers"));

        send_after(
            self.get_lookup_interval().await,
            ctx.clone(),
            rlpx_initiator_protocol::LookForPeer,
        );
    }

    #[send_handler]
    async fn handle_initiate(
        &mut self,
        msg: rlpx_initiator_protocol::Initiate,
        _ctx: &Context<Self>,
    ) {
        PeerConnection::spawn_as_initiator(self.context.clone(), &msg.node);
        METRICS.record_new_rlpx_conn_attempt().await;
    }

    #[send_handler]
    async fn handle_shutdown(
        &mut self,
        _msg: rlpx_initiator_protocol::Shutdown,
        ctx: &Context<Self>,
    ) {
        ctx.stop();
    }

    async fn do_look_for_peer(&mut self) -> Result<(), RLPxInitiatorError> {
        if !self.context.table.target_peers_reached().await? {
            if let Some(node) = self.context.discovery.next_dial_candidate().await {
                PeerConnection::spawn_as_initiator(self.context.clone(), &node);
                METRICS.record_new_rlpx_conn_attempt().await;
            };
        } else {
            debug!("Target peer connections reached, no need to initiate new connections.");
        }
        Ok(())
    }

    // We use the same lookup intervals as Discovery to try to get both process to check at the same rate
    async fn get_lookup_interval(&mut self) -> Duration {
        let peer_completion = self
            .context
            .table
            .target_peers_completion()
            .await
            .unwrap_or_default();
        lookup_interval_function(
            peer_completion,
            self.context.initial_lookup_interval,
            LOOKUP_INTERVAL_MS,
        )
    }
}
