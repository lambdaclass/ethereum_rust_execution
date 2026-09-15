//! Discovery protocol implementation for running both discv4 and discv5 on a shared UDP port.
//!
//! ## Packet Discrimination Strategy
//!
//! DiscV4 packets have a deterministic structure:
//! `hash (32 bytes) || signature (65 bytes) || type (1 byte) || data`
//! where `hash == keccak256(rest_of_packet)`.
//!
//! **Discrimination logic:**
//! 1. If packet length >= 98 bytes AND `packet[0..32] == keccak256(packet[32..])` → DiscV4
//! 2. Otherwise → DiscV5

pub mod codec;
pub mod contact_table;
mod discv4_handlers;
mod discv5_handlers;
pub mod ip_predictor;
pub mod lookup;
pub mod server;

pub use contact_table::{
    Contact, ContactTable, ContactValidation, DiscoveryProtocol, PeerEvent, Session,
};
pub use ip_predictor::IpPredictor;
pub use server::{
    DiscoveryHandle, DiscoveryServer, DiscoveryServerError, DiscoveryServerProtocol,
    is_discv4_packet,
};

use std::time::Duration;

/// Configuration for which discovery protocols to enable.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub discv4_enabled: bool,
    pub discv5_enabled: bool,
    /// How many connections the consumer wants. Discovery never opens one; it
    /// uses this only to pace its lookups against how far along the consumer is.
    pub target_peers: usize,
    /// Set to true when `--nat extip:<addr>` was supplied; locks the IP predictor
    /// from overwriting the user-specified external address.
    pub nat_extip_set: bool,
}

/// Lookup interval bounds for the RLPx initiator's connection attempts. The
/// discovery server has its own bounds, since each of its iterative lookups
/// emits far more traffic than a single connection attempt.
pub const INITIAL_LOOKUP_INTERVAL_MS: f64 = 100.0; // 10 per second
pub const LOOKUP_INTERVAL_MS: f64 = 600.0; // 100 per minute

/// Smooth easing curve for lookup intervals based on peer completion progress.
///
/// Shared by the discovery server and the RLPx initiator.
pub fn lookup_interval_function(progress: f64, lower_limit: f64, upper_limit: f64) -> Duration {
    // Smooth progression curve
    // See https://easings.net/#easeInOutCubic
    let ease_in_out_cubic = if progress < 0.5 {
        4.0 * progress.powf(3.0)
    } else {
        1.0 - ((-2.0 * progress + 2.0).powf(3.0)) / 2.0
    };
    Duration::from_micros(
        (1000f64 * (ease_in_out_cubic * (upper_limit - lower_limit) + lower_limit)).round() as u64,
    )
}
