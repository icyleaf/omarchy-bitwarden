//! Daemon subsystem for omawarden.
//!
//! Provides background synchronization, IPC socket communications,
//! state management, lock detection, and protocol versioning.

pub mod client;
pub mod handlers;
pub mod lock_detect;
pub mod protocol;
pub mod server;
pub mod state;

#[cfg(test)]
mod tests;

pub use client::*;
pub use handlers::*;
pub use lock_detect::*;
pub use protocol::*;
pub use server::*;
pub use state::*;
