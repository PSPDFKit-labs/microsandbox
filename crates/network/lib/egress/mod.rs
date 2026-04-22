//! Egress HTTP interception: observe and modify outbound HTTP traffic.
//!
//! When `egress_intercept_hosts` is set in [`NetworkConfig`](crate::config::NetworkConfig),
//! the TLS proxy feeds decrypted HTTP bytes through [`RequestFramer`](framer::RequestFramer)
//! and [`ResponseFramer`](framer::ResponseFramer), and publishes complete request/response
//! messages to the SDK via a Unix socket
//! (`egress.sock`). The SDK can observe, modify, short-circuit, or block traffic
//! using `onRequest`/`onResponse` hooks.

pub mod event;
pub mod framer;
pub mod publisher;
pub mod serialize;
