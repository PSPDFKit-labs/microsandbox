//! Egress event and decision types.
//!
//! These types are serialized as CBOR over the `egress.sock` Unix socket.
//! The runtime sends [`EgressEvent`] to the SDK, and the SDK replies with
//! [`EgressDecision`].

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An egress event sent from the runtime to the SDK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressEvent {
    /// Unique correlation ID for this event (used internally for decision matching).
    pub id: u64,
    /// Connection identifier (stable across request/response pairs on the same connection).
    pub connection_id: u64,
    /// The event payload.
    pub kind: EgressEventKind,
    /// Server hostname from TLS SNI.
    pub sni: String,
    /// Destination socket address (IP:port).
    pub dst: SocketAddr,
    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
}

/// The kind of egress event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EgressEventKind {
    /// An outbound HTTP request (guest → server).
    Request(HttpRequest),
    /// An inbound HTTP response (server → guest).
    Response(HttpResponse),
}

/// A parsed HTTP/1.1 request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// HTTP method (e.g., "GET", "POST").
    pub method: String,
    /// Request URI (e.g., "/api/v1/chat").
    pub uri: String,
    /// HTTP headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Request body. `None` if `egress_max_body_bytes` is 0 or no body present.
    pub body: Option<Vec<u8>>,
}

/// A parsed HTTP/1.1 response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP status code (e.g., 200, 404).
    pub status: u16,
    /// HTTP headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Response body. `None` if `egress_max_body_bytes` is 0 or no body present.
    pub body: Option<Vec<u8>>,
}

/// Metadata about the connection, passed to SDK hooks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressContext {
    /// Server hostname from TLS SNI.
    pub sni: String,
    /// Destination socket address (IP:port).
    pub dst: SocketAddr,
    /// Connection identifier.
    pub connection_id: u64,
    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
}

/// A decision sent from the SDK back to the runtime.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressDecision {
    /// Correlation ID matching the [`EgressEvent::id`].
    pub id: u64,
    /// The action to take.
    pub action: EgressAction,
}

/// Action the proxy should take in response to an egress event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EgressAction {
    /// Forward the original request/response unchanged.
    PassThrough,

    /// Forward a modified request to the server (only valid for `Request` events).
    ModifyRequest(HttpRequest),

    /// Short-circuit: return this response to the guest without contacting the
    /// server (only valid for `Request` events).
    ShortCircuit(HttpResponse),

    /// Forward a modified response to the guest (only valid for `Response` events).
    ModifyResponse(HttpResponse),

    /// Block: close both connections immediately.
    Block,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<&EgressEvent> for EgressContext {
    fn from(event: &EgressEvent) -> Self {
        Self {
            sni: event.sni.clone(),
            dst: event.dst,
            connection_id: event.connection_id,
            timestamp_ms: event.timestamp_ms,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn cbor_roundtrip<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).expect("CBOR encode failed");
        ciborium::from_reader(buf.as_slice()).expect("CBOR decode failed")
    }

    fn sample_request() -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            uri: "/api/v1/chat".into(),
            headers: vec![
                ("Host".into(), "api.openai.com".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: Some(b"{\"prompt\":\"hello\"}".to_vec()),
        }
    }

    fn sample_response() -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Some(b"{\"text\":\"world\"}".to_vec()),
        }
    }

    fn sample_dst() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(104, 18, 0, 1), 443))
    }

    #[test]
    fn request_event_cbor_roundtrip() {
        let event = EgressEvent {
            id: 1,
            connection_id: 42,
            kind: EgressEventKind::Request(sample_request()),
            sni: "api.openai.com".into(),
            dst: sample_dst(),
            timestamp_ms: 1700000000000,
        };
        assert_eq!(event, cbor_roundtrip(&event));
    }

    #[test]
    fn response_event_cbor_roundtrip() {
        let event = EgressEvent {
            id: 2,
            connection_id: 42,
            kind: EgressEventKind::Response(sample_response()),
            sni: "api.openai.com".into(),
            dst: sample_dst(),
            timestamp_ms: 1700000000100,
        };
        assert_eq!(event, cbor_roundtrip(&event));
    }

    #[test]
    fn decision_passthrough_cbor_roundtrip() {
        let d = EgressDecision {
            id: 1,
            action: EgressAction::PassThrough,
        };
        assert_eq!(d, cbor_roundtrip(&d));
    }

    #[test]
    fn decision_modify_request_cbor_roundtrip() {
        let d = EgressDecision {
            id: 2,
            action: EgressAction::ModifyRequest(sample_request()),
        };
        assert_eq!(d, cbor_roundtrip(&d));
    }

    #[test]
    fn decision_short_circuit_cbor_roundtrip() {
        let d = EgressDecision {
            id: 3,
            action: EgressAction::ShortCircuit(sample_response()),
        };
        assert_eq!(d, cbor_roundtrip(&d));
    }

    #[test]
    fn decision_block_cbor_roundtrip() {
        let d = EgressDecision {
            id: 4,
            action: EgressAction::Block,
        };
        assert_eq!(d, cbor_roundtrip(&d));
    }

    #[test]
    fn context_from_event() {
        let event = EgressEvent {
            id: 10,
            connection_id: 99,
            kind: EgressEventKind::Request(sample_request()),
            sni: "example.com".into(),
            dst: sample_dst(),
            timestamp_ms: 1234567890,
        };
        let ctx = EgressContext::from(&event);
        assert_eq!(ctx.sni, "example.com");
        assert_eq!(ctx.dst, sample_dst());
        assert_eq!(ctx.connection_id, 99);
        assert_eq!(ctx.timestamp_ms, 1234567890);
    }
}
