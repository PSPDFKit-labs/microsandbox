//! Node.js bindings for egress HTTP interception.
//!
//! Wraps the Rust SDK's `EgressConnection` for use from JavaScript/TypeScript.
//! Provides both a low-level `recv()`/`sendDecision()` API and a high-level
//! `egressIntercept()` callback-based API on `Sandbox`.

use napi::bindgen_prelude::*;

use crate::types::{EgressEvent, EgressHttpRequest, EgressHttpResponse};

/// Convert a Rust `EgressEvent` to the JS representation.
pub(crate) fn rust_event_to_js(
    event: &microsandbox_network::egress::event::EgressEvent,
) -> EgressEvent {
    let (kind_str, request, response) = match &event.kind {
        microsandbox_network::egress::event::EgressEventKind::Request(req) => {
            let headers = req
                .headers
                .iter()
                .map(|(k, v)| vec![k.clone(), v.clone()])
                .collect();
            (
                "request".to_string(),
                Some(EgressHttpRequest {
                    method: req.method.clone(),
                    uri: req.uri.clone(),
                    headers,
                    body: req.body.as_ref().map(|b| Buffer::from(b.as_slice())),
                }),
                None,
            )
        }
        microsandbox_network::egress::event::EgressEventKind::Response(resp) => {
            let headers = resp
                .headers
                .iter()
                .map(|(k, v)| vec![k.clone(), v.clone()])
                .collect();
            (
                "response".to_string(),
                None,
                Some(EgressHttpResponse {
                    status: resp.status as u32,
                    headers,
                    body: resp.body.as_ref().map(|b| Buffer::from(b.as_slice())),
                }),
            )
        }
    };

    EgressEvent {
        id: event.id as f64,
        kind: kind_str,
        sni: event.sni.clone(),
        dst: event.dst.to_string(),
        connection_id: event.connection_id as f64,
        timestamp_ms: event.timestamp_ms as f64,
        request,
        response,
    }
}
