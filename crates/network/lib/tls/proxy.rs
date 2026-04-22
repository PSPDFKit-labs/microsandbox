//! Channel-based TLS proxy task.
//!
//! Intercepts TLS connections by terminating the guest's TLS with a
//! generated per-domain certificate (MITM) and re-originating a TLS
//! connection to the real server. Bypass mode replays buffered bytes and
//! splices the connection without termination.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use super::sni;
use super::state::TlsState;
use crate::egress::event::{EgressAction, EgressEvent, EgressEventKind, HttpResponse};
use crate::egress::framer::{FrameResult, RequestFramer, ResponseFramer};
use crate::egress::publisher::{self, ProxyMessage};
use crate::egress::serialize;
use crate::secrets::config::HostPattern;
use crate::secrets::handler::SecretsHandler;
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Max bytes to buffer while waiting for the ClientHello.
const CLIENT_HELLO_BUF_SIZE: usize = 16384;

/// Buffer size for bidirectional relay.
const RELAY_BUF_SIZE: usize = 16384;

/// Global connection ID counter for egress events.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Optional egress interception handle passed to TLS proxy tasks.
#[derive(Clone)]
pub struct EgressHandle {
    /// Channel to send events to the publisher.
    pub tx: mpsc::Sender<ProxyMessage>,
    /// Hosts to intercept.
    pub intercept_hosts: Arc<Vec<HostPattern>>,
    /// Max body bytes to capture.
    pub max_body_bytes: usize,
    /// Whether an SDK client is currently connected to the publisher.
    pub client_connected: Arc<AtomicBool>,
    /// Per-connection wall-clock timeout (ms). 0 = disabled.
    pub timeout_ms: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn a TLS proxy task for a connection to an intercepted port.
pub fn spawn_tls_proxy(
    handle: &tokio::runtime::Handle,
    dst: SocketAddr,
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    egress: Option<EgressHandle>,
) {
    handle.spawn(async move {
        if let Err(e) =
            tls_proxy_task(dst, from_smoltcp, to_smoltcp, shared, tls_state, egress).await
        {
            tracing::debug!(dst = %dst, error = %e, "TLS proxy task ended");
        }
    });
}

/// Core TLS proxy task.
async fn tls_proxy_task(
    dst: SocketAddr,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    egress: Option<EgressHandle>,
) -> io::Result<()> {
    // Phase 0: Buffer initial data to extract SNI from ClientHello.
    // Timeout prevents a slow/malicious guest from holding a proxy slot indefinitely.
    let sni_name = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        extract_sni_from_channel(&mut from_smoltcp),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SNI extraction timed out"))?;
    let (sni_name, initial_buf) = sni_name?;

    // Host filtering: only intercept egress for matching hosts.
    let egress = egress.and_then(|e| {
        if e.intercept_hosts.iter().any(|p| p.matches(&sni_name)) {
            Some(e)
        } else {
            None // SNI doesn't match filter
        }
    });

    if tls_state.should_bypass(&sni_name) {
        tracing::debug!(sni = %sni_name, dst = %dst, "TLS bypass");
        bypass_relay(dst, initial_buf, from_smoltcp, to_smoltcp, shared).await
    } else {
        tracing::debug!(sni = %sni_name, dst = %dst, "TLS intercept");
        intercept_relay(
            dst,
            &sni_name,
            initial_buf,
            from_smoltcp,
            to_smoltcp,
            shared,
            tls_state,
            egress,
        )
        .await
    }
}

/// Bypass mode: plain TCP splice, no TLS termination.
async fn bypass_relay(
    dst: SocketAddr,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
) -> io::Result<()> {
    let mut server = TcpStream::connect(dst).await?;
    server.write_all(&initial_buf).await?;

    let (mut server_rx, mut server_tx) = server.into_split();
    let mut buf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        tokio::select! {
            data = from_smoltcp.recv() => {
                match data {
                    Some(bytes) => server_tx.write_all(&bytes).await?,
                    None => break,
                }
            }
            result = server_rx.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if to_smoltcp.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                            break;
                        }
                        shared.proxy_wake.wake();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

/// Intercept mode: MITM with guest-facing rustls + server-facing tokio_rustls.
#[allow(clippy::too_many_arguments)]
async fn intercept_relay(
    dst: SocketAddr,
    sni_name: &str,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    egress: Option<EgressHandle>,
) -> io::Result<()> {
    // Create secrets handler for this connection (filters by SNI).
    // tls_intercepted = true because we're in intercept_relay (not bypass).
    let secrets_handler = SecretsHandler::new(&tls_state.secrets, sni_name, true);

    // Get or generate per-domain certificate (includes cached ServerConfig).
    let domain_cert = tls_state.get_or_generate_cert(sni_name);

    // Reuse cached ServerConfig — avoids cert chain clone + key clone + rebuild per connection.
    let mut guest_tls = rustls::ServerConnection::new(domain_cert.server_config.clone())
        .map_err(io::Error::other)?;

    // Feed the buffered ClientHello.
    {
        let mut remaining = &initial_buf[..];
        while !remaining.is_empty() {
            guest_tls
                .read_tls(&mut remaining)
                .map_err(io::Error::other)?;
            guest_tls.process_new_packets().map_err(io::Error::other)?;
        }
    }

    // Reusable buffer for TLS output — avoids per-flush heap allocation.
    let mut tls_buf = Vec::with_capacity(RELAY_BUF_SIZE + 256);

    // Send ServerHello etc. back to guest.
    flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;

    // Complete guest-facing TLS handshake with timeout to prevent resource exhaustion.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while guest_tls.is_handshaking() {
            let data = from_smoltcp
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                guest_tls
                    .read_tls(&mut remaining)
                    .map_err(io::Error::other)?;
                guest_tls.process_new_packets().map_err(io::Error::other)?;
            }
            flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;

    // Connect to real server with TLS.
    let server_stream = TcpStream::connect(dst).await?;
    let server_name = ServerName::try_from(sni_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut server_tls = tls_state
        .connector
        .connect(server_name, server_stream)
        .await
        .map_err(io::Error::other)?;

    // Egress interception framers (created only when egress is active and
    // an SDK client is connected — no point buffering if nobody is listening).
    let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let mut req_framer = egress
        .as_ref()
        .filter(|e| e.client_connected.load(Ordering::Relaxed))
        .map(|e| RequestFramer::new(e.max_body_bytes));
    let mut resp_framer = egress
        .as_ref()
        .filter(|e| e.client_connected.load(Ordering::Relaxed))
        .map(|e| ResponseFramer::new(e.max_body_bytes));

    // Hold-back buffers: when the framer returns Incomplete, we must NOT
    // forward raw bytes downstream — the hook may later decide to modify
    // or block. We buffer here and only flush on Complete + PassThrough.
    let mut req_held_back: Vec<u8> = Vec::with_capacity(65536);
    let mut resp_held_back: Vec<u8> = Vec::with_capacity(65536);

    // Phase 2: Bidirectional plaintext relay (with optional wall-clock timeout).
    let egress_timeout_ms = egress.as_ref().map_or(0, |e| e.timeout_ms);
    let relay_result = async {
        let mut server_buf = vec![0u8; RELAY_BUF_SIZE];
        let mut plaintext_buf = vec![0u8; RELAY_BUF_SIZE];

        // Drain any application data already buffered during the TLS handshake.
        forward_plaintext_with_egress(
            &mut guest_tls,
            &mut server_tls,
            &secrets_handler,
            &shared,
            &mut plaintext_buf,
            &egress,
            &mut req_framer,
            &mut req_held_back,
            sni_name,
            dst,
            connection_id,
            &to_smoltcp,
            &mut tls_buf,
        )
        .await?;

        loop {
            tokio::select! {
                // Guest → server: receive encrypted, decrypt, forward plaintext.
                data = from_smoltcp.recv() => {
                    let data = match data {
                        Some(d) => d,
                        None => break,
                    };
                    // Feed all data to rustls.
                    let mut remaining = &data[..];
                    while !remaining.is_empty() {
                        guest_tls
                            .read_tls(&mut remaining)
                            .map_err(io::Error::other)?;
                        guest_tls
                            .process_new_packets()
                            .map_err(io::Error::other)?;
                    }

                    forward_plaintext_with_egress(
                        &mut guest_tls,
                        &mut server_tls,
                        &secrets_handler,
                        &shared,
                        &mut plaintext_buf,
                        &egress,
                        &mut req_framer,
                        &mut req_held_back,
                        sni_name,
                        dst,
                        connection_id,
                        &to_smoltcp,
                        &mut tls_buf,
                    )
                    .await?;
                }

                // Server → guest: read plaintext, encrypt, send via channel.
                result = server_tls.read(&mut server_buf) => {
                    match result {
                        Ok(0) => {
                            // Server closed — finalize any in-progress response.
                            if let (Some(egress_handle), Some(framer)) = (&egress, &mut resp_framer)
                                && let FrameResult::Complete(resp, _) = framer.feed_eof()
                            {
                                    let action = send_egress_event(
                                        egress_handle,
                                        EgressEventKind::Response(resp),
                                        sni_name,
                                        dst,
                                        connection_id,
                                    )
                                    .await;
                                    match action {
                                        EgressAction::PassThrough => {
                                            if !resp_held_back.is_empty() {
                                                guest_tls
                                                    .writer()
                                                    .write_all(&resp_held_back)
                                                    .map_err(io::Error::other)?;
                                                resp_held_back.clear();
                                            }
                                            flush_to_guest(
                                                &mut guest_tls,
                                                &to_smoltcp,
                                                &shared,
                                                &mut tls_buf,
                                            )
                                            .await?;
                                        }
                                        EgressAction::ModifyResponse(resp) => {
                                            resp_held_back.clear();
                                            let wire = serialize::serialize_response(&resp);
                                            guest_tls
                                                .writer()
                                                .write_all(&wire)
                                                .map_err(io::Error::other)?;
                                            flush_to_guest(
                                                &mut guest_tls,
                                                &to_smoltcp,
                                                &shared,
                                                &mut tls_buf,
                                            )
                                            .await?;
                                        }
                                        EgressAction::Block => {
                                            resp_held_back.clear();
                                        }
                                        _ => {
                                            if !resp_held_back.is_empty() {
                                                guest_tls
                                                    .writer()
                                                    .write_all(&resp_held_back)
                                                    .map_err(io::Error::other)?;
                                                resp_held_back.clear();
                                            }
                                            flush_to_guest(
                                                &mut guest_tls,
                                                &to_smoltcp,
                                                &shared,
                                                &mut tls_buf,
                                            )
                                            .await?;
                                        }
                                    }
                            }
                            break;
                        }
                        Ok(n) => {
                            let server_data = &server_buf[..n];

                            // Feed response bytes to egress framer and handle decisions.
                            // We hold back raw bytes until the framer completes to avoid
                            // double-forwarding when the hook modifies the response.
                            let mut did_write = false;
                            if let (Some(egress_handle), Some(framer)) = (&egress, &mut resp_framer) {
                                match feed_response_framer(
                                    framer,
                                    server_data,
                                    egress_handle,
                                    sni_name,
                                    dst,
                                    connection_id,
                                ).await {
                                    ResponseFrameResult::Action(action) => match action {
                                        EgressAction::PassThrough => {
                                            // Flush held-back bytes + current chunk.
                                            if !resp_held_back.is_empty() {
                                                guest_tls
                                                    .writer()
                                                    .write_all(&resp_held_back)
                                                    .map_err(io::Error::other)?;
                                                resp_held_back.clear();
                                            }
                                            guest_tls
                                                .writer()
                                                .write_all(server_data)
                                                .map_err(io::Error::other)?;
                                            did_write = true;
                                        }
                                        EgressAction::ModifyResponse(resp) => {
                                            // Discard held-back raw bytes, send re-serialized.
                                            resp_held_back.clear();
                                            let wire = serialize::serialize_response(&resp);
                                            guest_tls
                                                .writer()
                                                .write_all(&wire)
                                                .map_err(io::Error::other)?;
                                            did_write = true;
                                        }
                                        EgressAction::Block => {
                                            resp_held_back.clear();
                                            return Err(io::Error::new(
                                                io::ErrorKind::ConnectionAborted,
                                                "egress: response blocked by hook",
                                            ));
                                        }
                                        _ => {
                                            // Unknown action — flush as pass-through.
                                            if !resp_held_back.is_empty() {
                                                guest_tls
                                                    .writer()
                                                    .write_all(&resp_held_back)
                                                    .map_err(io::Error::other)?;
                                                resp_held_back.clear();
                                            }
                                            guest_tls
                                                .writer()
                                                .write_all(server_data)
                                                .map_err(io::Error::other)?;
                                            did_write = true;
                                        }
                                    },
                                    ResponseFrameResult::BodyTooLarge => {
                                        // Discard held-back bytes, reject with 502.
                                        resp_held_back.clear();
                                        tracing::debug!(sni = sni_name, "egress: response body too large, rejecting with 502");
                                        let error_resp = serialize::serialize_response(
                                            &HttpResponse {
                                                status: 502,
                                                headers: vec![
                                                    ("Content-Type".into(), "text/plain".into()),
                                                    ("Connection".into(), "close".into()),
                                                ],
                                                body: Some(b"502 Bad Gateway\n".to_vec()),
                                            },
                                        );
                                        guest_tls
                                            .writer()
                                            .write_all(&error_resp)
                                            .map_err(io::Error::other)?;
                                        flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
                                        return Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "egress: response body exceeds max size",
                                        ));
                                    }
                                    ResponseFrameResult::Incomplete => {
                                        // Hold back — do NOT forward to guest yet.
                                        resp_held_back.extend_from_slice(server_data);
                                    }
                                    ResponseFrameResult::Upgrade(action) => {
                                        // 101 protocol upgrade (WebSocket etc.).
                                        // Hook was called with headers-only. Now flush and go raw.
                                        match action {
                                            EgressAction::Block => {
                                                resp_held_back.clear();
                                                return Err(io::Error::new(
                                                    io::ErrorKind::ConnectionAborted,
                                                    "egress: upgrade response blocked by hook",
                                                ));
                                            }
                                            EgressAction::ModifyResponse(_) => {
                                                // ModifyResponse is not supported for protocol
                                                // upgrades — post-upgrade data isn't HTTP.
                                                // Flush raw bytes as pass-through and log a warning.
                                                tracing::debug!(sni = sni_name, "egress: ModifyResponse ignored for 101 upgrade");
                                                if !resp_held_back.is_empty() {
                                                    guest_tls
                                                        .writer()
                                                        .write_all(&resp_held_back)
                                                        .map_err(io::Error::other)?;
                                                    resp_held_back.clear();
                                                }
                                                guest_tls
                                                    .writer()
                                                    .write_all(server_data)
                                                    .map_err(io::Error::other)?;
                                                did_write = true;
                                            }
                                            _ => {
                                                // PassThrough / other — flush raw bytes.
                                                if !resp_held_back.is_empty() {
                                                    guest_tls
                                                        .writer()
                                                        .write_all(&resp_held_back)
                                                        .map_err(io::Error::other)?;
                                                    resp_held_back.clear();
                                                }
                                                guest_tls
                                                    .writer()
                                                    .write_all(server_data)
                                                    .map_err(io::Error::other)?;
                                                did_write = true;
                                            }
                                        }
                                        // 101 — both directions are no longer HTTP.
                                        resp_framer = None;
                                        req_framer = None;
                                    }
                                }
                            } else {
                                guest_tls
                                    .writer()
                                    .write_all(server_data)
                                    .map_err(io::Error::other)?;
                                did_write = true;
                            }

                            if did_write {
                                flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }

        Ok::<(), io::Error>(())
    };

    if egress_timeout_ms > 0 {
        match tokio::time::timeout(
            std::time::Duration::from_millis(egress_timeout_ms),
            relay_result,
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                tracing::debug!(sni = sni_name, "egress: connection timeout, sending 504");
                let error_resp = serialize::serialize_response(&HttpResponse {
                    status: 504,
                    headers: vec![
                        ("Content-Type".into(), "text/plain".into()),
                        ("Connection".into(), "close".into()),
                    ],
                    body: Some(b"504 Gateway Timeout\n".to_vec()),
                });
                guest_tls
                    .writer()
                    .write_all(&error_resp)
                    .map_err(io::Error::other)?;
                flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
            }
        }
    } else {
        relay_result.await?;
    }

    Ok(())
}

/// Send an egress event to the publisher and wait for a decision.
async fn send_egress_event(
    egress: &EgressHandle,
    kind: EgressEventKind,
    sni: &str,
    dst: SocketAddr,
    connection_id: u64,
) -> EgressAction {
    let event_id = publisher::next_event_id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let event = EgressEvent {
        id: event_id,
        connection_id,
        kind,
        sni: sni.to_string(),
        dst,
        timestamp_ms: now,
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    let msg = ProxyMessage::Event {
        event,
        reply: reply_tx,
    };

    if egress.tx.try_send(msg).is_err() {
        return EgressAction::PassThrough;
    }

    match reply_rx.await {
        Ok(decision) => decision.action,
        Err(_) => EgressAction::PassThrough,
    }
}

/// Result of feeding bytes to the response framer.
enum ResponseFrameResult {
    /// A complete response was parsed; apply this action.
    Action(EgressAction),
    /// Not enough data yet — holdback decision.
    Incomplete,
    /// Response body exceeds max — reject with 502.
    BodyTooLarge,
    /// Protocol upgrade (101 Switching Protocols). Contains the hook action
    /// for the headers-only response.
    Upgrade(EgressAction),
}

/// Feed bytes to the response framer and return an action if a complete
/// response was parsed.
async fn feed_response_framer(
    framer: &mut ResponseFramer,
    data: &[u8],
    egress: &EgressHandle,
    sni: &str,
    dst: SocketAddr,
    connection_id: u64,
) -> ResponseFrameResult {
    match framer.feed(data) {
        FrameResult::Complete(resp, _) => {
            let action = send_egress_event(
                egress,
                EgressEventKind::Response(resp),
                sni,
                dst,
                connection_id,
            )
            .await;
            ResponseFrameResult::Action(action)
        }
        FrameResult::Upgrade(resp, _) => {
            let action = send_egress_event(
                egress,
                EgressEventKind::Response(resp),
                sni,
                dst,
                connection_id,
            )
            .await;
            ResponseFrameResult::Upgrade(action)
        }
        FrameResult::Incomplete => ResponseFrameResult::Incomplete,
        FrameResult::BodyTooLarge => ResponseFrameResult::BodyTooLarge,
        FrameResult::ParseError => ResponseFrameResult::BodyTooLarge, // treat as rejection
    }
}

/// Buffer channel data until a complete ClientHello with SNI is received.
async fn extract_sni_from_channel(
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
) -> io::Result<(String, Vec<u8>)> {
    let mut initial_buf = Vec::with_capacity(CLIENT_HELLO_BUF_SIZE);
    loop {
        let data = from_smoltcp
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
        initial_buf.extend_from_slice(&data);

        if let Some(name) = sni::extract_sni(&initial_buf) {
            return Ok((name, initial_buf));
        }
        if initial_buf.len() >= CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large or no SNI found",
            ));
        }
    }
}

/// Read all available decrypted plaintext from the guest-facing TLS
/// connection and forward it to the upstream server, applying secret
/// substitution when configured. Egress-aware version that feeds bytes
/// to the request framer and handles interception decisions.
#[allow(clippy::too_many_arguments)]
async fn forward_plaintext_with_egress(
    guest_tls: &mut rustls::ServerConnection,
    server_tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    secrets_handler: &SecretsHandler,
    shared: &SharedState,
    buf: &mut [u8],
    egress: &Option<EgressHandle>,
    req_framer: &mut Option<RequestFramer>,
    req_held_back: &mut Vec<u8>,
    sni: &str,
    dst: SocketAddr,
    connection_id: u64,
    to_smoltcp: &mpsc::Sender<Bytes>,
    tls_buf: &mut Vec<u8>,
) -> io::Result<()> {
    loop {
        let n = match guest_tls.reader().read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        };

        let plaintext = &buf[..n];

        // Feed to egress request framer (before secret substitution — safe).
        // We hold back raw bytes until the framer completes to avoid
        // double-forwarding when the hook modifies or blocks the request.
        if let (Some(egress_handle), Some(framer)) = (egress, req_framer.as_mut()) {
            match framer.feed(plaintext) {
                FrameResult::Complete(req, _) => {
                    let action = send_egress_event(
                        egress_handle,
                        EgressEventKind::Request(req),
                        sni,
                        dst,
                        connection_id,
                    )
                    .await;

                    match action {
                        EgressAction::PassThrough => {
                            // Flush held-back bytes + current chunk through
                            // secret substitution.
                            if req_held_back.is_empty() {
                                forward_with_secrets(
                                    server_tls,
                                    secrets_handler,
                                    shared,
                                    plaintext,
                                )
                                .await?;
                            } else {
                                req_held_back.extend_from_slice(plaintext);
                                let all_data = std::mem::take(req_held_back);
                                forward_with_secrets(
                                    server_tls,
                                    secrets_handler,
                                    shared,
                                    &all_data,
                                )
                                .await?;
                            }
                            continue;
                        }
                        EgressAction::ModifyRequest(modified_req) => {
                            // Discard held-back raw bytes, send re-serialized.
                            req_held_back.clear();
                            let wire = serialize::serialize_request(&modified_req);
                            forward_with_secrets(server_tls, secrets_handler, shared, &wire)
                                .await?;
                            continue;
                        }
                        EgressAction::ShortCircuit(resp) => {
                            // Discard held-back, send synthetic response to guest.
                            req_held_back.clear();
                            let wire = serialize::serialize_response(&resp);
                            guest_tls
                                .writer()
                                .write_all(&wire)
                                .map_err(io::Error::other)?;
                            flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await?;
                            continue;
                        }
                        EgressAction::Block => {
                            req_held_back.clear();
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "egress: request blocked by hook",
                            ));
                        }
                        _ => {
                            // ModifyResponse not valid here — flush as pass-through.
                            if req_held_back.is_empty() {
                                forward_with_secrets(
                                    server_tls,
                                    secrets_handler,
                                    shared,
                                    plaintext,
                                )
                                .await?;
                            } else {
                                req_held_back.extend_from_slice(plaintext);
                                let all_data = std::mem::take(req_held_back);
                                forward_with_secrets(
                                    server_tls,
                                    secrets_handler,
                                    shared,
                                    &all_data,
                                )
                                .await?;
                            }
                            continue;
                        }
                    }
                }
                FrameResult::BodyTooLarge => {
                    // Discard held-back, reject with 413.
                    req_held_back.clear();
                    tracing::debug!(sni, "egress: request body too large, rejecting with 413");
                    let error_resp = serialize::serialize_response(&HttpResponse {
                        status: 413,
                        headers: vec![
                            ("Content-Type".into(), "text/plain".into()),
                            ("Connection".into(), "close".into()),
                        ],
                        body: Some(b"413 Payload Too Large\n".to_vec()),
                    });
                    guest_tls
                        .writer()
                        .write_all(&error_resp)
                        .map_err(io::Error::other)?;
                    flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await?;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "egress: request body exceeds max size",
                    ));
                }
                FrameResult::ParseError => {
                    // Malformed chunked encoding — reject with 400.
                    req_held_back.clear();
                    tracing::debug!(sni, "egress: malformed chunked request, rejecting with 400");
                    let error_resp = serialize::serialize_response(&HttpResponse {
                        status: 400,
                        headers: vec![
                            ("Content-Type".into(), "text/plain".into()),
                            ("Connection".into(), "close".into()),
                        ],
                        body: Some(b"400 Bad Request\n".to_vec()),
                    });
                    guest_tls
                        .writer()
                        .write_all(&error_resp)
                        .map_err(io::Error::other)?;
                    flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await?;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "egress: malformed chunked encoding in request",
                    ));
                }
                FrameResult::Incomplete => {
                    // Hold back — do NOT forward to server yet.
                    req_held_back.extend_from_slice(plaintext);
                    continue;
                }
                FrameResult::Upgrade(_, _) => {
                    unreachable!("request framer should not return Upgrade");
                }
            }
        }

        // No egress framing — normal path: apply secret substitution and forward.
        forward_with_secrets(server_tls, secrets_handler, shared, plaintext).await?;
    }
    Ok(())
}

/// Apply secret substitution and forward data to the upstream server.
async fn forward_with_secrets(
    server_tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    secrets_handler: &SecretsHandler,
    shared: &SharedState,
    data: &[u8],
) -> io::Result<()> {
    if secrets_handler.is_empty() {
        server_tls.write_all(data).await?;
        return Ok(());
    }

    if let Some(substituted) = secrets_handler.substitute(data) {
        server_tls.write_all(&substituted).await?;
        return Ok(());
    }

    // Violation: placeholder going to disallowed host.
    if secrets_handler.terminates_on_violation() {
        shared.trigger_termination();
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "secret violation: placeholder sent to disallowed host",
    ))
}

/// Flush pending TLS output from the guest-facing rustls connection
/// to the smoltcp channel.
///
/// Reuses `buf` across calls to avoid per-flush heap allocation. The
/// buffer grows to steady-state capacity on the first call and stays there.
async fn flush_to_guest(
    guest_tls: &mut rustls::ServerConnection,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    if guest_tls.wants_write() {
        buf.clear();
        guest_tls.write_tls(buf)?;
        if !buf.is_empty() {
            to_smoltcp
                .send(Bytes::copy_from_slice(buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
            shared.proxy_wake.wake();
        }
    }
    Ok(())
}
