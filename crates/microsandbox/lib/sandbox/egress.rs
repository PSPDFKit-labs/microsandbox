//! SDK-side egress interception stream.
//!
//! Connects to the runtime's `egress.sock` Unix socket and implements the
//! hook-based interception API. The SDK's `egress_intercept()` method runs
//! an event loop that reads events, calls user hooks, and writes decisions.

use std::io;
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use microsandbox_network::egress::event::{
    EgressAction, EgressContext, EgressDecision, EgressEvent, EgressEventKind, HttpRequest,
    HttpResponse,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Connection to the runtime's `egress.sock` for reading events and
/// writing decisions.
pub struct EgressConnection {
    stream: UnixStream,
}

/// Result type for egress request hooks.
///
/// - `None` → pass through unchanged
/// - `Some(RequestAction::Forward(req))` → forward modified request
/// - `Some(RequestAction::ShortCircuit(resp))` → return response to guest
pub enum RequestAction {
    /// Forward a (possibly modified) request to the server.
    Forward(HttpRequest),
    /// Short-circuit: return this response to the guest without contacting the server.
    ShortCircuit(HttpResponse),
}

/// Result type for egress response hooks.
///
/// - `None` → pass through unchanged
/// - `Some(resp)` → forward modified response to guest
pub type ResponseAction = Option<HttpResponse>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl EgressConnection {
    /// Connect to the egress socket.
    pub async fn connect(socket_path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(socket_path).await?;
        Ok(Self { stream })
    }

    /// Read the next egress event from the runtime.
    pub async fn recv(&mut self) -> io::Result<Option<EgressEvent>> {
        match read_frame(&mut self.stream).await {
            Ok(data) => {
                let event: EgressEvent = cbor_decode(&data)?;
                Ok(Some(event))
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Send a decision back to the runtime.
    pub async fn send_decision(&mut self, decision: EgressDecision) -> io::Result<()> {
        let data = cbor_encode(&decision)?;
        write_frame(&mut self.stream, &data).await
    }

    /// Run the interception event loop with user-provided hooks.
    ///
    /// Calls `on_request` for each outbound request and `on_response` for each
    /// server response. The hooks' return values determine the action:
    ///
    /// **`on_request`**: receives `(&mut HttpRequest, &EgressContext)`:
    /// - Returns `Ok(None)` → pass through unchanged
    /// - Returns `Ok(Some(RequestAction::Forward(req)))` → forward modified request
    /// - Returns `Ok(Some(RequestAction::ShortCircuit(resp)))` → short-circuit
    /// - Returns `Err(_)` → block the connection
    ///
    /// **`on_response`**: receives `(&mut HttpResponse, &HttpRequest, &EgressContext)`:
    /// - Returns `Ok(None)` → pass through unchanged
    /// - Returns `Ok(Some(resp))` → forward modified response
    /// - Returns `Err(_)` → block the connection
    pub async fn intercept<F, G>(&mut self, mut on_request: F, mut on_response: G) -> io::Result<()>
    where
        F: FnMut(
            &mut HttpRequest,
            &EgressContext,
        ) -> Result<Option<RequestAction>, Box<dyn std::error::Error>>,
        G: FnMut(
            &mut HttpResponse,
            &HttpRequest,
            &EgressContext,
        ) -> Result<ResponseAction, Box<dyn std::error::Error>>,
    {
        // Track the last request per connection for pairing with responses.
        let mut last_requests: std::collections::HashMap<u64, HttpRequest> =
            std::collections::HashMap::new();

        loop {
            let event = match self.recv().await? {
                Some(e) => e,
                None => break,
            };

            let ctx = EgressContext::from(&event);
            let event_id = event.id;
            let conn_id = event.connection_id;

            let action = match event.kind {
                EgressEventKind::Request(mut req) => match on_request(&mut req, &ctx) {
                    Ok(None) => {
                        last_requests.insert(conn_id, req);
                        EgressAction::PassThrough
                    }
                    Ok(Some(RequestAction::Forward(modified))) => {
                        last_requests.insert(conn_id, modified.clone());
                        EgressAction::ModifyRequest(modified)
                    }
                    Ok(Some(RequestAction::ShortCircuit(resp))) => {
                        last_requests.insert(conn_id, req);
                        EgressAction::ShortCircuit(resp)
                    }
                    Err(_) => EgressAction::Block,
                },
                EgressEventKind::Response(mut resp) => {
                    let empty_req = HttpRequest {
                        method: String::new(),
                        uri: String::new(),
                        headers: Vec::new(),
                        body: None,
                    };
                    let req = last_requests.get(&conn_id).unwrap_or(&empty_req);

                    let result = match on_response(&mut resp, req, &ctx) {
                        Ok(None) => EgressAction::PassThrough,
                        Ok(Some(modified)) => EgressAction::ModifyResponse(modified),
                        Err(_) => EgressAction::Block,
                    };
                    last_requests.remove(&conn_id);
                    result
                }
            };

            self.send_decision(EgressDecision {
                id: event_id,
                action,
            })
            .await?;
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn write_frame(stream: &mut UnixStream, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await
}

async fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 68 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "egress frame too large",
        ));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

fn cbor_encode<T: serde::Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(buf)
}

fn cbor_decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> io::Result<T> {
    ciborium::from_reader(data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    fn sample_dst() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443))
    }

    fn sample_request_event(id: u64, conn_id: u64) -> EgressEvent {
        EgressEvent {
            id,
            connection_id: conn_id,
            kind: EgressEventKind::Request(HttpRequest {
                method: "GET".into(),
                uri: "/test".into(),
                headers: vec![("Host".into(), "example.com".into())],
                body: None,
            }),
            sni: "example.com".into(),
            dst: sample_dst(),
            timestamp_ms: 1700000000000,
        }
    }

    fn sample_response_event(id: u64, conn_id: u64) -> EgressEvent {
        EgressEvent {
            id,
            connection_id: conn_id,
            kind: EgressEventKind::Response(HttpResponse {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: Some(b"{\"ok\":true}".to_vec()),
            }),
            sni: "example.com".into(),
            dst: sample_dst(),
            timestamp_ms: 1700000000100,
        }
    }

    fn temp_sock_path() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!("egress_sdk_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        dir.join(format!(
            "egress_{}.sock",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// Write a CBOR-encoded event as a length-prefixed frame.
    async fn mock_write_event(stream: &mut tokio::net::UnixStream, event: &EgressEvent) {
        let mut cbor = Vec::new();
        ciborium::into_writer(event, &mut cbor).unwrap();
        stream
            .write_all(&(cbor.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&cbor).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// Read a length-prefixed frame and decode as EgressDecision.
    async fn mock_read_decision(stream: &mut tokio::net::UnixStream) -> EgressDecision {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.unwrap();
        ciborium::from_reader(buf.as_slice()).unwrap()
    }

    #[tokio::test]
    async fn connect_and_recv() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock).unwrap();

        let sock_clone = sock.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            mock_write_event(&mut stream, &sample_request_event(1, 10)).await;
            stream
        });

        let mut conn = EgressConnection::connect(&sock_clone).await.unwrap();
        let event = conn.recv().await.unwrap().expect("expected event");
        assert_eq!(event.id, 1);
        assert_eq!(event.connection_id, 10);
        assert_eq!(event.sni, "example.com");
        assert!(matches!(event.kind, EgressEventKind::Request(_)));

        drop(server);
        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn send_decision_roundtrip() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock).unwrap();

        let sock_clone = sock.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            mock_read_decision(&mut stream).await
        });

        let mut conn = EgressConnection::connect(&sock_clone).await.unwrap();
        conn.send_decision(EgressDecision {
            id: 42,
            action: EgressAction::Block,
        })
        .await
        .unwrap();

        let decision = server.await.unwrap();
        assert_eq!(decision.id, 42);
        assert_eq!(decision.action, EgressAction::Block);

        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn intercept_passthrough() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock).unwrap();

        let sock_clone = sock.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            mock_write_event(&mut stream, &sample_request_event(1, 10)).await;
            let decision = mock_read_decision(&mut stream).await;
            drop(stream);
            decision
        });

        let mut conn = EgressConnection::connect(&sock_clone).await.unwrap();
        conn.intercept(
            |_req, _ctx| Ok(None), // pass through
            |_resp, _req, _ctx| Ok(None),
        )
        .await
        .unwrap();

        let decision = server.await.unwrap();
        assert_eq!(decision.id, 1);
        assert_eq!(decision.action, EgressAction::PassThrough);

        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn intercept_modify_request() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock).unwrap();

        let sock_clone = sock.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            mock_write_event(&mut stream, &sample_request_event(1, 10)).await;
            let decision = mock_read_decision(&mut stream).await;
            drop(stream);
            decision
        });

        let mut conn = EgressConnection::connect(&sock_clone).await.unwrap();
        conn.intercept(
            |req, _ctx| {
                req.headers.push(("X-Trace".into(), "abc".into()));
                Ok(Some(RequestAction::Forward(req.clone())))
            },
            |_resp, _req, _ctx| Ok(None),
        )
        .await
        .unwrap();

        let decision = server.await.unwrap();
        assert_eq!(decision.id, 1);
        match decision.action {
            EgressAction::ModifyRequest(req) => {
                assert!(
                    req.headers
                        .iter()
                        .any(|(k, v)| k == "X-Trace" && v == "abc")
                );
            }
            other => panic!("expected ModifyRequest, got {other:?}"),
        }

        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn intercept_short_circuit() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock).unwrap();

        let sock_clone = sock.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            mock_write_event(&mut stream, &sample_request_event(1, 10)).await;
            let decision = mock_read_decision(&mut stream).await;
            drop(stream);
            decision
        });

        let mut conn = EgressConnection::connect(&sock_clone).await.unwrap();
        conn.intercept(
            |_req, _ctx| {
                Ok(Some(RequestAction::ShortCircuit(HttpResponse {
                    status: 403,
                    headers: vec![],
                    body: Some(b"forbidden".to_vec()),
                })))
            },
            |_resp, _req, _ctx| Ok(None),
        )
        .await
        .unwrap();

        let decision = server.await.unwrap();
        match decision.action {
            EgressAction::ShortCircuit(resp) => {
                assert_eq!(resp.status, 403);
                assert_eq!(resp.body.as_deref(), Some(b"forbidden".as_slice()));
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }

        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn intercept_block_on_error() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock).unwrap();

        let sock_clone = sock.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            mock_write_event(&mut stream, &sample_request_event(1, 10)).await;
            let decision = mock_read_decision(&mut stream).await;
            drop(stream);
            decision
        });

        let mut conn = EgressConnection::connect(&sock_clone).await.unwrap();
        conn.intercept(
            |_req, _ctx| Err("blocked!".into()),
            |_resp, _req, _ctx| Ok(None),
        )
        .await
        .unwrap();

        let decision = server.await.unwrap();
        assert_eq!(decision.id, 1);
        assert_eq!(decision.action, EgressAction::Block);

        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn intercept_response_pairs_with_request() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock).unwrap();

        let sock_clone = sock.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Send request event first, then response for same connection.
            mock_write_event(&mut stream, &sample_request_event(1, 42)).await;
            let _d1 = mock_read_decision(&mut stream).await;
            mock_write_event(&mut stream, &sample_response_event(2, 42)).await;
            let d2 = mock_read_decision(&mut stream).await;
            drop(stream);
            d2
        });

        let mut conn = EgressConnection::connect(&sock_clone).await.unwrap();

        let seen_request_uri = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let uri_clone = seen_request_uri.clone();

        conn.intercept(
            |_req, _ctx| Ok(None), // pass through request
            move |_resp, req, _ctx| {
                // The response hook should receive the original request.
                *uri_clone.lock().unwrap() = req.uri.clone();
                Ok(None)
            },
        )
        .await
        .unwrap();

        let decision = server.await.unwrap();
        assert_eq!(decision.action, EgressAction::PassThrough);
        assert_eq!(*seen_request_uri.lock().unwrap(), "/test");

        std::fs::remove_file(&sock).ok();
    }
}
