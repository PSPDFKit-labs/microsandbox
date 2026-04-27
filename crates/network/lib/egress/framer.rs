//! HTTP/1.1 message framer.
//!
//! Accumulates bytes from the TLS proxy and emits complete HTTP messages
//! (request or response). Handles `Content-Length` and `Transfer-Encoding: chunked`.
//!
//! Two instances are used per connection: one for the request direction
//! (guest → server) and one for the response direction (server → guest).

use super::event::{HttpRequest, HttpResponse};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum number of headers to parse.
const MAX_HEADERS: usize = 128;

/// Default header buffer capacity.
const HEADER_BUF_CAPACITY: usize = 8192;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Framer for the request direction (guest → server).
pub struct RequestFramer {
    state: FramerState,
    buf: Vec<u8>,
    max_body_bytes: usize,
}

/// Framer for the response direction (server → guest).
pub struct ResponseFramer {
    state: FramerState,
    buf: Vec<u8>,
    max_body_bytes: usize,
}

/// Internal framer state machine.
enum FramerState {
    /// Accumulating bytes until `\r\n\r\n` is found.
    AwaitingHeaders,
    /// Headers parsed, buffering body bytes.
    BufferingBody {
        headers_end: usize,
        body_mode: BodyMode,
        body_buf: Vec<u8>,
    },
    /// Buffering a chunked body.
    BufferingChunked {
        headers_end: usize,
        body_buf: Vec<u8>,
        chunk_state: ChunkState,
        /// Number of chunk-encoded bytes already consumed by `process_chunks`.
        /// Prevents re-processing old data when `feed()` is called multiple times.
        chunk_bytes_consumed: usize,
    },
    /// Buffering a read-until-close body (no Content-Length, no chunked).
    /// Completes only via `feed_eof()`.
    BufferingUntilClose {
        headers_end: usize,
        body_buf: Vec<u8>,
    },
}

/// How the body length is determined.
#[allow(dead_code)]
enum BodyMode {
    /// Fixed length from `Content-Length`.
    ContentLength(usize),
    /// No body (Content-Length: 0 or not present for requests).
    None,
}

/// State for chunked transfer encoding parsing.
enum ChunkState {
    /// Reading chunk size line.
    ReadingSize { size_buf: Vec<u8> },
    /// Reading chunk data.
    ReadingData { remaining: usize },
    /// Reading the CRLF after chunk data.
    ReadingDataCrlf { remaining_crlf: u8 },
    /// Terminal chunk (size 0) seen.
    Done,
}

/// Result of feeding bytes to the framer.
#[derive(Debug)]
pub enum FrameResult<T> {
    /// Not enough data yet.
    Incomplete,
    /// A complete message was parsed. Contains the message and the number
    /// of bytes consumed from the input.
    Complete(T, usize),
    /// The message body exceeds the configured maximum size.
    BodyTooLarge,
    /// Protocol upgrade (101 Switching Protocols). Contains a headers-only
    /// message. Caller should stop framing both directions and switch to
    /// raw byte forwarding.
    Upgrade(T, usize),
    /// Malformed chunked encoding (non-hex chunk size). Connection should be
    /// terminated — the body cannot be reliably parsed.
    ParseError,
}

/// Result from chunk processing.
enum ChunkProcessResult {
    /// All chunks consumed, body complete.
    Done(usize),
    /// Need more data.
    Incomplete,
    /// Accumulated body exceeds max.
    TooLarge,
    /// Malformed chunk size line (non-hex characters).
    ParseError,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RequestFramer {
    /// Create a new request framer.
    ///
    /// `max_body_bytes`: maximum body bytes to capture per request.
    pub fn new(max_body_bytes: usize) -> Self {
        Self {
            state: FramerState::AwaitingHeaders,
            buf: Vec::with_capacity(HEADER_BUF_CAPACITY),
            max_body_bytes,
        }
    }

    /// Feed bytes from the decrypted stream. Returns a complete request if one
    /// has been fully received.
    pub fn feed(&mut self, data: &[u8]) -> FrameResult<HttpRequest> {
        self.buf.extend_from_slice(data);

        loop {
            match &mut self.state {
                FramerState::AwaitingHeaders => {
                    let Some(boundary) = find_header_boundary(&self.buf) else {
                        return FrameResult::Incomplete;
                    };

                    let header_bytes = &self.buf[..boundary];
                    let mut headers_arr = [httparse::EMPTY_HEADER; MAX_HEADERS];
                    let (header_count, method, path) = {
                        let mut req = httparse::Request::new(&mut headers_arr);
                        if req.parse(header_bytes).is_err() {
                            // Malformed request — skip and reset.
                            self.buf.clear();
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::Incomplete;
                        }
                        (
                            req.headers.len(),
                            req.method.unwrap_or("GET").to_string(),
                            req.path.unwrap_or("/").to_string(),
                        )
                    };

                    let body_mode = determine_body_mode_from_headers(&headers_arr, header_count);

                    match body_mode {
                        BodyDetermination::ContentLength(0) | BodyDetermination::Undetermined => {
                            let request = build_request_from_parts(
                                &method,
                                &path,
                                &headers_arr[..header_count],
                                None,
                            );
                            let consumed = boundary;
                            self.buf.drain(..consumed);
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::Complete(request, consumed);
                        }
                        BodyDetermination::ContentLength(len) => {
                            if len > self.max_body_bytes {
                                self.buf.clear();
                                self.state = FramerState::AwaitingHeaders;
                                return FrameResult::BodyTooLarge;
                            }
                            self.state = FramerState::BufferingBody {
                                headers_end: boundary,
                                body_mode: BodyMode::ContentLength(len),
                                body_buf: Vec::with_capacity(len),
                            };
                        }
                        BodyDetermination::Chunked => {
                            self.state = FramerState::BufferingChunked {
                                headers_end: boundary,
                                body_buf: Vec::new(),
                                chunk_state: ChunkState::ReadingSize {
                                    size_buf: Vec::new(),
                                },
                                chunk_bytes_consumed: 0,
                            };
                        }
                    }
                }

                FramerState::BufferingBody {
                    headers_end,
                    body_mode,
                    body_buf,
                } => {
                    let BodyMode::ContentLength(total_len) = body_mode else {
                        unreachable!();
                    };
                    let total_len = *total_len;
                    let headers_end = *headers_end;

                    let body_start = headers_end;
                    let available_body = self.buf.len().saturating_sub(body_start);

                    if available_body < total_len {
                        // Not enough body data yet. Capture what we can.
                        let capture_end = body_start + available_body;
                        let capturable = &self.buf[body_start + body_buf.len()..capture_end];
                        if !capturable.is_empty() {
                            body_buf.extend_from_slice(capturable);
                        }
                        return FrameResult::Incomplete;
                    }

                    // Full body available.
                    let body_end = body_start + total_len;
                    let remaining_body = &self.buf[body_start + body_buf.len()..body_end];
                    if !remaining_body.is_empty() {
                        body_buf.extend_from_slice(remaining_body);
                    }

                    let body = if self.max_body_bytes > 0 {
                        Some(std::mem::take(body_buf))
                    } else {
                        None
                    };

                    // Re-parse headers to build the request. This cannot fail
                    // because the same bytes parsed successfully in AwaitingHeaders.
                    let header_bytes = &self.buf[..headers_end];
                    let mut headers_arr = [httparse::EMPTY_HEADER; MAX_HEADERS];
                    let (count, method, path) = {
                        let mut req = httparse::Request::new(&mut headers_arr);
                        if req.parse(header_bytes).is_err() {
                            self.buf.clear();
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::ParseError;
                        }
                        (
                            req.headers.len(),
                            req.method.unwrap_or("GET").to_string(),
                            req.path.unwrap_or("/").to_string(),
                        )
                    };

                    let request =
                        build_request_from_parts(&method, &path, &headers_arr[..count], body);
                    let consumed = body_end;
                    self.buf.drain(..consumed);
                    self.state = FramerState::AwaitingHeaders;
                    return FrameResult::Complete(request, consumed);
                }

                FramerState::BufferingChunked {
                    headers_end,
                    body_buf,
                    chunk_state,
                    chunk_bytes_consumed,
                } => {
                    let headers_end_val = *headers_end;
                    let body_start = headers_end_val;

                    // Only process NEW chunk data (skip already-consumed bytes).
                    let chunk_data = &self.buf[body_start + *chunk_bytes_consumed..];
                    let result =
                        process_chunks(chunk_data, chunk_state, body_buf, self.max_body_bytes);

                    match result {
                        ChunkProcessResult::Incomplete => {
                            // All bytes in this slice were consumed by process_chunks.
                            *chunk_bytes_consumed = self.buf.len() - body_start;
                            return FrameResult::Incomplete;
                        }
                        ChunkProcessResult::TooLarge => {
                            self.buf.clear();
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::BodyTooLarge;
                        }
                        ChunkProcessResult::ParseError => {
                            self.buf.clear();
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::ParseError;
                        }
                        ChunkProcessResult::Done(bytes_consumed) => {
                            let body = if self.max_body_bytes > 0 {
                                Some(std::mem::take(body_buf))
                            } else {
                                None
                            };

                            let header_bytes = &self.buf[..headers_end_val];
                            let mut headers_arr = [httparse::EMPTY_HEADER; MAX_HEADERS];
                            let (count, method, path) = {
                                let mut req = httparse::Request::new(&mut headers_arr);
                                if req.parse(header_bytes).is_err() {
                                    self.buf.clear();
                                    self.state = FramerState::AwaitingHeaders;
                                    return FrameResult::ParseError;
                                }
                                (
                                    req.headers.len(),
                                    req.method.unwrap_or("GET").to_string(),
                                    req.path.unwrap_or("/").to_string(),
                                )
                            };

                            let request = build_request_from_parts(
                                &method,
                                &path,
                                &headers_arr[..count],
                                body,
                            );
                            let consumed = body_start + *chunk_bytes_consumed + bytes_consumed;
                            self.buf.drain(..consumed);
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::Complete(request, consumed);
                        }
                    }
                }

                FramerState::BufferingUntilClose { .. } => {
                    unreachable!("request framer does not use BufferingUntilClose");
                }
            }
        }
    }

    /// Reset the framer state (e.g., on connection close).
    pub fn reset(&mut self) {
        self.buf.clear();
        self.state = FramerState::AwaitingHeaders;
    }
}

impl ResponseFramer {
    /// Create a new response framer.
    pub fn new(max_body_bytes: usize) -> Self {
        Self {
            state: FramerState::AwaitingHeaders,
            buf: Vec::with_capacity(HEADER_BUF_CAPACITY),
            max_body_bytes,
        }
    }

    /// Feed bytes from the decrypted stream.
    pub fn feed(&mut self, data: &[u8]) -> FrameResult<HttpResponse> {
        self.buf.extend_from_slice(data);

        loop {
            match &mut self.state {
                FramerState::AwaitingHeaders => {
                    let Some(boundary) = find_header_boundary(&self.buf) else {
                        return FrameResult::Incomplete;
                    };

                    let header_bytes = &self.buf[..boundary];
                    let mut headers_arr = [httparse::EMPTY_HEADER; MAX_HEADERS];
                    let (header_count, status) = {
                        let mut resp = httparse::Response::new(&mut headers_arr);
                        if resp.parse(header_bytes).is_err() {
                            self.buf.clear();
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::Incomplete;
                        }
                        (resp.headers.len(), resp.code.unwrap_or(200))
                    };

                    // 101 Switching Protocols — protocol upgrade (WebSocket etc.).
                    // Emit headers-only and signal caller to stop framing.
                    if status == 101 {
                        let response =
                            build_response_from_parts(status, &headers_arr[..header_count], None);
                        let consumed = boundary;
                        self.buf.drain(..consumed);
                        self.state = FramerState::AwaitingHeaders;
                        return FrameResult::Upgrade(response, consumed);
                    }

                    let body_mode = determine_body_mode_from_headers(&headers_arr, header_count);

                    match body_mode {
                        BodyDetermination::ContentLength(0) => {
                            let response = build_response_from_parts(
                                status,
                                &headers_arr[..header_count],
                                None,
                            );
                            let consumed = boundary;
                            self.buf.drain(..consumed);
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::Complete(response, consumed);
                        }
                        BodyDetermination::Undetermined => {
                            // 1xx, 204, 205, and 304 MUST NOT have a body
                            // per RFC 7230/7231.
                            if status < 200 || status == 204 || status == 205 || status == 304 {
                                let response = build_response_from_parts(
                                    status,
                                    &headers_arr[..header_count],
                                    None,
                                );
                                let consumed = boundary;
                                self.buf.drain(..consumed);
                                self.state = FramerState::AwaitingHeaders;
                                return FrameResult::Complete(response, consumed);
                            }
                            // Other responses without Content-Length or
                            // Transfer-Encoding use read-until-close —
                            // buffer until `feed_eof()`.
                            self.state = FramerState::BufferingUntilClose {
                                headers_end: boundary,
                                body_buf: Vec::new(),
                            };
                        }
                        BodyDetermination::ContentLength(len) => {
                            if len > self.max_body_bytes {
                                self.buf.clear();
                                self.state = FramerState::AwaitingHeaders;
                                return FrameResult::BodyTooLarge;
                            }
                            self.state = FramerState::BufferingBody {
                                headers_end: boundary,
                                body_mode: BodyMode::ContentLength(len),
                                body_buf: Vec::with_capacity(len),
                            };
                        }
                        BodyDetermination::Chunked => {
                            self.state = FramerState::BufferingChunked {
                                headers_end: boundary,
                                body_buf: Vec::new(),
                                chunk_state: ChunkState::ReadingSize {
                                    size_buf: Vec::new(),
                                },
                                chunk_bytes_consumed: 0,
                            };
                        }
                    }
                }

                FramerState::BufferingBody {
                    headers_end,
                    body_mode,
                    body_buf,
                } => {
                    let BodyMode::ContentLength(total_len) = body_mode else {
                        unreachable!();
                    };
                    let total_len = *total_len;
                    let headers_end = *headers_end;
                    let body_start = headers_end;
                    let available_body = self.buf.len().saturating_sub(body_start);

                    if available_body < total_len {
                        let capture_end = body_start + available_body;
                        let capturable = &self.buf[body_start + body_buf.len()..capture_end];
                        if !capturable.is_empty() {
                            body_buf.extend_from_slice(capturable);
                        }
                        return FrameResult::Incomplete;
                    }

                    let body_end = body_start + total_len;
                    let remaining_body = &self.buf[body_start + body_buf.len()..body_end];
                    if !remaining_body.is_empty() {
                        body_buf.extend_from_slice(remaining_body);
                    }

                    let body = if self.max_body_bytes > 0 {
                        Some(std::mem::take(body_buf))
                    } else {
                        None
                    };

                    let header_bytes = &self.buf[..headers_end];
                    let mut headers_arr = [httparse::EMPTY_HEADER; MAX_HEADERS];
                    let (count, status) = {
                        let mut resp = httparse::Response::new(&mut headers_arr);
                        if resp.parse(header_bytes).is_err() {
                            self.buf.clear();
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::ParseError;
                        }
                        (resp.headers.len(), resp.code.unwrap_or(200))
                    };

                    let response = build_response_from_parts(status, &headers_arr[..count], body);
                    let consumed = body_end;
                    self.buf.drain(..consumed);
                    self.state = FramerState::AwaitingHeaders;
                    return FrameResult::Complete(response, consumed);
                }

                FramerState::BufferingChunked {
                    headers_end,
                    body_buf,
                    chunk_state,
                    chunk_bytes_consumed,
                } => {
                    let headers_end_val = *headers_end;
                    let body_start = headers_end_val;

                    // Only process NEW chunk data (skip already-consumed bytes).
                    let chunk_data = &self.buf[body_start + *chunk_bytes_consumed..];
                    let result =
                        process_chunks(chunk_data, chunk_state, body_buf, self.max_body_bytes);

                    match result {
                        ChunkProcessResult::Incomplete => {
                            *chunk_bytes_consumed = self.buf.len() - body_start;
                            return FrameResult::Incomplete;
                        }
                        ChunkProcessResult::TooLarge => {
                            self.buf.clear();
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::BodyTooLarge;
                        }
                        ChunkProcessResult::ParseError => {
                            self.buf.clear();
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::ParseError;
                        }
                        ChunkProcessResult::Done(bytes_consumed) => {
                            let body = if self.max_body_bytes > 0 {
                                Some(std::mem::take(body_buf))
                            } else {
                                None
                            };

                            let header_bytes = &self.buf[..headers_end_val];
                            let mut headers_arr = [httparse::EMPTY_HEADER; MAX_HEADERS];
                            let (count, status) = {
                                let mut resp = httparse::Response::new(&mut headers_arr);
                                if resp.parse(header_bytes).is_err() {
                                    self.buf.clear();
                                    self.state = FramerState::AwaitingHeaders;
                                    return FrameResult::ParseError;
                                }
                                (resp.headers.len(), resp.code.unwrap_or(200))
                            };

                            let response =
                                build_response_from_parts(status, &headers_arr[..count], body);
                            let consumed = body_start + *chunk_bytes_consumed + bytes_consumed;
                            self.buf.drain(..consumed);
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::Complete(response, consumed);
                        }
                    }
                }

                FramerState::BufferingUntilClose {
                    headers_end,
                    body_buf,
                } => {
                    let body_start = *headers_end;
                    let new_data = &self.buf[body_start + body_buf.len()..];
                    if body_buf.len() + new_data.len() > self.max_body_bytes {
                        self.buf.clear();
                        self.state = FramerState::AwaitingHeaders;
                        return FrameResult::BodyTooLarge;
                    }
                    body_buf.extend_from_slice(new_data);
                    return FrameResult::Incomplete;
                }
            }
        }
    }

    /// Signal that the server closed the connection.
    ///
    /// Finalizes any in-progress response body (read-until-close or
    /// partial chunked where the server closed before the terminal chunk).
    pub fn feed_eof(&mut self) -> FrameResult<HttpResponse> {
        match std::mem::replace(&mut self.state, FramerState::AwaitingHeaders) {
            FramerState::BufferingUntilClose {
                headers_end,
                body_buf,
            }
            | FramerState::BufferingChunked {
                headers_end,
                body_buf,
                ..
            } => {
                let header_bytes = &self.buf[..headers_end];
                let mut headers_arr = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let (count, status) = {
                    let mut resp = httparse::Response::new(&mut headers_arr);
                    if resp.parse(header_bytes).is_err() {
                        self.buf.clear();
                        return FrameResult::ParseError;
                    }
                    (resp.headers.len(), resp.code.unwrap_or(200))
                };
                let body = if self.max_body_bytes > 0 && !body_buf.is_empty() {
                    Some(body_buf)
                } else {
                    None
                };
                let response = build_response_from_parts(status, &headers_arr[..count], body);
                self.buf.clear();
                FrameResult::Complete(response, 0)
            }
            _ => {
                // AwaitingHeaders or BufferingBody — nothing useful to emit.
                self.buf.clear();
                FrameResult::Incomplete
            }
        }
    }

    /// Reset the framer state.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.state = FramerState::AwaitingHeaders;
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Find the `\r\n\r\n` boundary between HTTP headers and body.
fn find_header_boundary(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

/// How the body length is determined from headers.
enum BodyDetermination {
    /// `Content-Length: N` found.
    ContentLength(usize),
    /// `Transfer-Encoding: chunked` found.
    Chunked,
    /// Neither `Content-Length` nor `Transfer-Encoding` found.
    /// For requests this means no body; for responses this means read-until-close.
    Undetermined,
}

/// Scan headers for `Content-Length` or `Transfer-Encoding: chunked`.
fn determine_body_mode_from_headers(
    headers: &[httparse::Header<'_>],
    count: usize,
) -> BodyDetermination {
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;

    for h in &headers[..count] {
        if h.name.eq_ignore_ascii_case("content-length") {
            if let Ok(s) = std::str::from_utf8(h.value) {
                content_length = s.trim().parse().ok();
            }
        } else if h.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(h.value)
                .is_ok_and(|s| s.to_ascii_lowercase().contains("chunked"))
        {
            is_chunked = true;
        }
    }

    if is_chunked {
        BodyDetermination::Chunked
    } else if let Some(len) = content_length {
        BodyDetermination::ContentLength(len)
    } else {
        BodyDetermination::Undetermined
    }
}

/// Build an `HttpRequest` from pre-extracted parts (avoids borrow conflicts with httparse).
fn build_request_from_parts(
    method: &str,
    uri: &str,
    headers: &[httparse::Header<'_>],
    body: Option<Vec<u8>>,
) -> HttpRequest {
    let headers = headers
        .iter()
        .filter(|h| !h.name.is_empty())
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();

    HttpRequest {
        method: method.to_string(),
        uri: uri.to_string(),
        headers,
        body,
    }
}

/// Build an `HttpResponse` from pre-extracted parts (avoids borrow conflicts with httparse).
fn build_response_from_parts(
    status: u16,
    headers: &[httparse::Header<'_>],
    body: Option<Vec<u8>>,
) -> HttpResponse {
    let headers = headers
        .iter()
        .filter(|h| !h.name.is_empty())
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();

    HttpResponse {
        status,
        headers,
        body,
    }
}

/// Process chunked transfer encoding data.
///
/// Returns a `ChunkProcessResult` indicating done, incomplete, or too-large.
fn process_chunks(
    data: &[u8],
    chunk_state: &mut ChunkState,
    body_buf: &mut Vec<u8>,
    max_body_bytes: usize,
) -> ChunkProcessResult {
    let mut pos = 0;

    loop {
        if pos >= data.len() {
            return ChunkProcessResult::Incomplete;
        }

        match chunk_state {
            ChunkState::ReadingSize { size_buf } => {
                // Look for \r\n to end the chunk size line.
                while pos < data.len() {
                    let b = data[pos];
                    pos += 1;

                    if b == b'\n' && size_buf.last() == Some(&b'\r') {
                        size_buf.pop(); // remove \r
                        let size_str = String::from_utf8_lossy(size_buf);
                        // Chunk extensions after ';' are ignored.
                        let hex = size_str.split(';').next().unwrap_or("").trim();
                        let chunk_size = if hex == "0" || hex.is_empty() {
                            // "0" is the legitimate terminal chunk.
                            // Empty means the size line was blank — treat as terminal
                            // rather than erroring, since some HTTP clients emit bare CRLF.
                            0
                        } else {
                            match usize::from_str_radix(hex, 16) {
                                Ok(n) => n,
                                Err(_) => return ChunkProcessResult::ParseError,
                            }
                        };

                        if chunk_size == 0 {
                            // Terminal chunk. Skip trailing \r\n.
                            *chunk_state = ChunkState::Done;
                            // Consume the trailing \r\n after 0-chunk.
                            if pos + 1 < data.len() && data[pos] == b'\r' && data[pos + 1] == b'\n'
                            {
                                pos += 2;
                            }
                            return ChunkProcessResult::Done(pos);
                        }

                        *chunk_state = ChunkState::ReadingData {
                            remaining: chunk_size,
                        };
                        break;
                    } else {
                        size_buf.push(b);
                    }
                }
            }

            ChunkState::ReadingData { remaining } => {
                let available = data.len() - pos;
                let take = available.min(*remaining);
                let chunk_data = &data[pos..pos + take];

                // Check if adding this data would exceed the limit.
                if body_buf.len() + chunk_data.len() > max_body_bytes {
                    return ChunkProcessResult::TooLarge;
                }

                if !chunk_data.is_empty() {
                    body_buf.extend_from_slice(chunk_data);
                }

                pos += take;
                *remaining -= take;

                if *remaining == 0 {
                    *chunk_state = ChunkState::ReadingDataCrlf { remaining_crlf: 2 };
                } else {
                    return ChunkProcessResult::Incomplete;
                }
            }

            ChunkState::ReadingDataCrlf { remaining_crlf } => {
                // Consume the \r\n after chunk data.
                while pos < data.len() && *remaining_crlf > 0 {
                    pos += 1;
                    *remaining_crlf -= 1;
                }
                if *remaining_crlf == 0 {
                    *chunk_state = ChunkState::ReadingSize {
                        size_buf: Vec::new(),
                    };
                } else {
                    return ChunkProcessResult::Incomplete;
                }
            }

            ChunkState::Done => {
                return ChunkProcessResult::Done(pos);
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_no_body() {
        let mut framer = RequestFramer::new(1024);
        let input = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match framer.feed(input) {
            FrameResult::Complete(req, _) => {
                assert_eq!(req.method, "GET");
                assert_eq!(req.uri, "/");
                assert_eq!(req.headers.len(), 1);
                assert_eq!(
                    req.headers[0],
                    ("Host".to_string(), "example.com".to_string())
                );
                assert!(req.body.as_ref().is_none_or(|b| b.is_empty()));
            }
            FrameResult::Incomplete => panic!("expected complete"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn request_with_content_length_body() {
        let mut framer = RequestFramer::new(1024);
        let input = b"POST /api HTTP/1.1\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}";
        match framer.feed(input) {
            FrameResult::Complete(req, _) => {
                assert_eq!(req.method, "POST");
                assert_eq!(req.uri, "/api");
                assert_eq!(req.body.as_deref(), Some(b"{\"key\":\"val\"}".as_slice()));
            }
            FrameResult::Incomplete => panic!("expected complete"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn request_body_rejection() {
        let mut framer = RequestFramer::new(5); // max 5 bytes
        let input = b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n0123456789";
        assert!(matches!(framer.feed(input), FrameResult::BodyTooLarge));
    }

    #[test]
    fn request_zero_max_body_rejects() {
        let mut framer = RequestFramer::new(0);
        let input = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        // Content-Length 5 > max_body_bytes 0, so body is rejected.
        assert!(matches!(framer.feed(input), FrameResult::BodyTooLarge));
    }

    #[test]
    fn request_multi_chunk_arrival() {
        let mut framer = RequestFramer::new(1024);

        // Feed headers only first.
        let part1 = b"POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\n";
        assert!(matches!(framer.feed(part1), FrameResult::Incomplete));

        // Feed body.
        let part2 = b"hello";
        match framer.feed(part2) {
            FrameResult::Complete(req, _) => {
                assert_eq!(req.body.as_deref(), Some(b"hello".as_slice()));
            }
            FrameResult::Incomplete => panic!("expected complete"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn response_with_body() {
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        match framer.feed(input) {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body.as_deref(), Some(b"ok".as_slice()));
            }
            FrameResult::Incomplete => panic!("expected complete"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn chunked_request() {
        let mut framer = RequestFramer::new(1024);
        let input = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        match framer.feed(input) {
            FrameResult::Complete(req, _) => {
                assert_eq!(req.body.as_deref(), Some(b"hello".as_slice()));
            }
            FrameResult::Incomplete => panic!("expected complete"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn chunked_multi_chunk() {
        let mut framer = RequestFramer::new(1024);
        let input =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        match framer.feed(input) {
            FrameResult::Complete(req, _) => {
                assert_eq!(req.body.as_deref(), Some(b"hello world".as_slice()));
            }
            FrameResult::Incomplete => panic!("expected complete"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn chunked_body_rejection() {
        let mut framer = RequestFramer::new(5); // max 5 bytes
        // Two chunks totaling 11 bytes > 5 byte limit.
        let input =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert!(matches!(framer.feed(input), FrameResult::BodyTooLarge));
    }

    #[test]
    fn chunked_malformed_size_rejected() {
        let mut framer = RequestFramer::new(1024);
        // First chunk is valid, second has a non-hex size "ZZ".
        let input =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nZZ\r\nworld\r\n0\r\n\r\n";
        assert!(matches!(framer.feed(input), FrameResult::ParseError));

        // Framer should accept a valid request after reset.
        let valid = b"GET / HTTP/1.1\r\nHost: ok.com\r\n\r\n";
        match framer.feed(valid) {
            FrameResult::Complete(req, _) => assert_eq!(req.method, "GET"),
            other => panic!("expected complete after parse error reset, got {other:?}"),
        }
    }

    #[test]
    fn sequential_requests() {
        let mut framer = RequestFramer::new(1024);
        let input = b"GET /a HTTP/1.1\r\nHost: a.com\r\n\r\nGET /b HTTP/1.1\r\nHost: b.com\r\n\r\n";

        match framer.feed(input) {
            FrameResult::Complete(req, _) => {
                assert_eq!(req.uri, "/a");
            }
            FrameResult::Incomplete => panic!("expected first request"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }

        // Second request should be parseable from remaining buffer.
        match framer.feed(b"") {
            FrameResult::Complete(req, _) => {
                assert_eq!(req.uri, "/b");
            }
            FrameResult::Incomplete => panic!("expected second request"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn response_no_body() {
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 204 No Content\r\n\r\n";
        match framer.feed(input) {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 204);
                assert!(resp.body.as_ref().is_none_or(|b| b.is_empty()));
            }
            FrameResult::Incomplete => panic!("expected complete"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn response_200_no_content_length_buffers_until_eof() {
        // A 200 response without Content-Length or Transfer-Encoding uses
        // read-until-close per RFC 7230 §3.3.3 — buffers until feed_eof().
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        assert!(matches!(framer.feed(input), FrameResult::Incomplete));
    }

    #[test]
    fn response_205_no_content_length_returns_complete() {
        // 205 Reset Content MUST NOT have a body — should be Complete.
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 205 Reset Content\r\n\r\n";
        match framer.feed(input) {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 205);
            }
            other => panic!("expected Complete for 205, got {other:?}"),
        }
    }

    #[test]
    fn response_304_no_content_length_returns_complete() {
        // 304 Not Modified MUST NOT have a body — should be Complete.
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 304 Not Modified\r\n\r\n";
        match framer.feed(input) {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 304);
            }
            other => panic!("expected Complete for 304, got {other:?}"),
        }
    }

    #[test]
    fn response_body_rejection() {
        let mut framer = ResponseFramer::new(3); // max 3 bytes
        let input = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
        assert!(matches!(framer.feed(input), FrameResult::BodyTooLarge));
    }

    #[test]
    fn response_chunked_buffers_body() {
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        match framer.feed(input) {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body.as_deref(), Some(b"hello".as_slice()));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn response_101_returns_upgrade() {
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        match framer.feed(input) {
            FrameResult::Upgrade(resp, _) => {
                assert_eq!(resp.status, 101);
                assert!(resp.body.is_none());
                assert!(resp.headers.iter().any(|(k, _)| k == "Upgrade"));
            }
            other => panic!("expected Upgrade, got {other:?}"),
        }
    }

    #[test]
    fn response_with_content_length_returns_complete() {
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        match framer.feed(input) {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body.as_deref(), Some(b"hello".as_slice()));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn request_chunked_still_buffers() {
        // Request framer should still buffer chunked bodies (not Upgrade).
        let mut framer = RequestFramer::new(1024);
        let input = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        match framer.feed(input) {
            FrameResult::Complete(req, _) => {
                assert_eq!(req.method, "POST");
                assert_eq!(req.body.as_deref(), Some(b"hello".as_slice()));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn response_multi_chunk_arrival() {
        let mut framer = ResponseFramer::new(1024);

        let part1 = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        assert!(matches!(framer.feed(part1), FrameResult::Incomplete));

        let part2 = b"world";
        match framer.feed(part2) {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body.as_deref(), Some(b"world".as_slice()));
            }
            FrameResult::Incomplete => panic!("expected complete"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn malformed_request_resets() {
        let mut framer = RequestFramer::new(1024);
        // Garbage that has \r\n\r\n but isn't valid HTTP.
        let garbage = b"NOT HTTP AT ALL\r\n\r\n";
        assert!(matches!(framer.feed(garbage), FrameResult::Incomplete));

        // Framer should accept a valid request after reset.
        let valid = b"GET / HTTP/1.1\r\nHost: ok.com\r\n\r\n";
        match framer.feed(valid) {
            FrameResult::Complete(req, _) => assert_eq!(req.method, "GET"),
            FrameResult::Incomplete => panic!("expected complete after malformed reset"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn malformed_response_resets() {
        let mut framer = ResponseFramer::new(1024);
        let garbage = b"GARBAGE RESPONSE\r\n\r\n";
        assert!(matches!(framer.feed(garbage), FrameResult::Incomplete));

        // 204 is bodyless per RFC — returns Complete even without Content-Length.
        let valid = b"HTTP/1.1 204 No Content\r\n\r\n";
        match framer.feed(valid) {
            FrameResult::Complete(resp, _) => assert_eq!(resp.status, 204),
            FrameResult::Incomplete => panic!("expected complete after malformed reset"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected streaming"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn empty_feed() {
        let mut framer = RequestFramer::new(1024);
        assert!(matches!(framer.feed(b""), FrameResult::Incomplete));
        // Should still work after empty feed.
        let input = b"GET / HTTP/1.1\r\nHost: x.com\r\n\r\n";
        assert!(matches!(framer.feed(input), FrameResult::Complete(_, _)));
    }

    #[test]
    fn request_framer_reset() {
        let mut framer = RequestFramer::new(1024);

        // Feed partial data.
        framer.feed(b"GET /partial HTTP/1.1\r\n");
        // Reset discards partial state.
        framer.reset();

        // Fresh request should parse cleanly.
        let input = b"POST /new HTTP/1.1\r\nContent-Length: 2\r\n\r\nok";
        match framer.feed(input) {
            FrameResult::Complete(req, _) => {
                assert_eq!(req.method, "POST");
                assert_eq!(req.uri, "/new");
                assert_eq!(req.body.as_deref(), Some(b"ok".as_slice()));
            }
            FrameResult::Incomplete => panic!("expected complete after reset"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected upgrade"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn response_feed_eof_completes_read_until_close() {
        let mut framer = ResponseFramer::new(1024);
        // 200 without Content-Length — read-until-close.
        let headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        assert!(matches!(framer.feed(headers), FrameResult::Incomplete));

        // Feed some body bytes.
        assert!(matches!(framer.feed(b"hello "), FrameResult::Incomplete));
        assert!(matches!(framer.feed(b"world"), FrameResult::Incomplete));

        // Server closes — feed_eof() should emit Complete with buffered body.
        match framer.feed_eof() {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body.as_deref(), Some(b"hello world".as_slice()));
            }
            other => panic!("expected Complete from feed_eof, got {other:?}"),
        }
    }

    #[test]
    fn response_feed_eof_completes_partial_chunked() {
        let mut framer = ResponseFramer::new(1024);
        // Chunked response with one chunk but no terminal chunk.
        let input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(matches!(framer.feed(input), FrameResult::Incomplete));

        // Server closes before terminal chunk.
        match framer.feed_eof() {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body.as_deref(), Some(b"hello".as_slice()));
            }
            other => panic!("expected Complete from feed_eof, got {other:?}"),
        }
    }

    #[test]
    fn response_chunked_body_too_large() {
        let mut framer = ResponseFramer::new(5); // max 5 bytes
        let input =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert!(matches!(framer.feed(input), FrameResult::BodyTooLarge));
    }

    #[test]
    fn response_read_until_close_body_too_large() {
        let mut framer = ResponseFramer::new(5); // max 5 bytes
        let headers = b"HTTP/1.1 200 OK\r\n\r\n";
        assert!(matches!(framer.feed(headers), FrameResult::Incomplete));
        // Feed 10 bytes — exceeds max.
        assert!(matches!(
            framer.feed(b"0123456789"),
            FrameResult::BodyTooLarge
        ));
    }

    #[test]
    fn response_feed_eof_on_awaiting_headers() {
        let mut framer = ResponseFramer::new(1024);
        // No data fed — feed_eof should return Incomplete (nothing to emit).
        assert!(matches!(framer.feed_eof(), FrameResult::Incomplete));
    }

    // ── Multi-feed chunked tests ─────────────────────────────────────────

    #[test]
    fn response_chunked_multi_feed() {
        // Chunked response arriving in multiple TCP segments.
        let mut framer = ResponseFramer::new(1024);

        // Feed 1: headers + partial chunk size
        let part1 = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        assert!(matches!(framer.feed(part1), FrameResult::Incomplete));

        // Feed 2: rest of chunk data + terminal chunk
        let part2 = b"lo\r\n0\r\n\r\n";
        match framer.feed(part2) {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body.as_deref(), Some(b"hello".as_slice()));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn response_chunked_multi_feed_multiple_chunks() {
        // Two chunks, data split across three feeds.
        let mut framer = ResponseFramer::new(1024);

        // Feed 1: headers + first chunk
        let part1 = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(matches!(framer.feed(part1), FrameResult::Incomplete));

        // Feed 2: second chunk partially
        let part2 = b"6\r\n wo";
        assert!(matches!(framer.feed(part2), FrameResult::Incomplete));

        // Feed 3: rest of second chunk + terminal
        let part3 = b"rld\r\n0\r\n\r\n";
        match framer.feed(part3) {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body.as_deref(), Some(b"hello world".as_slice()));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn response_chunked_split_at_chunk_size_boundary() {
        // Split exactly between chunk size line and chunk data.
        let mut framer = ResponseFramer::new(1024);

        let part1 = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n";
        assert!(matches!(framer.feed(part1), FrameResult::Incomplete));

        let part2 = b"hello\r\n0\r\n\r\n";
        match framer.feed(part2) {
            FrameResult::Complete(resp, _) => {
                assert_eq!(resp.body.as_deref(), Some(b"hello".as_slice()));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn request_chunked_multi_feed() {
        // Request-direction chunked also works across feeds.
        let mut framer = RequestFramer::new(1024);

        let part1 = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        assert!(matches!(framer.feed(part1), FrameResult::Incomplete));

        let part2 = b"lo\r\n0\r\n\r\n";
        match framer.feed(part2) {
            FrameResult::Complete(req, _) => {
                assert_eq!(req.method, "POST");
                assert_eq!(req.body.as_deref(), Some(b"hello".as_slice()));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn response_chunked_byte_at_a_time() {
        // Worst case: feed one byte at a time.
        let mut framer = ResponseFramer::new(1024);
        let full = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";

        for (i, &byte) in full.iter().enumerate() {
            match framer.feed(&[byte]) {
                FrameResult::Incomplete => {}
                FrameResult::Complete(resp, _) => {
                    // Completes once the terminal chunk "0\r\n" is seen and
                    // the trailing \r\n is consumed (if available).
                    assert_eq!(resp.body.as_deref(), Some(b"hello".as_slice()));
                    // Verify we're near the end (within last few bytes).
                    assert!(
                        i >= full.len() - 3,
                        "completed too early at byte {i}/{}",
                        full.len()
                    );
                    return;
                }
                other => panic!("unexpected result at byte {i}: {other:?}"),
            }
        }
        panic!("never completed");
    }
}
