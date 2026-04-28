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
    /// Buffering a chunked body (used by `RequestFramer`; `ResponseFramer`
    /// returns `StreamBody` for chunked responses instead).
    BufferingChunked {
        headers_end: usize,
        body_buf: Vec<u8>,
        chunk_state: ChunkState,
        /// Number of chunk-encoded bytes already consumed by `process_chunks`.
        /// Prevents re-processing old data when `feed()` is called multiple times.
        chunk_bytes_consumed: usize,
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
    /// Headers are complete but the body is unbounded (chunked or
    /// read-until-close). Contains: headers-only message, header bytes
    /// consumed, and body spillover (bytes after the header boundary
    /// already in the buffer). The caller must forward the spillover
    /// immediately and then stream remaining body bytes without feeding
    /// them to the framer.
    StreamBody(T, usize, Vec<u8>),
    /// Protocol upgrade (101 Switching Protocols). Contains a headers-only
    /// message. Caller should stop framing both directions and switch to
    /// raw byte forwarding.
    Upgrade(T, usize),
    /// Malformed chunked encoding (non-hex chunk size). Connection should be
    /// terminated — the body cannot be reliably parsed.
    ParseError,
}

/// Tracks chunked transfer encoding body to detect when the stream ends.
///
/// After the response framer returns `StreamBody` for a chunked response,
/// the TLS proxy forwards body bytes directly to the guest. This tracker
/// parses the chunked encoding on the fly to detect the terminal chunk
/// (`0\r\n[trailers]\r\n`). When the stream ends, the proxy can exit
/// streaming mode and resume framing subsequent HTTP messages on the same
/// keep-alive connection.
pub struct ChunkedBodyTracker {
    state: TrackerState,
}

/// Internal state for `ChunkedBodyTracker`.
enum TrackerState {
    /// Reading hex digits of chunk-size.
    Size { value: usize },
    /// Non-hex character seen (chunk extension), scanning for CR.
    SizeExt { size: usize },
    /// CR seen after chunk-size line, expecting LF.
    SizeLF { size: usize },
    /// Skipping `remaining` bytes of chunk-data.
    Data { remaining: usize },
    /// All chunk-data consumed, expecting CR.
    DataCR,
    /// CR seen after chunk-data, expecting LF.
    DataLF,
    /// At the start of a trailer line (or the terminating empty line).
    TrailerStart,
    /// Inside a trailer field line, scanning for CR.
    TrailerLine,
    /// CR seen inside a trailer line, expecting LF.
    TrailerLineLF,
    /// CR seen at trailer-line start (empty line = end of trailers).
    FinalLF,
}

impl Default for ChunkedBodyTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedBodyTracker {
    /// Create a new tracker starting at the beginning of the chunked body.
    pub fn new() -> Self {
        Self {
            state: TrackerState::Size { value: 0 },
        }
    }

    /// Feed body bytes and return the byte offset just past the end of the
    /// chunked body if the terminal chunk was found, or `None` if more data
    /// is needed.
    ///
    /// When `Some(offset)` is returned, bytes `data[..offset]` belong to
    /// the chunked body and bytes `data[offset..]` are the start of the
    /// next HTTP message (if any).
    pub fn feed(&mut self, data: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < data.len() {
            match self.state {
                TrackerState::Data { ref mut remaining } => {
                    // Fast-skip chunk data bytes.
                    let skip = (*remaining).min(data.len() - i);
                    *remaining -= skip;
                    i += skip;
                    if *remaining == 0 {
                        self.state = TrackerState::DataCR;
                    }
                }
                _ => {
                    let b = data[i];
                    i += 1;
                    match self.state {
                        TrackerState::Size { ref mut value } => match b {
                            b'0'..=b'9' => *value = value.wrapping_mul(16) + (b - b'0') as usize,
                            b'a'..=b'f' => {
                                *value = value.wrapping_mul(16) + (b - b'a' + 10) as usize
                            }
                            b'A'..=b'F' => {
                                *value = value.wrapping_mul(16) + (b - b'A' + 10) as usize
                            }
                            b'\r' => {
                                let size = *value;
                                self.state = TrackerState::SizeLF { size };
                            }
                            _ => {
                                // Chunk extension character.
                                let size = *value;
                                self.state = TrackerState::SizeExt { size };
                            }
                        },
                        TrackerState::SizeExt { size } => {
                            if b == b'\r' {
                                self.state = TrackerState::SizeLF { size };
                            }
                        }
                        TrackerState::SizeLF { size } => {
                            if b == b'\n' {
                                if size == 0 {
                                    self.state = TrackerState::TrailerStart;
                                } else {
                                    self.state = TrackerState::Data { remaining: size };
                                }
                            } else {
                                // Malformed — be lenient, treat as extension.
                                self.state = TrackerState::SizeExt { size };
                            }
                        }
                        TrackerState::Data { .. } => unreachable!(),
                        TrackerState::DataCR => {
                            if b == b'\r' {
                                self.state = TrackerState::DataLF;
                            }
                            // else: malformed, but tolerate
                        }
                        TrackerState::DataLF => {
                            if b == b'\n' {
                                self.state = TrackerState::Size { value: 0 };
                            }
                            // else: malformed, but tolerate
                        }
                        TrackerState::TrailerStart => {
                            if b == b'\r' {
                                self.state = TrackerState::FinalLF;
                            } else {
                                self.state = TrackerState::TrailerLine;
                            }
                        }
                        TrackerState::TrailerLine => {
                            if b == b'\r' {
                                self.state = TrackerState::TrailerLineLF;
                            }
                        }
                        TrackerState::TrailerLineLF => {
                            if b == b'\n' {
                                self.state = TrackerState::TrailerStart;
                            } else {
                                self.state = TrackerState::TrailerLine;
                            }
                        }
                        TrackerState::FinalLF => {
                            if b == b'\n' {
                                return Some(i);
                            }
                            // Not actually the final empty line — treat as trailer.
                            self.state = TrackerState::TrailerLine;
                        }
                    }
                }
            }
        }
        None
    }
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
                            // stream body through without buffering.
                            let response = build_response_from_parts(
                                status,
                                &headers_arr[..header_count],
                                None,
                            );
                            let consumed = boundary;
                            let spillover = self.buf[consumed..].to_vec();
                            self.buf.clear();
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::StreamBody(response, consumed, spillover);
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
                            // Chunked bodies are unbounded — emit headers-only
                            // and let caller stream body through.
                            let response = build_response_from_parts(
                                status,
                                &headers_arr[..header_count],
                                None,
                            );
                            let consumed = boundary;
                            let spillover = self.buf[consumed..].to_vec();
                            self.buf.clear();
                            self.state = FramerState::AwaitingHeaders;
                            return FrameResult::StreamBody(response, consumed, spillover);
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

                // ResponseFramer never enters BufferingChunked — chunked
                // responses return StreamBody from AwaitingHeaders.
                FramerState::BufferingChunked { .. } => {
                    unreachable!("ResponseFramer should never enter BufferingChunked");
                }
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
        }
    }

    #[test]
    fn response_200_no_content_length_returns_stream_body() {
        // A 200 response without Content-Length or Transfer-Encoding uses
        // read-until-close — returns StreamBody so the caller streams body through.
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        match framer.feed(input) {
            FrameResult::StreamBody(resp, _, spillover) => {
                assert_eq!(resp.status, 200);
                assert!(resp.body.is_none());
                assert!(spillover.is_empty());
            }
            other => panic!("expected StreamBody, got {other:?}"),
        }
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
    fn response_chunked_returns_stream_body() {
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        match framer.feed(input) {
            FrameResult::StreamBody(resp, _, spillover) => {
                assert_eq!(resp.status, 200);
                assert!(resp.body.is_none());
                // Spillover contains the chunk data that arrived with headers.
                assert_eq!(spillover, b"5\r\nhello\r\n0\r\n\r\n");
            }
            other => panic!("expected StreamBody, got {other:?}"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
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
            FrameResult::StreamBody(..) => panic!("unexpected stream body"),
        }
    }

    #[test]
    fn response_read_until_close_returns_stream_body_with_spillover() {
        let mut framer = ResponseFramer::new(1024);
        // 200 without Content-Length — read-until-close → StreamBody.
        let input = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world";
        match framer.feed(input) {
            FrameResult::StreamBody(resp, _, spillover) => {
                assert_eq!(resp.status, 200);
                assert!(resp.body.is_none());
                assert_eq!(spillover, b"hello world");
            }
            other => panic!("expected StreamBody, got {other:?}"),
        }
    }

    #[test]
    fn response_chunked_partial_returns_stream_body() {
        // Chunked response — returns StreamBody immediately with spillover.
        let mut framer = ResponseFramer::new(1024);
        let input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        match framer.feed(input) {
            FrameResult::StreamBody(resp, _, spillover) => {
                assert_eq!(resp.status, 200);
                assert!(resp.body.is_none());
                assert_eq!(spillover, b"5\r\nhello\r\n");
            }
            other => panic!("expected StreamBody, got {other:?}"),
        }
    }

    #[test]
    fn response_chunked_returns_stream_body_regardless_of_size() {
        // Chunked responses always return StreamBody (no size check).
        let mut framer = ResponseFramer::new(5); // max 5 bytes
        let input =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        match framer.feed(input) {
            FrameResult::StreamBody(resp, _, spillover) => {
                assert_eq!(resp.status, 200);

                assert!(!spillover.is_empty());
            }
            other => panic!("expected StreamBody, got {other:?}"),
        }
    }

    #[test]
    fn response_read_until_close_returns_stream_body() {
        let mut framer = ResponseFramer::new(5); // max 5 bytes
        let input = b"HTTP/1.1 200 OK\r\n\r\n0123456789";
        match framer.feed(input) {
            FrameResult::StreamBody(resp, _, spillover) => {
                assert_eq!(resp.status, 200);
                assert_eq!(spillover, b"0123456789");
            }
            other => panic!("expected StreamBody, got {other:?}"),
        }
    }

    // ── Multi-feed chunked tests ─────────────────────────────────────────

    #[test]
    fn response_chunked_multi_feed_returns_stream_body() {
        // Chunked response with headers + partial body in first feed.
        let mut framer = ResponseFramer::new(1024);

        let part1 = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        match framer.feed(part1) {
            FrameResult::StreamBody(resp, _, spillover) => {
                assert_eq!(resp.status, 200);
                assert!(resp.body.is_none());
                assert_eq!(spillover, b"5\r\nhel");
            }
            other => panic!("expected StreamBody, got {other:?}"),
        }
    }

    #[test]
    fn response_chunked_headers_only_returns_stream_body() {
        // Headers arrive alone — empty spillover.
        let mut framer = ResponseFramer::new(1024);

        let headers = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        match framer.feed(headers) {
            FrameResult::StreamBody(resp, _, spillover) => {
                assert_eq!(resp.status, 200);
                assert!(spillover.is_empty());
            }
            other => panic!("expected StreamBody, got {other:?}"),
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
        // StreamBody is returned once the header boundary (\r\n\r\n) is found.
        let mut framer = ResponseFramer::new(1024);
        let full = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";

        let header_end = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".len();

        for (i, &byte) in full.iter().enumerate() {
            match framer.feed(&[byte]) {
                FrameResult::Incomplete => {}
                FrameResult::StreamBody(resp, _, spillover) => {
                    assert_eq!(resp.status, 200);
                    assert!(resp.body.is_none());

                    // StreamBody fires right at the header boundary.
                    // The last byte of \r\n\r\n is at index header_end - 1.
                    assert_eq!(i, header_end - 1);
                    // Spillover is empty — no body bytes in the same feed.
                    assert!(spillover.is_empty());
                    return;
                }
                other => panic!("unexpected result at byte {i}: {other:?}"),
            }
        }
        panic!("never got StreamBody");
    }

    // ── ChunkedBodyTracker tests ─────────────────────────────────────────

    #[test]
    fn tracker_simple_single_chunk() {
        let mut tracker = ChunkedBodyTracker::new();
        let input = b"5\r\nhello\r\n0\r\n\r\n";
        let end = tracker.feed(input).expect("should detect end");
        assert_eq!(end, input.len());
    }

    #[test]
    fn tracker_multi_chunk() {
        let mut tracker = ChunkedBodyTracker::new();
        let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let end = tracker.feed(input).expect("should detect end");
        assert_eq!(end, input.len());
    }

    #[test]
    fn tracker_split_across_feeds() {
        let mut tracker = ChunkedBodyTracker::new();
        assert!(tracker.feed(b"5\r\nhel").is_none());
        assert!(tracker.feed(b"lo\r\n0").is_none());
        let end = tracker.feed(b"\r\n\r\n").expect("should detect end");
        assert_eq!(end, 4); // all 4 bytes consumed: \r\n\r\n
    }

    #[test]
    fn tracker_terminal_chunk_split_cr_lf() {
        // Split right between \r and \n of the final empty line.
        let mut tracker = ChunkedBodyTracker::new();
        assert!(tracker.feed(b"0\r\n\r").is_none());
        let end = tracker.feed(b"\n").expect("should detect end");
        assert_eq!(end, 1);
    }

    #[test]
    fn tracker_with_trailers() {
        let mut tracker = ChunkedBodyTracker::new();
        let input = b"5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n";
        let end = tracker.feed(input).expect("should detect end");
        assert_eq!(end, input.len());
    }

    #[test]
    fn tracker_with_multiple_trailers() {
        let mut tracker = ChunkedBodyTracker::new();
        let input = b"3\r\nabc\r\n0\r\nTrailer-A: 1\r\nTrailer-B: 2\r\n\r\n";
        let end = tracker.feed(input).expect("should detect end");
        assert_eq!(end, input.len());
    }

    #[test]
    fn tracker_spillover_after_terminal() {
        // Bytes after the chunked body belong to the next HTTP message.
        let mut tracker = ChunkedBodyTracker::new();
        let input = b"0\r\n\r\nHTTP/1.1 200 OK\r\n";
        let end = tracker.feed(input).expect("should detect end");
        assert_eq!(end, 5); // "0\r\n\r\n" = 5 bytes
        assert_eq!(&input[end..], b"HTTP/1.1 200 OK\r\n");
    }

    #[test]
    fn tracker_chunk_extension() {
        // Chunk extensions after ';' should be tolerated.
        let mut tracker = ChunkedBodyTracker::new();
        let input = b"5;ext=val\r\nhello\r\n0\r\n\r\n";
        let end = tracker.feed(input).expect("should detect end");
        assert_eq!(end, input.len());
    }

    #[test]
    fn tracker_large_chunk_skips_efficiently() {
        let mut tracker = ChunkedBodyTracker::new();
        // 1MB chunk — the tracker should skip data without byte-by-byte iteration.
        let size_line = b"100000\r\n";
        assert!(tracker.feed(size_line).is_none());

        // Feed 1MB of data in 64KB blocks.
        let block = vec![b'x'; 65536];
        for _ in 0..16 {
            assert!(tracker.feed(&block).is_none());
        }

        // CRLF after data + terminal chunk.
        let tail = b"\r\n0\r\n\r\n";
        let end = tracker.feed(tail).expect("should detect end");
        assert_eq!(end, tail.len());
    }

    #[test]
    fn tracker_empty_feeds_are_no_ops() {
        let mut tracker = ChunkedBodyTracker::new();
        assert!(tracker.feed(b"").is_none());
        assert!(tracker.feed(b"").is_none());
        // Should still work after empty feeds.
        let input = b"0\r\n\r\n";
        let end = tracker.feed(input).expect("should detect end");
        assert_eq!(end, input.len());
    }

    #[test]
    fn tracker_byte_at_a_time() {
        let mut tracker = ChunkedBodyTracker::new();
        let input = b"3\r\nabc\r\n0\r\n\r\n";
        for (i, &byte) in input.iter().enumerate() {
            match tracker.feed(&[byte]) {
                Some(end) => {
                    assert_eq!(end, 1); // consumed this single byte
                    assert_eq!(i, input.len() - 1); // should be the last byte
                    return;
                }
                None => {}
            }
        }
        panic!("tracker never detected end");
    }
}
