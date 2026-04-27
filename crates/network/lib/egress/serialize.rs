//! HTTP/1.1 re-serializer for modified requests and responses.
//!
//! Converts [`HttpRequest`] and [`HttpResponse`] structs back into HTTP/1.1
//! wire bytes for writing to TLS connections.

use super::event::{HttpRequest, HttpResponse};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Serialize an [`HttpRequest`] to HTTP/1.1 wire bytes.
///
/// Automatically sets `Content-Length` based on the body length.
pub fn serialize_request(req: &HttpRequest) -> Vec<u8> {
    let body = req.body.as_deref().unwrap_or(&[]);
    let mut buf = Vec::with_capacity(256 + body.len());

    // Request line.
    buf.extend_from_slice(req.method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(req.uri.as_bytes());
    buf.extend_from_slice(b" HTTP/1.1\r\n");

    // Headers, replacing Content-Length if body is present.
    let mut wrote_content_length = false;
    for (name, value) in &req.headers {
        if name.eq_ignore_ascii_case("content-length") {
            buf.extend_from_slice(b"Content-Length: ");
            buf.extend_from_slice(body.len().to_string().as_bytes());
            buf.extend_from_slice(b"\r\n");
            wrote_content_length = true;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // Drop Transfer-Encoding — we re-serialize with Content-Length.
            continue;
        } else {
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
    }

    // Add Content-Length if not present and body is non-empty.
    if !wrote_content_length && !body.is_empty() {
        buf.extend_from_slice(b"Content-Length: ");
        buf.extend_from_slice(body.len().to_string().as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // Header/body boundary.
    buf.extend_from_slice(b"\r\n");

    // Body.
    buf.extend_from_slice(body);

    buf
}

/// Serialize an [`HttpResponse`] to HTTP/1.1 wire bytes.
///
/// Automatically sets `Content-Length` based on the body length.
pub fn serialize_response(resp: &HttpResponse) -> Vec<u8> {
    let body = resp.body.as_deref().unwrap_or(&[]);
    let mut buf = Vec::with_capacity(256 + body.len());

    // Status line.
    buf.extend_from_slice(b"HTTP/1.1 ");
    buf.extend_from_slice(resp.status.to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(reason_phrase(resp.status).as_bytes());
    buf.extend_from_slice(b"\r\n");

    // Headers, replacing Content-Length.
    let mut wrote_content_length = false;
    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("content-length") {
            buf.extend_from_slice(b"Content-Length: ");
            buf.extend_from_slice(body.len().to_string().as_bytes());
            buf.extend_from_slice(b"\r\n");
            wrote_content_length = true;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // Drop Transfer-Encoding — we re-serialize with Content-Length.
            continue;
        } else {
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
    }

    if !wrote_content_length {
        buf.extend_from_slice(b"Content-Length: ");
        buf.extend_from_slice(body.len().to_string().as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(body);

    buf
}

/// Standard reason phrase for common status codes.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_get_request() {
        let req = HttpRequest {
            method: "GET".into(),
            uri: "/api".into(),
            headers: vec![("Host".into(), "example.com".into())],
            body: None,
        };
        let bytes = serialize_request(&req);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("GET /api HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn serialize_post_request_with_body() {
        let req = HttpRequest {
            method: "POST".into(),
            uri: "/data".into(),
            headers: vec![
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: Some(b"{\"key\":1}".to_vec()),
        };
        let bytes = serialize_request(&req);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Length: 9\r\n"));
        assert!(s.ends_with("{\"key\":1}"));
    }

    #[test]
    fn serialize_response_rewrites_content_length() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![
                ("Content-Type".into(), "text/plain".into()),
                ("Content-Length".into(), "999".into()), // wrong, should be rewritten
            ],
            body: Some(b"hello".to_vec()),
        };
        let bytes = serialize_response(&resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("hello"));
    }

    #[test]
    fn serialize_request_no_headers() {
        let req = HttpRequest {
            method: "GET".into(),
            uri: "/".into(),
            headers: vec![],
            body: None,
        };
        let bytes = serialize_request(&req);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("GET / HTTP/1.1\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn serialize_response_no_body() {
        let resp = HttpResponse {
            status: 204,
            headers: vec![],
            body: None,
        };
        let bytes = serialize_response(&resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Length: 0\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn serialize_response_empty_body() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: Some(vec![]),
        };
        let bytes = serialize_response(&resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Length: 0\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn serialize_request_strips_transfer_encoding() {
        let req = HttpRequest {
            method: "POST".into(),
            uri: "/data".into(),
            headers: vec![
                ("Host".into(), "example.com".into()),
                ("Transfer-Encoding".into(), "chunked".into()),
            ],
            body: Some(b"hello".to_vec()),
        };
        let bytes = serialize_request(&req);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(!s.to_lowercase().contains("transfer-encoding"));
        assert!(s.ends_with("hello"));
    }

    #[test]
    fn serialize_response_strips_transfer_encoding() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![
                ("Content-Type".into(), "text/plain".into()),
                ("Transfer-Encoding".into(), "chunked".into()),
            ],
            body: Some(b"world".to_vec()),
        };
        let bytes = serialize_response(&resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(!s.to_lowercase().contains("transfer-encoding"));
        assert!(s.ends_with("world"));
    }

    #[test]
    fn round_trip_request() {
        use crate::egress::framer::{FrameResult, RequestFramer};

        let original = HttpRequest {
            method: "POST".into(),
            uri: "/data".into(),
            headers: vec![
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: Some(b"{\"a\":1}".to_vec()),
        };

        let wire = serialize_request(&original);
        let mut framer = RequestFramer::new(4096);
        match framer.feed(&wire) {
            FrameResult::Complete(parsed, _) => {
                assert_eq!(parsed.method, original.method);
                assert_eq!(parsed.uri, original.uri);
                assert_eq!(parsed.body, original.body);
                // Headers may include an auto-added Content-Length, so check originals are present.
                for (name, value) in &original.headers {
                    if !name.eq_ignore_ascii_case("content-length") {
                        assert!(
                            parsed.headers.contains(&(name.clone(), value.clone())),
                            "missing header {name}: {value}"
                        );
                    }
                }
            }
            FrameResult::Incomplete => panic!("expected complete from round-trip"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected upgrade"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }

    #[test]
    fn round_trip_response() {
        use crate::egress::framer::{FrameResult, ResponseFramer};

        let original = HttpResponse {
            status: 404,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: Some(b"not found".to_vec()),
        };

        let wire = serialize_response(&original);
        let mut framer = ResponseFramer::new(4096);
        match framer.feed(&wire) {
            FrameResult::Complete(parsed, _) => {
                assert_eq!(parsed.status, original.status);
                assert_eq!(parsed.body, original.body);
                for (name, value) in &original.headers {
                    if !name.eq_ignore_ascii_case("content-length") {
                        assert!(
                            parsed.headers.contains(&(name.clone(), value.clone())),
                            "missing header {name}: {value}"
                        );
                    }
                }
            }
            FrameResult::Incomplete => panic!("expected complete from round-trip"),
            FrameResult::BodyTooLarge => panic!("unexpected body too large"),
            FrameResult::Upgrade(_, _) => panic!("unexpected upgrade"),
            FrameResult::ParseError => panic!("unexpected parse error"),
        }
    }
}
