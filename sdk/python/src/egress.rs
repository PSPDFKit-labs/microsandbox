//! Python bindings for egress HTTP interception.
//!
//! Wraps the Rust SDK's `EgressConnection` for use from Python.

use pyo3::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Low-level egress interception connection.
///
/// Provides `recv()` to read egress events and decision methods to respond.
#[pyclass(name = "EgressConnection")]
pub(crate) struct PyEgressConnection {
    pub(crate) inner:
        std::sync::Arc<tokio::sync::Mutex<microsandbox::sandbox::egress::EgressConnection>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyEgressConnection {
    /// Receive the next egress event. Returns `None` when the stream ends.
    fn recv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            match guard.recv().await {
                Ok(Some(event)) => Python::with_gil(|py| Ok(Some(egress_event_to_py(py, &event)?))),
                Ok(None) => Ok(None),
                Err(e) => Err(pyo3::exceptions::PyIOError::new_err(e.to_string())),
            }
        })
    }

    /// Send a pass-through decision.
    fn pass_through<'py>(&self, py: Python<'py>, event_id: u64) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            guard
                .send_decision(microsandbox_network::egress::event::EgressDecision {
                    id: event_id,
                    action: microsandbox_network::egress::event::EgressAction::PassThrough,
                })
                .await
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
            Ok(())
        })
    }

    /// Send a block decision.
    fn block<'py>(&self, py: Python<'py>, event_id: u64) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            guard
                .send_decision(microsandbox_network::egress::event::EgressDecision {
                    id: event_id,
                    action: microsandbox_network::egress::event::EgressAction::Block,
                })
                .await
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
            Ok(())
        })
    }

    /// Send a modified request decision.
    #[pyo3(signature = (event_id, method, uri, headers, body=None))]
    fn modify_request<'py>(
        &self,
        py: Python<'py>,
        event_id: u64,
        method: String,
        uri: String,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            guard
                .send_decision(microsandbox_network::egress::event::EgressDecision {
                    id: event_id,
                    action: microsandbox_network::egress::event::EgressAction::ModifyRequest(
                        microsandbox_network::egress::event::HttpRequest {
                            method,
                            uri,
                            headers,
                            body,
                        },
                    ),
                })
                .await
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
            Ok(())
        })
    }

    /// Send a short-circuit decision (return response to guest, skip server).
    #[pyo3(signature = (event_id, status, headers, body=None))]
    fn short_circuit<'py>(
        &self,
        py: Python<'py>,
        event_id: u64,
        status: u16,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            guard
                .send_decision(microsandbox_network::egress::event::EgressDecision {
                    id: event_id,
                    action: microsandbox_network::egress::event::EgressAction::ShortCircuit(
                        microsandbox_network::egress::event::HttpResponse {
                            status,
                            headers,
                            body,
                        },
                    ),
                })
                .await
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
            Ok(())
        })
    }

    /// Send a modified response decision.
    #[pyo3(signature = (event_id, status, headers, body=None))]
    fn modify_response<'py>(
        &self,
        py: Python<'py>,
        event_id: u64,
        status: u16,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            guard
                .send_decision(microsandbox_network::egress::event::EgressDecision {
                    id: event_id,
                    action: microsandbox_network::egress::event::EgressAction::ModifyResponse(
                        microsandbox_network::egress::event::HttpResponse {
                            status,
                            headers,
                            body,
                        },
                    ),
                })
                .await
                .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a Rust EgressEvent to a Python dict.
fn egress_event_to_py(
    py: Python<'_>,
    event: &microsandbox_network::egress::event::EgressEvent,
) -> PyResult<PyObject> {
    use pyo3::types::PyDict;

    let dict = PyDict::new(py);
    dict.set_item("id", event.id)?;
    dict.set_item("connection_id", event.connection_id)?;
    dict.set_item("sni", &event.sni)?;
    dict.set_item("dst", event.dst.to_string())?;
    dict.set_item("timestamp_ms", event.timestamp_ms)?;

    match &event.kind {
        microsandbox_network::egress::event::EgressEventKind::Request(req) => {
            dict.set_item("kind", "request")?;
            let req_dict = PyDict::new(py);
            req_dict.set_item("method", &req.method)?;
            req_dict.set_item("uri", &req.uri)?;
            let headers: Vec<(&str, &str)> = req
                .headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            req_dict.set_item("headers", headers)?;
            req_dict.set_item("body", req.body.as_deref())?;
            dict.set_item("request", req_dict)?;
        }
        microsandbox_network::egress::event::EgressEventKind::Response(resp) => {
            dict.set_item("kind", "response")?;
            let resp_dict = PyDict::new(py);
            resp_dict.set_item("status", resp.status)?;
            let headers: Vec<(&str, &str)> = resp
                .headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            resp_dict.set_item("headers", headers)?;
            resp_dict.set_item("body", resp.body.as_deref())?;
            dict.set_item("response", resp_dict)?;
        }
    }

    Ok(dict.into())
}
