"""High-level egress interception API with Gondolin/mitmproxy-style hooks.

Wraps the low-level ``EgressConnection`` (from native Rust binding) with
``on_request``/``on_response`` callback hooks.

Example::

    from microsandbox import Sandbox, Network
    from microsandbox.egress_intercept import egress_intercept
    from microsandbox.events import EgressHttpRequest, EgressHttpResponse

    sb = await Sandbox.create(
        name="agent", image="python",
        network=Network(egress_intercept_hosts=["*"]),
    )

    async def on_request(request, ctx):
        print(f"→ {request.method} {request.uri} [{ctx.sni}]")
        if "/admin" in request.uri:
            raise Exception("blocked")
        request.headers.append(("X-Trace-Id", "abc123"))
        return request

    async def on_response(response, request, ctx):
        print(f"← {response.status} [{ctx.sni}]")
        return None  # pass through

    handle = await egress_intercept(sb, on_request=on_request, on_response=on_response)
    # ... do other work while interception is active ...
    await handle.stop()   # graceful shutdown
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import Any

from microsandbox.events import (
    EgressContext,
    EgressHttpRequest,
    EgressHttpResponse,
)


class EgressInterceptHandle:
    """Handle for a running egress interception loop.

    Returned by :func:`egress_intercept`. The event loop runs in a
    background asyncio task.
    """

    def __init__(self, task: asyncio.Task[None]) -> None:
        self._task = task

    @property
    def done(self) -> asyncio.Task[None]:
        """Awaitable that resolves when the loop ends naturally (sandbox stopped)."""
        return self._task

    async def stop(self) -> None:
        """Cancel the intercept loop and wait for it to finish."""
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task


def _dict_to_request(d: dict[str, Any]) -> EgressHttpRequest:
    """Convert a raw event dict's request sub-dict to an EgressHttpRequest."""
    return EgressHttpRequest(
        method=d["method"],
        uri=d["uri"],
        headers=[(k, v) for k, v in d["headers"]],
        body=d.get("body"),
    )


def _dict_to_response(d: dict[str, Any]) -> EgressHttpResponse:
    """Convert a raw event dict's response sub-dict to an EgressHttpResponse."""
    return EgressHttpResponse(
        status=d["status"],
        headers=[(k, v) for k, v in d["headers"]],
        body=d.get("body"),
    )


def _is_response(value: Any) -> bool:
    """Check if a return value is a response (has ``status``) vs a request (has ``method``)."""
    return isinstance(value, EgressHttpResponse) or (
        isinstance(value, dict) and "status" in value
    )


async def egress_intercept(
    sandbox: Any,
    *,
    on_request: Callable[
        [EgressHttpRequest, EgressContext],
        Awaitable[EgressHttpRequest | EgressHttpResponse | None]
        | EgressHttpRequest
        | EgressHttpResponse
        | None,
    ] | None = None,
    on_response: Callable[
        [EgressHttpResponse, EgressHttpRequest | None, EgressContext],
        Awaitable[EgressHttpResponse | None] | EgressHttpResponse | None,
    ] | None = None,
) -> EgressInterceptHandle:
    """Start egress interception with callback hooks.

    Connects to the sandbox's egress socket and starts processing events
    in a background asyncio task. Returns an :class:`EgressInterceptHandle`
    immediately.

    Args:
        sandbox: A running ``Sandbox`` instance with ``egress_intercept_hosts`` configured.
        on_request: Called for each outbound HTTP request. Return values:

            - ``None`` → pass through unchanged
            - ``EgressHttpRequest`` → forward modified request to server
            - ``EgressHttpResponse`` → short-circuit (return response to guest)
            - raise any exception → block the connection

        on_response: Called for each server response. Return values:

            - ``None`` → pass through unchanged
            - ``EgressHttpResponse`` → forward modified response to guest
            - raise any exception → block the connection

    Returns:
        A handle to control the interception loop.
    """
    conn = await sandbox.egress_connection()

    async def _loop() -> None:
        last_requests: dict[int, EgressHttpRequest] = {}

        while True:
            event = await conn.recv()
            if event is None:
                break

            ctx = EgressContext(
                sni=event["sni"],
                dst=event["dst"],
                connection_id=event["connection_id"],
                timestamp_ms=event["timestamp_ms"],
            )
            event_id: int = event["id"]
            connection_id: int = event["connection_id"]

            try:
                if event["kind"] == "request" and "request" in event:
                    request = _dict_to_request(event["request"])
                    last_requests[connection_id] = request

                    if on_request is not None:
                        result = on_request(request, ctx)
                        if asyncio.iscoroutine(result):
                            result = await result

                        if result is None:
                            await conn.pass_through(event_id)
                        elif _is_response(result):
                            await conn.short_circuit(
                                event_id, result.status,
                                result.headers, result.body,
                            )
                        else:
                            last_requests[connection_id] = result
                            await conn.modify_request(
                                event_id, result.method, result.uri,
                                result.headers, result.body,
                            )
                    else:
                        await conn.pass_through(event_id)

                elif event["kind"] == "response" and "response" in event:
                    response = _dict_to_response(event["response"])
                    original_request = last_requests.pop(connection_id, None)

                    if on_response is not None:
                        result = on_response(response, original_request, ctx)
                        if asyncio.iscoroutine(result):
                            result = await result

                        if result is None:
                            await conn.pass_through(event_id)
                        else:
                            await conn.modify_response(
                                event_id, result.status,
                                result.headers, result.body,
                            )
                    else:
                        await conn.pass_through(event_id)
                else:
                    await conn.pass_through(event_id)

            except Exception:
                await conn.block(event_id)

    task = asyncio.create_task(_loop())
    return EgressInterceptHandle(task)
